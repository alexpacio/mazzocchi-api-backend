use std::{ops::DerefMut, sync::Arc};

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::State,
    http::{header, Request, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tiberius::{error::Error, Query};

use crate::{
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
    response::FilteredUser,
    AppState,
};

pub async fn health_checker_handler() -> impl IntoResponse {
    let json_response = serde_json::json!({
        "status": "success",
        "message": "The application is healthy"
    });

    Json(json_response)
}

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(body.email.to_owned().to_ascii_lowercase())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "User with that email already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password,role,customer_name) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        body.name.to_string(),
        body.email.to_string().to_ascii_lowercase(),
        hashed_password,
        body.role.to_string(),
        body.customer_name.to_string()
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "user": filter_user_record(&user)
    })});

    Ok(Json(user_response))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1",
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password",
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    };

    if !is_valid {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password"
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let now = chrono::Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.env.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie = Cookie::build("token", token.to_owned())
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(json!({"status": "success", "token": token}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn logout_handler() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn get_me_handler(
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    Ok(Json(json_response))
}

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id,
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        customer_name: user.customer_name.to_owned(),
        photo: user.photo.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Params {
    page: Option<u32>,
    size: Option<u32>,
    sorting_dir: Option<String>,
    sorting_field: Option<String>
}

#[derive(Serialize, Clone, Debug)]
struct SqlClienteRow<'a> {
    codice: Option<&'a str>,
    materiale: Option<&'a str>,
    spessore: Option<f64>,
    #[serde(rename = "dimX")]
    dim_x: Option<f64>,
    #[serde(rename = "dimY")]
    dim_y: Option<f64>,
    area: Option<f64>,
    peso: Option<f64>,
    ritaglio: Option<u8>,
    qta: Option<i32>,
    udata1: Option<&'a str>,
    udata2: Option<&'a str>,
    udata3: Option<&'a str>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PaginatedResponse {
    results: Vec<Value>,
    current_page: i32,
    total_pages: i32,
    total_count: i32,
}

pub fn cast_database_err(err: Error) -> (StatusCode, Json<serde_json::Value>) {
    let error_response = serde_json::json!({
        "status": "error",
        "message": format!("Database error: {}", err),
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
}

pub async fn get_orders_handler<B>(
    State(data): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<Params>,
    req: Request<B>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut sql_server_client_mutex = data.sql_server_db.lock().await;
    let sql_server_client = sql_server_client_mutex.deref_mut();

    let customer_name = req
        .extensions()
        .get::<User>()
        .unwrap()
        .customer_name
        .as_ref();

    let mut count_query_string =
        "select COUNT(*) from SRLMAZZ_LANTEK.dbo.VGiacenzaLamiere".to_owned();

    if customer_name.is_some() {
        count_query_string.push_str(" WHERE Udata1 = @P1");
    }

    let mut count_query = Query::new(count_query_string);

    if customer_name.is_some() {
        count_query.bind(customer_name);
    }

    let total_count = count_query
        .query(sql_server_client)
        .await
        .map_err(cast_database_err)?
        .into_first_result()
        .await
        .map_err(cast_database_err)?
        .first()
        .map(|f| f.get::<i32, usize>(0))
        .unwrap_or(Some(0));

    let mut page_size = params.size.unwrap_or(20 as u32);
    if page_size == 0 || page_size > 20 {
        page_size = 20;
    }

    let total_pages = (total_count.unwrap() as f32 / page_size as f32).ceil() as u32;

    let page_num_unchecked = params.page.unwrap_or(1) as u32;
    let mut page_num: u32 = page_num_unchecked;
    if page_num_unchecked == 0 {
        page_num = 1;
    } else if total_pages < page_num_unchecked {
        page_num = total_pages;
    };
    let offset: i32 = ((page_num - 1) * (page_size as u32)) as i32;

    let sorting_field = params.sorting_field.unwrap_or(String::from("Codice"));
    let sorting_dir = params.sorting_dir.unwrap_or(String::from("DESC")).to_uppercase();

    let query_filter_string = format!("ORDER BY {sorting_field} {sorting_dir} OFFSET @P1 ROWS FETCH NEXT @P2 ROWS ONLY");

    let mut query_string_vec: Vec<String> = vec![
        "select * from SRLMAZZ_LANTEK.dbo.VGiacenzaLamiere".to_string(),
        query_filter_string,
    ];

    let mut udata1: Option<String> = None;

    if customer_name.is_some() {
        udata1 = Some(customer_name.unwrap().clone());
        query_string_vec[1] = format!("ORDER BY {sorting_field} {sorting_dir} OFFSET @P2 ROWS FETCH NEXT @P3 ROWS ONLY");
        query_string_vec.insert(1, String::from("WHERE Udata1 = @P1"));
    }
    
    let query_string = query_string_vec.join(" ");

    let mut query = Query::new(query_string);
    if udata1.is_some() {
        query.bind(udata1.as_ref().unwrap().as_str());
    }
    query.bind(offset);
    query.bind(page_size as i32);

    let rows = query
        .query(sql_server_client)
        .await
        .map_err(cast_database_err)?
        .into_results()
        .await
        .map_err(cast_database_err)?;

    let mut result_in_json: Vec<Value> = vec![];
    for row in &rows[0] {
        let casted_row = SqlClienteRow {
            codice: row.get::<&str, usize>(0),
            materiale: row.get::<&str, usize>(1),
            spessore: row.get::<f64, usize>(2),
            dim_x: row.get::<f64, usize>(3),
            dim_y: row.get::<f64, usize>(4),
            area: row.get::<f64, usize>(5),
            peso: row.get::<f64, usize>(6),
            ritaglio: row.get::<u8, usize>(7),
            qta: row.get::<i32, usize>(8),
            udata1: row.get::<&str, usize>(9),
            udata2: row.get::<&str, usize>(10),
            udata3: row.get::<&str, usize>(11),
        };
        result_in_json.push(serde_json::json!(casted_row));
    }

    Ok(Json(PaginatedResponse {
        results: result_in_json,
        current_page: page_num as i32,
        total_pages: total_pages as i32,
        total_count: total_count.unwrap(),
    }))
}
