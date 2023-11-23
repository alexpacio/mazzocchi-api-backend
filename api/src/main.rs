mod config;
mod handler;
mod jwt_auth;
mod model;
mod response;
mod route;

use std::sync::Arc;

use config::Config;

use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use dotenv::dotenv;
use route::create_router;
use tower_http::cors::CorsLayer;

use tiberius::{Client, Config as TiberiusConfig, AuthMethod};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_util::compat::{TokioAsyncWriteCompatExt, Compat};

use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

pub struct AppState {
    db: Pool<Postgres>,
    env: Config,
    sql_server_db: Arc<Mutex<Client<Compat<TcpStream>>>>,
}

#[tokio::main]
async fn main() {
    let _ = dotenv().ok();

    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    // SQL SERVER CONNECTION

    let mut sql_server_config = TiberiusConfig::new();

    sql_server_config.host(&config.sqlserver_hostname);
    sql_server_config.port(1433);
    sql_server_config.authentication(AuthMethod::sql_server(&config.sqlserver_username, &config.sqlserver_password));
    sql_server_config.trust_cert();

    let sql_server_tcp = TcpStream::connect(sql_server_config.get_addr()).await.unwrap();
    let _ = sql_server_tcp.set_nodelay(true);

    let sql_server_client = Client::connect(sql_server_config, sql_server_tcp.compat_write()).await.unwrap();

    let sql_server_client_state = Arc::new(Mutex::new(sql_server_client));
    //

    let cors = CorsLayer::new()
        .allow_origin(config.cors_origin_value.parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);

    let app = create_router(Arc::new(AppState {
        db: pool.clone(),
        env: config.clone(),
        sql_server_db: sql_server_client_state.clone()
    }))
    .layer(cors);

    println!("🚀 Server started successfully");
    axum::Server::bind(&"0.0.0.0:8800".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
