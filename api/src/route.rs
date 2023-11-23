use std::sync::Arc;

use axum::{
    http::StatusCode,
    middleware,
    routing::{get, get_service, post},
    Router,
};

use crate::{
    handler::{
        get_me_handler, get_orders_handler, health_checker_handler, login_user_handler,
        logout_handler, register_user_handler,
    },
    jwt_auth::{auth, reject_if_not_admin},
    AppState,
};

use tower_http::services::{ServeDir, ServeFile};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/healthchecker", get(health_checker_handler))
        .route(
            "/api/auth/register",
            post(register_user_handler)
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    reject_if_not_admin,
                ))
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth))
        )
        .route("/api/auth/login", post(login_user_handler))
        .route(
            "/api/auth/logout",
            get(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/users/me",
            get(get_me_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/orders",
            get(get_orders_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .with_state(app_state)
        .fallback(
            get_service(
                ServeDir::new("./html").not_found_service(
                    ServeFile::new("./html/index.html"),
                ),
            )
            .handle_error(|_| async move {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }),
        )
}
