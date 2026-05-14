pub mod data;
pub mod domain;
pub mod email;
pub mod middleware;
pub mod routes;
pub mod services;

use std::sync::Arc;

use axum::{
    Router, middleware as mw,
    routing::{get, patch, post},
};

use domain::{JwtManager, PasswordService};
use email::EmailClient;

#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub jwt: Arc<JwtManager>,
    pub passwords: Arc<PasswordService>,
    pub redis: redis::Client,
    pub email: Arc<EmailClient>,
    pub app_base_url: String,
    pub oauth: Arc<OAuthConfig>,
    pub http: reqwest::Client,
}

fn oauth_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/{provider}", get(routes::oauth::authorize))
        .route("/auth/{provider}/callback", get(routes::oauth::callback))
}

/// Router without rate limiting — for integration tests.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/register", post(routes::register))
        .route("/login", post(routes::login))
        .route("/refresh", post(routes::refresh))
        .route("/logout", post(routes::logout))
        .route("/me", get(routes::me).delete(routes::delete_me))
        .route("/me/password", patch(routes::change_password))
        .route("/me/sessions/revoke-all", post(routes::logout_all))
        .route(
            "/password-reset/request",
            post(routes::password_reset_request),
        )
        .route(
            "/password-reset/confirm",
            post(routes::password_reset_confirm),
        )
        .merge(oauth_routes())
        .with_state(state)
}

/// Production router with per-IP rate limiting on /register, /login, and /password-reset/request.
pub fn build_production_router(state: AppState) -> Router {
    let rate_limited = Router::new()
        .route("/login", post(routes::login))
        .route("/register", post(routes::register))
        .route(
            "/password-reset/request",
            post(routes::password_reset_request),
        )
        .route_layer(mw::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ));

    Router::new()
        .route("/health", get(routes::health))
        .merge(rate_limited)
        .route("/refresh", post(routes::refresh))
        .route("/logout", post(routes::logout))
        .route("/me", get(routes::me).delete(routes::delete_me))
        .route("/me/password", patch(routes::change_password))
        .route("/me/sessions/revoke-all", post(routes::logout_all))
        .route(
            "/password-reset/confirm",
            post(routes::password_reset_confirm),
        )
        .merge(oauth_routes())
        .with_state(state)
}
