pub mod data;
pub mod domain;
pub mod email;
pub mod middleware;
pub mod routes;
pub mod services;

use std::sync::{Arc, LazyLock};

use axum::{
    Router, middleware as mw,
    routing::{get, patch, post},
};
use axum_prometheus::{PrometheusMetricLayer, metrics_exporter_prometheus::PrometheusHandle};

use domain::{JwtManager, PasswordService};
use email::EmailClient;

#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,

    /// Overrides for provider endpoint URLs, used by tests to redirect calls
    /// to a local mock server instead of the real provider.
    pub github_auth_url: Option<String>,
    pub github_token_url: Option<String>,
    pub github_api_base_url: Option<String>,
    pub google_auth_url: Option<String>,
    pub google_token_url: Option<String>,
    pub google_userinfo_url: Option<String>,
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

/// `PrometheusMetricLayer::pair()` installs a global `metrics` recorder, which
/// can only happen once per process — so the pair is built lazily and shared
/// across every router we construct (each integration test spawns its own).
static PROMETHEUS: LazyLock<(PrometheusMetricLayer<'static>, PrometheusHandle)> =
    LazyLock::new(PrometheusMetricLayer::pair);

fn oauth_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/{provider}", get(routes::oauth::authorize))
        .route("/auth/{provider}/callback", get(routes::oauth::callback))
}

/// Router without rate limiting — for integration tests.
pub fn build_router(state: AppState) -> Router {
    let (prometheus_layer, metric_handle) = PROMETHEUS.clone();
    Router::new()
        .route("/health", get(routes::health))
        .route(
            "/metrics",
            get(move || async move { metric_handle.render() }),
        )
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
        .route("/email-verify/request", post(routes::email_verify_request))
        .route("/email-verify/confirm", post(routes::email_verify_confirm))
        .merge(oauth_routes())
        .layer(prometheus_layer)
        .with_state(state)
}

/// Production router with per-IP rate limiting on /register, /login, /password-reset/request,
/// and /email-verify/request.
pub fn build_production_router(state: AppState) -> Router {
    let (prometheus_layer, metric_handle) = PROMETHEUS.clone();
    let rate_limited = Router::new()
        .route("/login", post(routes::login))
        .route("/register", post(routes::register))
        .route(
            "/password-reset/request",
            post(routes::password_reset_request),
        )
        .route("/email-verify/request", post(routes::email_verify_request))
        .route_layer(mw::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ));

    Router::new()
        .route("/health", get(routes::health))
        .route(
            "/metrics",
            get(move || async move { metric_handle.render() }),
        )
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
        .route("/email-verify/confirm", post(routes::email_verify_confirm))
        .merge(oauth_routes())
        .layer(prometheus_layer)
        .with_state(state)
}
