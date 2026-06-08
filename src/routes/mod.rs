pub mod oauth;

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    AppState,
    data::{
        AuditLogRepository, DataError, EmailVerificationTokenRepository, LockoutStore,
        ResetTokenRepository, RoleRepository, TokenStore, UserRepository,
    },
    domain::DomainError,
    middleware::AuthUser,
};

/// Generates a random token paired with its SHA-256 hash for storage.
/// The raw token is sent to the user; only the hash is persisted, so a
/// database leak doesn't expose usable tokens.
fn generate_secure_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let raw = hex::encode(bytes);
    let hash = hex::encode(Sha256::digest(raw.as_bytes()));
    (raw, hash)
}

/// Increments the `auth_events_total{event, reason}` counter for a security
/// event (login, logout, password reset, lockout, OAuth link, ...). Use an
/// empty `reason` for events that don't have one (e.g. successes).
fn record_auth_event(
    event: &'static str,
    reason: impl Into<axum_prometheus::metrics::SharedString>,
) {
    axum_prometheus::metrics::counter!(
        "auth_events_total",
        "event" => event,
        "reason" => reason.into(),
    )
    .increment(1);
}

/// Persists a security event to the `audit_events` table for compliance and
/// forensics. Insert failures are logged but never propagated — an audit-log
/// outage must not block authentication.
async fn audit(
    state: &AppState,
    user_id: Option<Uuid>,
    event: &'static str,
    reason: Option<&str>,
    ip: std::net::IpAddr,
) {
    if let Err(e) = AuditLogRepository::new(&state.pool)
        .record(user_id, event, reason, &ip.to_string())
        .await
    {
        tracing::error!(error = %e, event, "audit_log_write_failed");
    }
}

// --- /register ---

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

impl RegisterRequest {
    fn validate(&self) -> Result<(), ApiError> {
        validate_email(&self.email)?;
        validate_password(&self.password)?;
        Ok(())
    }
}

fn validate_email(email: &str) -> Result<(), ApiError> {
    if email.len() > 254 {
        return Err(ApiError::Validation("email too long".into()));
    }
    let at = email
        .find('@')
        .ok_or_else(|| ApiError::Validation("invalid email".into()))?;
    // Reject multiple @ signs
    if email[at + 1..].contains('@') {
        return Err(ApiError::Validation("invalid email".into()));
    }
    let local = &email[..at];
    let domain = &email[at + 1..];
    if local.is_empty() || local.len() > 64 {
        return Err(ApiError::Validation("invalid email".into()));
    }
    // Domain must have at least one dot, not at the start or end
    if domain.starts_with('.') {
        return Err(ApiError::Validation("invalid email".into()));
    }
    let dot = domain
        .rfind('.')
        .ok_or_else(|| ApiError::Validation("invalid email".into()))?;
    if domain[dot + 1..].is_empty() {
        return Err(ApiError::Validation("invalid email".into()));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.len() < 8 {
        return Err(ApiError::Validation(
            "password must be at least 8 characters".into(),
        ));
    }
    // Upper bound prevents Argon2 DoS via extremely long inputs
    if password.len() > 128 {
        return Err(ApiError::Validation("password too long".into()));
    }
    Ok(())
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: Uuid,
    pub email: String,
}

pub async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    body.validate()?;
    let hash = state.passwords.hash(&body.password)?;
    let repo = UserRepository::new(&state.pool);
    let user = match repo.create(&body.email, &hash).await {
        Ok(user) => user,
        Err(e) => {
            if matches!(e, DataError::EmailConflict) {
                tracing::warn!(email = %body.email, ip = %addr.ip(), event = "register_failed", reason = "email_conflict");
                record_auth_event("register_failed", "email_conflict");
                audit(
                    &state,
                    None,
                    "register_failed",
                    Some("email_conflict"),
                    addr.ip(),
                )
                .await;
            }
            return Err(ApiError::from(e));
        }
    };
    tracing::info!(email = %user.email, user_id = %user.id, ip = %addr.ip(), event = "register_success");
    record_auth_event("register_success", "");
    audit(&state, Some(user.id), "register_success", None, addr.ip()).await;

    let (raw_token, token_hash) = generate_secure_token();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);
    EmailVerificationTokenRepository::new(&state.pool)
        .create(user.id, &token_hash, expires_at)
        .await?;
    let verify_link = format!("{}/verify-email?token={}", state.app_base_url, raw_token);
    if let Err(e) = state
        .email
        .send_verification_email(&user.email, &verify_link)
        .await
    {
        tracing::error!(user_id = %user.id, error = %e, event = "verification_email_failed");
    }

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: user.id,
            email: user.email,
        }),
    ))
}

// --- /login ---

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

impl LoginRequest {
    fn validate(&self) -> Result<(), ApiError> {
        validate_email(&self.email)?;
        if self.password.is_empty() {
            return Err(ApiError::Validation("password is required".into()));
        }
        // Upper bound prevents Argon2 DoS via extremely long inputs during verify
        if self.password.len() > 128 {
            return Err(ApiError::Validation("password too long".into()));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    body.validate()?;

    let lockout = LockoutStore::new(&state.redis);
    if lockout.is_locked(&body.email).await? {
        tracing::warn!(email = %body.email, ip = %addr.ip(), event = "login_failed", reason = "account_locked");
        record_auth_event("login_failed", "account_locked");
        audit(
            &state,
            None,
            "login_failed",
            Some("account_locked"),
            addr.ip(),
        )
        .await;
        return Err(ApiError::Unauthorized);
    }

    let repo = UserRepository::new(&state.pool);
    let user = match repo.find_by_email(&body.email).await? {
        Some(u) => u,
        None => {
            tracing::warn!(email = %body.email, ip = %addr.ip(), event = "login_failed", reason = "unknown_email");
            record_auth_event("login_failed", "unknown_email");
            audit(
                &state,
                None,
                "login_failed",
                Some("unknown_email"),
                addr.ip(),
            )
            .await;
            return Err(ApiError::Unauthorized);
        }
    };

    let hash = match user.password_hash.as_deref() {
        Some(hash) => hash,
        None => {
            tracing::warn!(email = %body.email, ip = %addr.ip(), event = "login_failed", reason = "oauth_only_account");
            record_auth_event("login_failed", "oauth_only_account");
            audit(
                &state,
                Some(user.id),
                "login_failed",
                Some("oauth_only_account"),
                addr.ip(),
            )
            .await;
            return Err(ApiError::Unauthorized);
        }
    };
    if !state.passwords.verify(&body.password, hash)? {
        let attempts = lockout.record_failure(&body.email).await?;
        tracing::warn!(email = %body.email, ip = %addr.ip(), attempts, event = "login_failed", reason = "invalid_password");
        record_auth_event("login_failed", "invalid_password");
        audit(
            &state,
            Some(user.id),
            "login_failed",
            Some("invalid_password"),
            addr.ip(),
        )
        .await;
        return Err(ApiError::Unauthorized);
    }

    lockout.clear(&body.email).await?;

    // Checked only after the password is confirmed correct, so an attacker
    // probing emails can't use this to learn whether an account is unverified.
    if user.email_verified_at.is_none() {
        tracing::warn!(email = %body.email, ip = %addr.ip(), event = "login_failed", reason = "email_not_verified");
        record_auth_event("login_failed", "email_not_verified");
        audit(
            &state,
            Some(user.id),
            "login_failed",
            Some("email_not_verified"),
            addr.ip(),
        )
        .await;
        return Err(ApiError::EmailNotVerified);
    }

    let roles = RoleRepository::new(&state.pool)
        .list_for_user(user.id)
        .await?;
    let access_token = state.jwt.sign_access_token(user.id, &user.email, &roles)?;
    let (refresh_token, refresh_jti) = state.jwt.sign_refresh_token(user.id, &user.email)?;

    TokenStore::new(&state.redis)
        .store_refresh_token(refresh_jti, user.id, 7 * 24 * 3600)
        .await?;

    tracing::info!(email = %user.email, user_id = %user.id, ip = %addr.ip(), event = "login_success");
    record_auth_event("login_success", "");
    audit(&state, Some(user.id), "login_success", None, addr.ip()).await;
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
    }))
}

// --- /refresh ---

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl RefreshRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.refresh_token.is_empty() {
            return Err(ApiError::Validation("refresh_token is required".into()));
        }
        Ok(())
    }
}

pub async fn refresh(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    body.validate()?;
    let claims = match state.jwt.verify_refresh(&body.refresh_token) {
        Ok(claims) => claims,
        Err(_) => {
            tracing::warn!(ip = %addr.ip(), event = "refresh_failed", reason = "invalid_token");
            record_auth_event("refresh_failed", "invalid_token");
            audit(
                &state,
                None,
                "refresh_failed",
                Some("invalid_token"),
                addr.ip(),
            )
            .await;
            return Err(ApiError::Unauthorized);
        }
    };

    let store = TokenStore::new(&state.redis);
    // Atomically consume the old JTI — None means already revoked or unknown.
    let revoked = store.revoke_refresh_token(claims.jti).await?;
    if revoked.is_none() {
        tracing::warn!(user_id = %claims.sub, ip = %addr.ip(), event = "refresh_failed", reason = "token_revoked");
        record_auth_event("refresh_failed", "token_revoked");
        audit(
            &state,
            Some(claims.sub),
            "refresh_failed",
            Some("token_revoked"),
            addr.ip(),
        )
        .await;
        return Err(ApiError::Unauthorized);
    }

    let roles = RoleRepository::new(&state.pool)
        .list_for_user(claims.sub)
        .await?;
    let access_token = state
        .jwt
        .sign_access_token(claims.sub, &claims.email, &roles)?;
    let (refresh_token, new_jti) = state.jwt.sign_refresh_token(claims.sub, &claims.email)?;

    store
        .store_refresh_token(new_jti, claims.sub, 7 * 24 * 3600)
        .await?;

    tracing::info!(user_id = %claims.sub, ip = %addr.ip(), event = "token_refreshed");
    record_auth_event("token_refreshed", "");
    audit(&state, Some(claims.sub), "token_refreshed", None, addr.ip()).await;
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
    }))
}

// --- /me ---

#[derive(Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub email: String,
}

pub async fn me(AuthUser(claims): AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        id: claims.sub,
        email: claims.email,
    })
}

// --- PATCH /me/password ---

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

impl ChangePasswordRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.current_password.is_empty() {
            return Err(ApiError::Validation("current_password is required".into()));
        }
        if self.current_password.len() > 128 {
            return Err(ApiError::Validation("current_password too long".into()));
        }
        validate_password(&self.new_password)?;
        Ok(())
    }
}

pub async fn change_password(
    AuthUser(claims): AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    body.validate()?;
    let repo = UserRepository::new(&state.pool);
    let user = repo
        .find_by_id(claims.sub)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let hash = user
        .password_hash
        .as_deref()
        .ok_or(ApiError::Unauthorized)?;
    if !state.passwords.verify(&body.current_password, hash)? {
        tracing::warn!(user_id = %claims.sub, ip = %addr.ip(), event = "change_password_failed", reason = "wrong_current_password");
        record_auth_event("change_password_failed", "wrong_current_password");
        audit(
            &state,
            Some(claims.sub),
            "change_password_failed",
            Some("wrong_current_password"),
            addr.ip(),
        )
        .await;
        return Err(ApiError::Unauthorized);
    }
    let new_hash = state.passwords.hash(&body.new_password)?;
    repo.update_password(claims.sub, &new_hash).await?;
    tracing::info!(user_id = %claims.sub, ip = %addr.ip(), event = "password_changed");
    record_auth_event("password_changed", "");
    audit(
        &state,
        Some(claims.sub),
        "password_changed",
        None,
        addr.ip(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- DELETE /me ---

pub async fn delete_me(
    AuthUser(claims): AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    // Recorded before deletion — once the user row is gone, an audit_events
    // row referencing it would violate the foreign-key constraint.
    audit(&state, Some(claims.sub), "account_deleted", None, addr.ip()).await;
    let repo = UserRepository::new(&state.pool);
    repo.delete(claims.sub).await?;
    tracing::info!(user_id = %claims.sub, ip = %addr.ip(), event = "account_deleted");
    record_auth_event("account_deleted", "");
    Ok(StatusCode::NO_CONTENT)
}

// --- /health ---

#[derive(Serialize)]
pub struct HealthResponse {
    pub db: &'static str,
    pub redis: &'static str,
}

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query!("SELECT 1 as ping")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    let redis_ok = async {
        let mut conn = state.redis.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<String>(&mut conn).await
    }
    .await
    .is_ok();

    let status = if db_ok && redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            db: if db_ok { "ok" } else { "error" },
            redis: if redis_ok { "ok" } else { "error" },
        }),
    )
}

// --- /openapi.yaml & /docs ---

const OPENAPI_SPEC: &str = include_str!("../../openapi.yaml");

const SWAGGER_UI_HTML: &str = r##"<!DOCTYPE html>
<html>
  <head>
    <title>rauths API docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => {
        window.ui = SwaggerUIBundle({
          url: "/openapi.yaml",
          dom_id: "#swagger-ui",
        });
      };
    </script>
  </body>
</html>"##;

pub async fn openapi_spec() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI_SPEC)
}

pub async fn docs() -> impl IntoResponse {
    Html(SWAGGER_UI_HTML)
}

// --- POST /me/sessions/revoke-all ---

pub async fn logout_all(
    AuthUser(claims): AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let count = TokenStore::new(&state.redis)
        .revoke_all_sessions(claims.sub)
        .await?;
    tracing::info!(user_id = %claims.sub, ip = %addr.ip(), sessions_revoked = count, event = "logout_all");
    record_auth_event("logout_all", "");
    audit(&state, Some(claims.sub), "logout_all", None, addr.ip()).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- /logout ---

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

impl LogoutRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if self.refresh_token.is_empty() {
            return Err(ApiError::Validation("refresh_token is required".into()));
        }
        Ok(())
    }
}

pub async fn logout(
    AuthUser(access_claims): AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<LogoutRequest>,
) -> Result<StatusCode, ApiError> {
    body.validate()?;
    let claims = match state.jwt.verify_refresh(&body.refresh_token) {
        Ok(claims) => claims,
        Err(_) => {
            tracing::warn!(ip = %addr.ip(), event = "logout_failed", reason = "invalid_token");
            record_auth_event("logout_failed", "invalid_token");
            audit(
                &state,
                None,
                "logout_failed",
                Some("invalid_token"),
                addr.ip(),
            )
            .await;
            return Err(ApiError::Unauthorized);
        }
    };
    let store = TokenStore::new(&state.redis);
    store.revoke_refresh_token(claims.jti).await?;

    // Block the access token for the remainder of its lifetime so a stolen
    // copy can't be used after the user has logged out.
    let remaining = access_claims.exp - chrono::Utc::now().timestamp();
    if remaining > 0 {
        store
            .revoke_access_token(access_claims.jti, remaining as u64)
            .await?;
    }

    tracing::info!(user_id = %claims.sub, ip = %addr.ip(), event = "logout");
    record_auth_event("logout", "");
    audit(&state, Some(claims.sub), "logout", None, addr.ip()).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- /password-reset/request ---

#[derive(Deserialize)]
pub struct PasswordResetRequestBody {
    pub email: String,
}

impl PasswordResetRequestBody {
    fn validate(&self) -> Result<(), ApiError> {
        validate_email(&self.email)?;
        Ok(())
    }
}

pub async fn password_reset_request(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<PasswordResetRequestBody>,
) -> Result<StatusCode, ApiError> {
    body.validate()?;

    let repo = UserRepository::new(&state.pool);
    if let Some(user) = repo.find_by_email(&body.email).await? {
        let (raw_token, token_hash) = generate_secure_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);

        ResetTokenRepository::new(&state.pool)
            .create(user.id, &token_hash, expires_at)
            .await?;

        let reset_link = format!("{}/reset-password?token={}", state.app_base_url, raw_token);
        if let Err(e) = state
            .email
            .send_password_reset(&user.email, &reset_link)
            .await
        {
            tracing::error!(user_id = %user.id, error = %e, event = "password_reset_email_failed");
        } else {
            tracing::info!(user_id = %user.id, ip = %addr.ip(), event = "password_reset_requested");
            record_auth_event("password_reset_requested", "");
            audit(
                &state,
                Some(user.id),
                "password_reset_requested",
                None,
                addr.ip(),
            )
            .await;
        }
    }

    Ok(StatusCode::OK)
}

// --- /password-reset/confirm ---

#[derive(Deserialize)]
pub struct PasswordResetConfirmBody {
    pub token: String,
    pub new_password: String,
}

impl PasswordResetConfirmBody {
    fn validate(&self) -> Result<(), ApiError> {
        if self.token.is_empty() {
            return Err(ApiError::Validation("token is required".into()));
        }
        validate_password(&self.new_password)?;
        Ok(())
    }
}

pub async fn password_reset_confirm(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<PasswordResetConfirmBody>,
) -> Result<StatusCode, ApiError> {
    body.validate()?;

    let token_hash = hex::encode(Sha256::digest(body.token.as_bytes()));
    let user_id = ResetTokenRepository::new(&state.pool)
        .consume(&token_hash)
        .await?
        .ok_or_else(|| ApiError::BadRequest("invalid or expired reset token".into()))?;

    let new_hash = state.passwords.hash(&body.new_password)?;
    UserRepository::new(&state.pool)
        .update_password(user_id, &new_hash)
        .await?;

    TokenStore::new(&state.redis)
        .revoke_all_sessions(user_id)
        .await?;

    tracing::info!(user_id = %user_id, ip = %addr.ip(), event = "password_reset_confirmed");
    record_auth_event("password_reset_confirmed", "");
    audit(
        &state,
        Some(user_id),
        "password_reset_confirmed",
        None,
        addr.ip(),
    )
    .await;
    Ok(StatusCode::OK)
}

// --- /email-verify/request ---

#[derive(Deserialize)]
pub struct EmailVerifyRequestBody {
    pub email: String,
}

impl EmailVerifyRequestBody {
    fn validate(&self) -> Result<(), ApiError> {
        validate_email(&self.email)?;
        Ok(())
    }
}

pub async fn email_verify_request(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<EmailVerifyRequestBody>,
) -> Result<StatusCode, ApiError> {
    body.validate()?;

    let repo = UserRepository::new(&state.pool);
    if let Some(user) = repo.find_by_email(&body.email).await?
        && user.email_verified_at.is_none()
    {
        let (raw_token, token_hash) = generate_secure_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);

        EmailVerificationTokenRepository::new(&state.pool)
            .create(user.id, &token_hash, expires_at)
            .await?;

        let verify_link = format!("{}/verify-email?token={}", state.app_base_url, raw_token);
        if let Err(e) = state
            .email
            .send_verification_email(&user.email, &verify_link)
            .await
        {
            tracing::error!(user_id = %user.id, error = %e, event = "verification_email_failed");
        } else {
            tracing::info!(user_id = %user.id, ip = %addr.ip(), event = "verification_requested");
            record_auth_event("verification_requested", "");
            audit(
                &state,
                Some(user.id),
                "verification_requested",
                None,
                addr.ip(),
            )
            .await;
        }
    }

    Ok(StatusCode::OK)
}

// --- /email-verify/confirm ---

#[derive(Deserialize)]
pub struct EmailVerifyConfirmBody {
    pub token: String,
}

impl EmailVerifyConfirmBody {
    fn validate(&self) -> Result<(), ApiError> {
        if self.token.is_empty() {
            return Err(ApiError::Validation("token is required".into()));
        }
        Ok(())
    }
}

pub async fn email_verify_confirm(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(body): Json<EmailVerifyConfirmBody>,
) -> Result<StatusCode, ApiError> {
    body.validate()?;

    let token_hash = hex::encode(Sha256::digest(body.token.as_bytes()));
    let user_id = EmailVerificationTokenRepository::new(&state.pool)
        .consume(&token_hash)
        .await?
        .ok_or_else(|| ApiError::BadRequest("invalid or expired verification token".into()))?;

    UserRepository::new(&state.pool)
        .mark_verified(user_id)
        .await?;

    tracing::info!(user_id = %user_id, ip = %addr.ip(), event = "email_verified");
    record_auth_event("email_verified", "");
    audit(&state, Some(user_id), "email_verified", None, addr.ip()).await;
    Ok(StatusCode::OK)
}

// --- Error type ---

pub enum ApiError {
    BadRequest(String),
    Conflict,
    Unauthorized,
    EmailNotVerified,
    Validation(String),
    Internal,
}

impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        match e {
            DomainError::InvalidToken(_) | DomainError::WrongTokenKind => Self::Unauthorized,
            DomainError::Hashing(_) => Self::Internal,
        }
    }
}

impl From<DataError> for ApiError {
    fn from(e: DataError) -> Self {
        match e {
            DataError::EmailConflict => Self::Conflict,
            DataError::NotFound | DataError::Database(_) | DataError::Cache(_) => Self::Internal,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::Conflict => (StatusCode::CONFLICT, "email already registered").into_response(),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(),
            Self::EmailNotVerified => (StatusCode::FORBIDDEN, "email not verified").into_response(),
            Self::Validation(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg).into_response(),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(email: &str, password: &str) {
        let req = RegisterRequest {
            email: email.into(),
            password: password.into(),
        };
        assert!(
            req.validate().is_ok(),
            "expected ok for email={email:?} password={password:?}"
        );
    }

    fn err(email: &str, password: &str) {
        let req = RegisterRequest {
            email: email.into(),
            password: password.into(),
        };
        assert!(
            req.validate().is_err(),
            "expected err for email={email:?} password={password:?}"
        );
    }

    #[test]
    fn valid_inputs_pass() {
        ok("alice@example.com", "password123");
        ok("a@b.io", "password123");
        ok("user+tag@sub.domain.org", "password123");
    }

    #[test]
    fn email_missing_at_fails() {
        err("notanemail", "password123");
    }

    #[test]
    fn email_empty_local_part_fails() {
        err("@example.com", "password123");
    }

    #[test]
    fn email_no_dot_in_domain_fails() {
        err("user@nodot", "password123");
    }

    #[test]
    fn email_domain_starts_with_dot_fails() {
        err("user@.example.com", "password123");
    }

    #[test]
    fn email_domain_ends_with_dot_fails() {
        err("user@example.", "password123");
    }

    #[test]
    fn email_multiple_at_signs_fails() {
        err("a@b@c.com", "password123");
    }

    #[test]
    fn email_too_long_fails() {
        let long = format!("{}@example.com", "a".repeat(245));
        err(&long, "password123");
    }

    #[test]
    fn password_empty_fails() {
        err("alice@example.com", "");
    }

    #[test]
    fn password_too_short_fails() {
        err("alice@example.com", "short");
        err("alice@example.com", "1234567"); // 7 chars
    }

    #[test]
    fn password_exactly_8_chars_passes() {
        ok("alice@example.com", "12345678");
    }

    #[test]
    fn password_too_long_fails() {
        let long = "a".repeat(129);
        err("alice@example.com", &long);
    }

    #[test]
    fn password_exactly_128_chars_passes() {
        ok("alice@example.com", &"a".repeat(128));
    }

    // --- LoginRequest::validate ---

    fn login_ok(email: &str, password: &str) {
        let req = LoginRequest {
            email: email.into(),
            password: password.into(),
        };
        assert!(
            req.validate().is_ok(),
            "expected ok for email={email:?} password={password:?}"
        );
    }

    fn login_err(email: &str, password: &str) {
        let req = LoginRequest {
            email: email.into(),
            password: password.into(),
        };
        assert!(
            req.validate().is_err(),
            "expected err for email={email:?} password={password:?}"
        );
    }

    #[test]
    fn login_valid_inputs_pass() {
        login_ok("alice@example.com", "anypassword");
        // Short password is allowed on login — policy only enforced on register
        login_ok("alice@example.com", "short");
        login_ok("alice@example.com", &"a".repeat(128));
    }

    #[test]
    fn login_invalid_email_fails() {
        login_err("notanemail", "anypassword");
        login_err("@example.com", "anypassword");
        login_err("user@nodot", "anypassword");
    }

    #[test]
    fn login_empty_password_fails() {
        login_err("alice@example.com", "");
    }

    #[test]
    fn login_password_over_128_chars_fails() {
        login_err("alice@example.com", &"a".repeat(129));
    }

    // --- RefreshRequest::validate ---

    #[test]
    fn refresh_empty_token_fails() {
        let req = RefreshRequest {
            refresh_token: "".into(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn refresh_non_empty_token_passes() {
        let req = RefreshRequest {
            refresh_token: "some.jwt.token".into(),
        };
        assert!(req.validate().is_ok());
    }

    // --- LogoutRequest::validate ---

    #[test]
    fn logout_empty_token_fails() {
        let req = LogoutRequest {
            refresh_token: "".into(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn logout_non_empty_token_passes() {
        let req = LogoutRequest {
            refresh_token: "some.jwt.token".into(),
        };
        assert!(req.validate().is_ok());
    }

    // --- ChangePasswordRequest::validate ---

    fn cp_ok(current: &str, new: &str) {
        let req = ChangePasswordRequest {
            current_password: current.into(),
            new_password: new.into(),
        };
        assert!(
            req.validate().is_ok(),
            "expected ok for current={current:?} new={new:?}"
        );
    }

    fn cp_err(current: &str, new: &str) {
        let req = ChangePasswordRequest {
            current_password: current.into(),
            new_password: new.into(),
        };
        assert!(
            req.validate().is_err(),
            "expected err for current={current:?} new={new:?}"
        );
    }

    #[test]
    fn change_password_valid_inputs_pass() {
        cp_ok("oldpassword", "newpassword");
        cp_ok("a", "12345678");
        cp_ok(&"a".repeat(128), "12345678");
    }

    #[test]
    fn change_password_empty_current_fails() {
        cp_err("", "newpassword");
    }

    #[test]
    fn change_password_current_over_128_fails() {
        cp_err(&"a".repeat(129), "newpassword");
    }

    #[test]
    fn change_password_new_too_short_fails() {
        cp_err("oldpassword", "short");
    }

    #[test]
    fn change_password_new_too_long_fails() {
        cp_err("oldpassword", &"a".repeat(129));
    }
}
