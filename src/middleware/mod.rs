use std::net::SocketAddr;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use redis::AsyncCommands;

use crate::{AppState, data::TokenStore, domain::Claims};

// --- JWT auth extractor ---

/// Extractor that validates the `Authorization: Bearer <token>` header
/// and injects the verified [`Claims`] into the handler.
pub struct AuthUser(pub Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingToken)?;

        let claims = state
            .jwt
            .verify_access(token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Fails open on cache errors so a Redis outage never locks out authenticated
        // users — the same trade-off the rate limiter makes.
        match TokenStore::new(&state.redis)
            .is_access_token_revoked(claims.jti)
            .await
        {
            Ok(true) => return Err(AuthError::InvalidToken),
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e, "revocation check unavailable, failing open"),
        }

        Ok(AuthUser(claims))
    }
}

pub enum AuthError {
    MissingToken,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::MissingToken => (StatusCode::UNAUTHORIZED, "missing authorization token"),
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid or expired token"),
        };
        (status, body).into_response()
    }
}

// --- Rate limiting middleware ---

const RATE_LIMIT_MAX: u64 = 5;
const RATE_LIMIT_WINDOW_SECS: i64 = 60;

const USER_RATE_LIMIT_MAX: u64 = 30;
const USER_RATE_LIMIT_WINDOW_SECS: i64 = 60;

/// Per-IP rate limiter backed by Redis. Allows [`RATE_LIMIT_MAX`] requests per
/// [`RATE_LIMIT_WINDOW_SECS`] seconds. Fails open if Redis is unavailable so a
/// cache outage never takes down the auth service.
pub async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let route = request.uri().path().to_owned();
    let key = format!("rl:{route}:{ip}");

    match check_rate_limit(&state.redis, &key, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECS).await {
        Ok(true) => {
            tracing::warn!(ip = %ip, route = %route, event = "rate_limit_exceeded");
            (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response()
        }
        Ok(false) => next.run(request).await,
        Err(e) => {
            tracing::error!(error = %e, "rate limiter unavailable, failing open");
            next.run(request).await
        }
    }
}

/// Per-user rate limiter backed by Redis, for authenticated endpoints. Allows
/// [`USER_RATE_LIMIT_MAX`] requests per [`USER_RATE_LIMIT_WINDOW_SECS`] seconds
/// per user, on top of the per-IP limit. Requests without a valid access token
/// are passed through — [`AuthUser`] is responsible for rejecting those.
/// Fails open if Redis is unavailable, matching [`rate_limit`].
pub async fn user_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let user_id = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|token| state.jwt.verify_access(token).ok())
        .map(|claims| claims.sub);

    let Some(user_id) = user_id else {
        return next.run(request).await;
    };

    let route = request.uri().path().to_owned();
    let key = format!("rl:user:{route}:{user_id}");

    match check_rate_limit(
        &state.redis,
        &key,
        USER_RATE_LIMIT_MAX,
        USER_RATE_LIMIT_WINDOW_SECS,
    )
    .await
    {
        Ok(true) => {
            tracing::warn!(user_id = %user_id, route = %route, event = "user_rate_limit_exceeded");
            (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response()
        }
        Ok(false) => next.run(request).await,
        Err(e) => {
            tracing::error!(error = %e, "rate limiter unavailable, failing open");
            next.run(request).await
        }
    }
}

async fn check_rate_limit(
    redis: &redis::Client,
    key: &str,
    max: u64,
    window_secs: i64,
) -> redis::RedisResult<bool> {
    let mut conn = redis.get_multiplexed_async_connection().await?;
    let count: u64 = conn.incr(key, 1u64).await?;
    // Only set TTL on the first increment to avoid resetting the window on each hit.
    if count == 1 {
        let _: () = conn.expire(key, window_secs).await?;
    }
    Ok(count > max)
}
