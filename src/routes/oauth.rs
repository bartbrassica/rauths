use axum::{
    Json,
    extract::{Path, Query, State},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    data::{OAuthRepository, RoleRepository, TokenStore, UserRepository},
};

use super::{ApiError, LoginResponse};

// --- Provider helpers ---

struct ProviderConfig<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    auth_url: &'a str,
    token_url: &'a str,
    scope: &'static str,
}

fn provider_config<'a>(
    provider: &str,
    state: &'a AppState,
) -> Result<ProviderConfig<'a>, ApiError> {
    match provider {
        "github" => Ok(ProviderConfig {
            client_id: state
                .oauth
                .github_client_id
                .as_deref()
                .ok_or(ApiError::Internal)?,
            client_secret: state
                .oauth
                .github_client_secret
                .as_deref()
                .ok_or(ApiError::Internal)?,
            auth_url: state
                .oauth
                .github_auth_url
                .as_deref()
                .unwrap_or("https://github.com/login/oauth/authorize"),
            token_url: state
                .oauth
                .github_token_url
                .as_deref()
                .unwrap_or("https://github.com/login/oauth/access_token"),
            scope: "user:email",
        }),
        "google" => Ok(ProviderConfig {
            client_id: state
                .oauth
                .google_client_id
                .as_deref()
                .ok_or(ApiError::Internal)?,
            client_secret: state
                .oauth
                .google_client_secret
                .as_deref()
                .ok_or(ApiError::Internal)?,
            auth_url: state
                .oauth
                .google_auth_url
                .as_deref()
                .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth"),
            token_url: state
                .oauth
                .google_token_url
                .as_deref()
                .unwrap_or("https://oauth2.googleapis.com/token"),
            scope: "openid email",
        }),
        _ => Err(ApiError::Validation("unsupported provider".into())),
    }
}

// --- GET /auth/{provider} ---

#[derive(Serialize)]
pub struct AuthorizeResponse {
    pub authorization_url: String,
}

pub async fn authorize(
    Path(provider): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<AuthorizeResponse>, ApiError> {
    let config = provider_config(&provider, &state)?;

    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let oauth_state = hex::encode(bytes);

    TokenStore::new(&state.redis)
        .store_oauth_state(&oauth_state, &provider)
        .await?;

    let redirect_uri = format!("{}/auth/{provider}/callback", state.app_base_url);

    let mut url =
        reqwest::Url::parse(config.auth_url).expect("static auth_url is always a valid URL");
    url.query_pairs_mut()
        .append_pair("client_id", config.client_id)
        .append_pair("scope", config.scope)
        .append_pair("state", &oauth_state)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code");

    Ok(Json(AuthorizeResponse {
        authorization_url: url.to_string(),
    }))
}

// --- GET /auth/{provider}/callback ---

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    State(state): State<AppState>,
) -> Result<Json<LoginResponse>, ApiError> {
    if query.error.is_some() {
        return Err(ApiError::BadRequest("oauth authorization denied".into()));
    }

    let code = query
        .code
        .ok_or_else(|| ApiError::BadRequest("missing code".into()))?;
    let oauth_state = query
        .state
        .ok_or_else(|| ApiError::BadRequest("missing state".into()))?;

    let stored_provider = TokenStore::new(&state.redis)
        .consume_oauth_state(&oauth_state)
        .await?
        .ok_or_else(|| ApiError::BadRequest("invalid or expired state".into()))?;

    if stored_provider != provider {
        return Err(ApiError::BadRequest("state provider mismatch".into()));
    }

    let config = provider_config(&provider, &state)?;
    let redirect_uri = format!("{}/auth/{provider}/callback", state.app_base_url);

    let access_token = exchange_code(&state.http, &config, &code, &redirect_uri).await?;

    let (provider_user_id, email) = match provider.as_str() {
        "github" => {
            let api_base = state
                .oauth
                .github_api_base_url
                .as_deref()
                .unwrap_or("https://api.github.com");
            fetch_github_user(&state.http, &access_token, api_base).await?
        }
        "google" => {
            let userinfo_url = state
                .oauth
                .google_userinfo_url
                .as_deref()
                .unwrap_or("https://www.googleapis.com/oauth2/v3/userinfo");
            fetch_google_user(&state.http, &access_token, userinfo_url).await?
        }
        _ => return Err(ApiError::Validation("unsupported provider".into())),
    };

    let oauth_repo = OAuthRepository::new(&state.pool);
    let user_repo = UserRepository::new(&state.pool);

    let user_id = if let Some(account) = oauth_repo
        .find_account(&provider, &provider_user_id)
        .await?
    {
        account.user_id
    } else {
        let user = match user_repo.find_by_email(&email).await? {
            Some(existing) if existing.email_verified_at.is_none() => {
                // The provider has just proven ownership of this email, but the
                // existing account never verified it — it was squatting on the
                // address. Reclaim it for the verified owner and revoke the
                // squatter's password so it can no longer be used to log in.
                user_repo.mark_verified(existing.id).await?;
                user_repo.clear_password(existing.id).await?;
                tracing::warn!(
                    user_id = %existing.id,
                    provider = %provider,
                    event = "oauth_account_reclaimed"
                );
                existing
            }
            Some(existing) => existing,
            None => user_repo.create_oauth_user(&email).await?,
        };
        oauth_repo
            .create_account(user.id, &provider, &provider_user_id)
            .await?;
        user.id
    };

    let user = user_repo
        .find_by_id(user_id)
        .await?
        .ok_or(ApiError::Internal)?;

    let roles = RoleRepository::new(&state.pool)
        .list_for_user(user_id)
        .await?;
    let access_token_jwt = state.jwt.sign_access_token(user_id, &user.email, &roles)?;
    let (refresh_token, refresh_jti) = state.jwt.sign_refresh_token(user_id, &user.email)?;
    TokenStore::new(&state.redis)
        .store_refresh_token(refresh_jti, user_id, 7 * 24 * 3600)
        .await?;

    tracing::info!(
        user_id = %user_id,
        provider = %provider,
        event = "oauth_login_success"
    );

    Ok(Json(LoginResponse {
        access_token: access_token_jwt,
        refresh_token,
    }))
}

// --- Provider HTTP helpers ---

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

async fn exchange_code(
    http: &reqwest::Client,
    config: &ProviderConfig<'_>,
    code: &str,
    redirect_uri: &str,
) -> Result<String, ApiError> {
    let resp = http
        .post(config.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id),
            ("client_secret", config.client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, event = "oauth_token_exchange_failed");
            ApiError::Internal
        })?;

    if !resp.status().is_success() {
        tracing::error!(status = %resp.status(), event = "oauth_token_exchange_failed");
        return Err(ApiError::Internal);
    }

    let token: TokenResponse = resp.json().await.map_err(|e| {
        tracing::error!(error = %e, event = "oauth_token_parse_failed");
        ApiError::Internal
    })?;

    Ok(token.access_token)
}

#[derive(Deserialize)]
struct GithubUser {
    id: i64,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

async fn fetch_github_user(
    http: &reqwest::Client,
    token: &str,
    api_base: &str,
) -> Result<(String, String), ApiError> {
    let user: GithubUser = http
        .get(format!("{api_base}/user"))
        .bearer_auth(token)
        .header("User-Agent", "rustauth")
        .send()
        .await
        .map_err(|_| ApiError::Internal)?
        .json()
        .await
        .map_err(|_| ApiError::Internal)?;

    let email = if let Some(e) = user.email {
        e
    } else {
        let emails: Vec<GithubEmail> = http
            .get(format!("{api_base}/user/emails"))
            .bearer_auth(token)
            .header("User-Agent", "rustauth")
            .send()
            .await
            .map_err(|_| ApiError::Internal)?
            .json()
            .await
            .map_err(|_| ApiError::Internal)?;

        emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .ok_or_else(|| {
                ApiError::BadRequest("no verified primary email on github account".into())
            })?
            .email
    };

    Ok((user.id.to_string(), email))
}

#[derive(Deserialize)]
struct GoogleUser {
    sub: String,
    email: String,
    email_verified: Option<bool>,
}

async fn fetch_google_user(
    http: &reqwest::Client,
    token: &str,
    userinfo_url: &str,
) -> Result<(String, String), ApiError> {
    let user: GoogleUser = http
        .get(userinfo_url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| ApiError::Internal)?
        .json()
        .await
        .map_err(|_| ApiError::Internal)?;

    if user.email_verified != Some(true) {
        return Err(ApiError::BadRequest(
            "google account email is not verified".into(),
        ));
    }

    Ok((user.sub, user.email))
}
