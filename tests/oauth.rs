use std::{
    net::SocketAddr,
    sync::Arc,
};

use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use rustauth::{
    AppState, OAuthConfig, build_router,
    domain::{JwtManager, PasswordService},
    email::{CapturedEmails, EmailClient},
};

const TEST_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIsgepUW6fIVvsGe3iwBb2mnhBFdIZ7zb+CfdLEo1pNB
-----END PRIVATE KEY-----";

const TEST_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADyia6fy2lW6Ezrs11/ZGt0axfBAfMSJu+rfdNbu62/Y=
-----END PUBLIC KEY-----";

/// Builds an `OAuthConfig` with both providers configured and every provider
/// endpoint redirected to `mock`, so callbacks never touch the real internet.
fn oauth_config(mock: &MockServer) -> OAuthConfig {
    OAuthConfig {
        github_client_id: Some("gh-client".to_string()),
        github_client_secret: Some("gh-secret".to_string()),
        google_client_id: Some("g-client".to_string()),
        google_client_secret: Some("g-secret".to_string()),
        github_auth_url: Some(format!("{}/github/authorize", mock.uri())),
        github_token_url: Some(format!("{}/github/token", mock.uri())),
        github_api_base_url: Some(format!("{}/github", mock.uri())),
        google_auth_url: Some(format!("{}/google/authorize", mock.uri())),
        google_token_url: Some(format!("{}/google/token", mock.uri())),
        google_userinfo_url: Some(format!("{}/google/userinfo", mock.uri())),
    }
}

async fn spawn_app(
    pool: PgPool,
    oauth: OAuthConfig,
) -> (String, CapturedEmails) {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
    let redis = redis::Client::open(redis_url).expect("valid redis url");

    let jwt = Arc::new(
        JwtManager::from_ed25519_pem(TEST_PRIVATE_PEM, TEST_PUBLIC_PEM)
            .expect("valid test keypair"),
    );
    let passwords = Arc::new(PasswordService::for_testing());
    let (email, captured) = EmailClient::capturing();

    let state = AppState {
        pool,
        jwt,
        passwords,
        redis,
        email: Arc::new(email),
        app_base_url: "http://app.test".to_string(),
        oauth: Arc::new(oauth),
        http: reqwest::Client::new(),
    };
    let app = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (format!("http://{addr}"), captured)
}

fn extract_token(link: &str) -> &str {
    link.split("token=").nth(1).expect("token= in link")
}

fn find_link(emails: &[(String, String)], path_fragment: &str) -> String {
    emails
        .iter()
        .rev()
        .find(|(_, link)| link.contains(path_fragment))
        .expect("expected a captured link matching the given path")
        .1
        .clone()
}

/// Registers a user and verifies their email via the captured link, leaving
/// behind a verified, password-protected account.
async fn register_and_verify(
    base: &str,
    client: &reqwest::Client,
    captured: &CapturedEmails,
    email: &str,
    password: &str,
) {
    client
        .post(format!("{base}/register"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await
        .unwrap();

    let link = find_link(&captured.lock().unwrap(), "/verify-email");
    let token = extract_token(&link).to_string();

    let res = client
        .post(format!("{base}/email-verify/confirm"))
        .json(&json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

/// Registers a user without verifying — leaves an unverified account
/// "squatting" on the email address with a password set.
async fn register_unverified(base: &str, client: &reqwest::Client, email: &str, password: &str) {
    let res = client
        .post(format!("{base}/register"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
}

async fn me(base: &str, client: &reqwest::Client, access_token: &str) -> Value {
    let res = client
        .get(format!("{base}/me"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

/// Drives `/auth/{provider}` to obtain a fresh, validly-stored OAuth state
/// token, mirroring how a real client would arrive at the callback.
async fn fetch_oauth_state(base: &str, client: &reqwest::Client, provider: &str) -> String {
    let res: Value = client
        .get(format!("{base}/auth/{provider}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let url = reqwest::Url::parse(res["authorization_url"].as_str().unwrap()).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "state")
        .expect("authorization_url contains a state param")
        .1
        .into_owned()
}

async fn callback(
    base: &str,
    client: &reqwest::Client,
    provider: &str,
    state: &str,
) -> reqwest::Response {
    client
        .get(format!(
            "{base}/auth/{provider}/callback?code=test-code&state={state}"
        ))
        .send()
        .await
        .unwrap()
}

// --- Mock provider responses ---

async fn mock_github_token(mock: &MockServer, access_token: &str) {
    Mock::given(method("POST"))
        .and(path("/github/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"access_token": access_token})),
        )
        .mount(mock)
        .await;
}

async fn mock_github_user(mock: &MockServer, id: i64, email: Option<&str>) {
    Mock::given(method("GET"))
        .and(path("/github/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": id, "email": email})))
        .mount(mock)
        .await;
}

async fn mock_github_emails(mock: &MockServer, emails: Value) {
    Mock::given(method("GET"))
        .and(path("/github/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(emails))
        .mount(mock)
        .await;
}

async fn mock_google_token(mock: &MockServer, access_token: &str) {
    Mock::given(method("POST"))
        .and(path("/google/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"access_token": access_token})),
        )
        .mount(mock)
        .await;
}

async fn mock_google_userinfo(mock: &MockServer, sub: &str, email: &str, email_verified: Value) {
    Mock::given(method("GET"))
        .and(path("/google/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": sub,
            "email": email,
            "email_verified": email_verified,
        })))
        .mount(mock)
        .await;
}

// --- GET /auth/{provider} ---

#[sqlx::test]
async fn authorize_returns_authorization_url_for_github(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{base}/auth/github"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    let url = reqwest::Url::parse(body["authorization_url"].as_str().unwrap()).unwrap();

    let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs["client_id"], "gh-client");
    assert_eq!(pairs["scope"], "user:email");
    assert_eq!(pairs["response_type"], "code");
    assert_eq!(
        pairs["redirect_uri"],
        "http://app.test/auth/github/callback"
    );
    assert!(!pairs["state"].is_empty());
}

#[sqlx::test]
async fn authorize_returns_422_for_unsupported_provider(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;

    let res = reqwest::Client::new()
        .get(format!("{base}/auth/twitter"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

#[sqlx::test]
async fn authorize_returns_500_when_provider_not_configured(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, OAuthConfig::default()).await;
    let _ = &mock;

    let res = reqwest::Client::new()
        .get(format!("{base}/auth/github"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 500);
}

// --- GET /auth/{provider}/callback — input validation ---

#[sqlx::test]
async fn callback_without_code_returns_400(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = client
        .get(format!("{base}/auth/github/callback?state={state}"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_without_state_returns_400(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{base}/auth/github/callback?code=test-code"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_with_provider_error_returns_400(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = client
        .get(format!(
            "{base}/auth/github/callback?error=access_denied&state={state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_with_unknown_state_returns_400(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    let res = callback(&base, &client, "github", "bogus-state-token").await;
    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_with_state_provider_mismatch_returns_400(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    // The state was issued for "github" but the callback path claims "google".
    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "google", &state).await;

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_state_is_single_use(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_github_token(&mock, "gh-access-token").await;
    mock_github_user(&mock, 555, Some("once@example.com")).await;

    let state = fetch_oauth_state(&base, &client, "github").await;

    let first = callback(&base, &client, "github", &state).await;
    assert_eq!(first.status(), 200);

    let second = callback(&base, &client, "github", &state).await;
    assert_eq!(second.status(), 400);
}

// --- GET /auth/{provider}/callback — account linking ---

#[sqlx::test]
async fn callback_creates_new_user_on_first_github_login(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_github_token(&mock, "gh-access-token").await;
    mock_github_user(&mock, 1001, Some("newgh@example.com")).await;

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "github", &state).await;
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());

    let profile = me(&base, &client, body["access_token"].as_str().unwrap()).await;
    assert_eq!(profile["email"], "newgh@example.com");
}

#[sqlx::test]
async fn callback_creates_new_user_on_first_google_login(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_google_token(&mock, "g-access-token").await;
    mock_google_userinfo(&mock, "google-sub-1", "newg@example.com", json!(true)).await;

    let state = fetch_oauth_state(&base, &client, "google").await;
    let res = callback(&base, &client, "google", &state).await;
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    let profile = me(&base, &client, body["access_token"].as_str().unwrap()).await;
    assert_eq!(profile["email"], "newg@example.com");
}

#[sqlx::test]
async fn callback_logs_into_existing_linked_account_on_repeat_login(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_github_token(&mock, "gh-access-token").await;
    mock_github_user(&mock, 2002, Some("repeat@example.com")).await;

    let first_state = fetch_oauth_state(&base, &client, "github").await;
    let first: Value = callback(&base, &client, "github", &first_state)
        .await
        .json()
        .await
        .unwrap();
    let first_profile = me(&base, &client, first["access_token"].as_str().unwrap()).await;

    let second_state = fetch_oauth_state(&base, &client, "github").await;
    let second_res = callback(&base, &client, "github", &second_state).await;
    assert_eq!(second_res.status(), 200);
    let second: Value = second_res.json().await.unwrap();
    let second_profile = me(&base, &client, second["access_token"].as_str().unwrap()).await;

    assert_eq!(first_profile["id"], second_profile["id"]);
    assert_eq!(second_profile["email"], "repeat@example.com");
}

#[sqlx::test]
async fn callback_links_to_existing_verified_account_with_same_email(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, captured) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    register_and_verify(
        &base,
        &client,
        &captured,
        "verified@example.com",
        "hunter2!",
    )
    .await;

    let login: Value = client
        .post(format!("{base}/login"))
        .json(&json!({"email": "verified@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let original_profile = me(&base, &client, login["access_token"].as_str().unwrap()).await;

    mock_github_token(&mock, "gh-access-token").await;
    mock_github_user(&mock, 3003, Some("verified@example.com")).await;

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "github", &state).await;
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    let oauth_profile = me(&base, &client, body["access_token"].as_str().unwrap()).await;

    // Same underlying account — the OAuth identity was linked, not duplicated.
    assert_eq!(original_profile["id"], oauth_profile["id"]);

    // The original password login must still work — linking must not clear it.
    let still_works = client
        .post(format!("{base}/login"))
        .json(&json!({"email": "verified@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(still_works.status(), 200);
}

#[sqlx::test]
async fn callback_reclaims_unverified_account_squatting_on_email(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _captured) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    // An account exists with this email but never verified it — a squatter.
    register_unverified(&base, &client, "squatted@example.com", "squatter-pw1").await;

    mock_github_token(&mock, "gh-access-token").await;
    mock_github_user(&mock, 4004, Some("squatted@example.com")).await;

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "github", &state).await;
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    let profile = me(&base, &client, body["access_token"].as_str().unwrap()).await;
    assert_eq!(profile["email"], "squatted@example.com");

    // The squatter's password must be revoked so it can no longer be used.
    let password_login = client
        .post(format!("{base}/login"))
        .json(&json!({"email": "squatted@example.com", "password": "squatter-pw1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(password_login.status(), 401);
}

#[sqlx::test]
async fn callback_github_falls_back_to_verified_primary_email(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_github_token(&mock, "gh-access-token").await;
    // Primary email is hidden on the /user endpoint — must be fetched from /user/emails.
    mock_github_user(&mock, 5005, None).await;
    mock_github_emails(
        &mock,
        json!([
            {"email": "secondary@example.com", "primary": false, "verified": true},
            {"email": "primary@example.com", "primary": true, "verified": true},
        ]),
    )
    .await;

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "github", &state).await;
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    let profile = me(&base, &client, body["access_token"].as_str().unwrap()).await;
    assert_eq!(profile["email"], "primary@example.com");
}

#[sqlx::test]
async fn callback_github_returns_400_when_no_verified_primary_email(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_github_token(&mock, "gh-access-token").await;
    mock_github_user(&mock, 6006, None).await;
    mock_github_emails(
        &mock,
        json!([{"email": "unverified@example.com", "primary": true, "verified": false}]),
    )
    .await;

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "github", &state).await;

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_google_returns_400_when_email_not_verified(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    mock_google_token(&mock, "g-access-token").await;
    mock_google_userinfo(
        &mock,
        "google-sub-2",
        "unverified@example.com",
        json!(false),
    )
    .await;

    let state = fetch_oauth_state(&base, &client, "google").await;
    let res = callback(&base, &client, "google", &state).await;

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn callback_returns_500_when_token_exchange_fails(pool: PgPool) {
    let mock = MockServer::start().await;
    let (base, _) = spawn_app(pool, oauth_config(&mock)).await;
    let client = reqwest::Client::new();

    Mock::given(method("POST"))
        .and(path("/github/token"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock)
        .await;

    let state = fetch_oauth_state(&base, &client, "github").await;
    let res = callback(&base, &client, "github", &state).await;

    assert_eq!(res.status(), 500);
}
