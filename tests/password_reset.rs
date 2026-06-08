use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use sqlx::PgPool;
use tokio::net::TcpListener;

use rustauth::{
    AppState, OAuthConfig, build_router,
    domain::{JwtManager, PasswordService},
    email::EmailClient,
};

const TEST_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIsgepUW6fIVvsGe3iwBb2mnhBFdIZ7zb+CfdLEo1pNB
-----END PRIVATE KEY-----";

const TEST_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADyia6fy2lW6Ezrs11/ZGt0axfBAfMSJu+rfdNbu62/Y=
-----END PUBLIC KEY-----";

async fn spawn_app(pool: PgPool) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
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
        oauth: Arc::new(OAuthConfig::default()),
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

fn extract_token(reset_link: &str) -> &str {
    reset_link.split("token=").nth(1).expect("token= in link")
}

/// Registration sends a verification email, so captured emails for an
/// account under test may contain both verification and reset-password
/// links. Finds the most recent link whose path matches `path_fragment`.
fn find_link(emails: &[(String, String)], path_fragment: &str) -> String {
    emails
        .iter()
        .rev()
        .find(|(_, link)| link.contains(path_fragment))
        .expect("expected a captured link matching the given path")
        .1
        .clone()
}

/// Registers a user, then verifies the email using the captured verification
/// link, so the account can subsequently log in.
async fn register_and_verify(
    base: &str,
    client: &reqwest::Client,
    captured: &Arc<Mutex<Vec<(String, String)>>>,
    email: &str,
    password: &str,
) {
    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": email, "password": password}))
        .send()
        .await
        .unwrap();

    let link = find_link(&captured.lock().unwrap(), "/verify-email");
    let token = extract_token(&link).to_string();

    let res = client
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

// --- /password-reset/request ---

#[sqlx::test]
async fn request_returns_200_for_registered_email(pool: PgPool) {
    let (base, _) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[sqlx::test]
async fn request_returns_200_for_unknown_email(pool: PgPool) {
    let (base, _) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "ghost@example.com"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[sqlx::test]
async fn request_sends_email_with_reset_link(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();

    // One email from registration (verification) and one from the reset request.
    let emails = captured.lock().unwrap();
    assert_eq!(emails.len(), 2);
    let (to, link) = emails
        .iter()
        .find(|(_, link)| link.contains("/reset-password"))
        .expect("reset email sent");
    assert_eq!(to, "alice@example.com");
    assert!(link.contains("token="));
}

#[sqlx::test]
async fn request_does_not_send_email_for_unknown_address(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;

    reqwest::Client::new()
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "ghost@example.com"}))
        .send()
        .await
        .unwrap();

    assert!(captured.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn request_with_invalid_email_returns_422(pool: PgPool) {
    let (base, _) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "notanemail"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

// --- /password-reset/confirm ---

#[sqlx::test]
async fn confirm_resets_password_and_allows_login_with_new(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "alice@example.com", "hunter2!").await;

    client
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();

    let link = find_link(&captured.lock().unwrap(), "/reset-password");
    let token = extract_token(&link).to_string();

    let res = client
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": token, "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let login = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "new_secret!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);

    let old_login = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(old_login.status(), 401);
}

#[sqlx::test]
async fn confirm_revokes_all_existing_sessions(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "alice@example.com", "hunter2!").await;

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    client
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();

    let link = find_link(&captured.lock().unwrap(), "/reset-password");
    let token = extract_token(&link).to_string();

    client
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": token, "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();

    let refresh = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": login["refresh_token"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(refresh.status(), 401);
}

#[sqlx::test]
async fn confirm_token_is_single_use(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/password-reset/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();

    let link = find_link(&captured.lock().unwrap(), "/reset-password");
    let token = extract_token(&link).to_string();

    client
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": token, "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();

    let replay = client
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": token, "new_password": "another_pass!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 400);
}

#[sqlx::test]
async fn confirm_with_bogus_token_returns_400(pool: PgPool) {
    let (base, _) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": "totally_fake_token", "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn confirm_with_empty_token_returns_422(pool: PgPool) {
    let (base, _) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": "", "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

#[sqlx::test]
async fn confirm_with_short_new_password_returns_422(pool: PgPool) {
    let (base, _) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/password-reset/confirm"))
        .json(&serde_json::json!({"token": "sometoken", "new_password": "short"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}
