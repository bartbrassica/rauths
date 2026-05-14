use std::{net::SocketAddr, sync::Arc};

use sqlx::PgPool;
use tokio::net::TcpListener;

use rustauth::{
    AppState, OAuthConfig, build_router,
    domain::{JwtManager, PasswordService},
    email::EmailClient,
};
use uuid::Uuid;

// Same test keys as in the jwt unit tests.
const TEST_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIsgepUW6fIVvsGe3iwBb2mnhBFdIZ7zb+CfdLEo1pNB
-----END PRIVATE KEY-----";

const TEST_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADyia6fy2lW6Ezrs11/ZGt0axfBAfMSJu+rfdNbu62/Y=
-----END PUBLIC KEY-----";

/// Builds the app with a test DB, connects to Redis, and binds to a random
/// port. Returns the base URL. The server runs for the lifetime of the test.
async fn spawn_app(pool: PgPool) -> String {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
    let redis = redis::Client::open(redis_url).expect("valid redis url");

    let jwt = Arc::new(
        JwtManager::from_ed25519_pem(TEST_PRIVATE_PEM, TEST_PUBLIC_PEM)
            .expect("valid test keypair"),
    );
    let passwords = Arc::new(PasswordService::for_testing());

    let (email, _) = EmailClient::capturing();
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

    format!("http://{addr}")
}

// --- /register ---

#[sqlx::test]
async fn register_returns_201_with_user_info(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["email"], "alice@example.com");
    assert!(body["id"].is_string());
}

#[sqlx::test]
async fn register_duplicate_email_returns_409(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let payload = serde_json::json!({"email": "alice@example.com", "password": "hunter2!"});

    client
        .post(format!("{base}/register"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let res = client
        .post(format!("{base}/register"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 409);
}

// --- /login ---

#[sqlx::test]
async fn login_with_valid_credentials_returns_tokens(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
}

#[sqlx::test]
async fn login_with_wrong_password_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "wrongpass"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn login_with_unknown_email_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "ghost@example.com", "password": "anything"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

// --- /me ---

#[sqlx::test]
async fn me_with_valid_access_token_returns_user(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let res = client
        .get(format!("{base}/me"))
        .bearer_auth(login["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["email"], "alice@example.com");
    assert!(body["id"].is_string());
}

#[sqlx::test]
async fn me_without_token_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .get(format!("{base}/me"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn me_rejects_refresh_token(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let res = client
        .get(format!("{base}/me"))
        .bearer_auth(login["refresh_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

// --- /refresh ---

#[sqlx::test]
async fn refresh_issues_new_tokens_and_revokes_old(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let old_refresh = login["refresh_token"].as_str().unwrap();

    let refreshed: serde_json::Value = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": old_refresh}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(refreshed["access_token"].is_string());
    assert_ne!(refreshed["refresh_token"], login["refresh_token"]);

    // Old refresh token must be revoked — replay must fail.
    let replay = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": old_refresh}))
        .send()
        .await
        .unwrap();

    assert_eq!(replay.status(), 401);
}

#[sqlx::test]
async fn refresh_rejects_access_token(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": login["access_token"]}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

// --- /logout ---

#[sqlx::test]
async fn logout_returns_204_and_revokes_refresh_token(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let refresh_token = login["refresh_token"].as_str().unwrap();

    let logout = client
        .post(format!("{base}/logout"))
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();

    assert_eq!(logout.status(), 204);

    // Revoked token must be rejected on next refresh attempt.
    let replay = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();

    assert_eq!(replay.status(), 401);
}

// --- /register input validation ---

#[sqlx::test]
async fn register_with_invalid_email_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let cases = [
        "notanemail",
        "@example.com",
        "user@nodot",
        "user@example.",
        "a@b@c.com",
    ];

    let client = reqwest::Client::new();
    for email in cases {
        let res = client
            .post(format!("{base}/register"))
            .json(&serde_json::json!({"email": email, "password": "password123"}))
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 422, "expected 422 for email={email:?}");
    }
}

#[sqlx::test]
async fn register_with_empty_password_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

#[sqlx::test]
async fn register_with_short_password_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "short"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

#[sqlx::test]
async fn register_with_password_over_128_chars_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;
    let long_password = "a".repeat(129);

    let res = reqwest::Client::new()
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": long_password}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

// --- /login input validation ---

#[sqlx::test]
async fn login_with_invalid_email_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let cases = ["notanemail", "@example.com", "user@nodot", "a@b@c.com"];

    let client = reqwest::Client::new();
    for email in cases {
        let res = client
            .post(format!("{base}/login"))
            .json(&serde_json::json!({"email": email, "password": "anypassword"}))
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 422, "expected 422 for email={email:?}");
    }
}

#[sqlx::test]
async fn login_with_empty_password_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

#[sqlx::test]
async fn login_with_password_over_128_chars_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;
    let long_password = "a".repeat(129);

    let res = reqwest::Client::new()
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": long_password}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

// --- /refresh input validation ---

#[sqlx::test]
async fn refresh_with_empty_token_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

// --- /logout input validation ---

#[sqlx::test]
async fn logout_with_empty_token_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/logout"))
        .json(&serde_json::json!({"refresh_token": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

// --- PATCH /me/password ---

async fn register_and_login(base: &str, client: &reqwest::Client) -> serde_json::Value {
    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[sqlx::test]
async fn change_password_returns_204_and_allows_login_with_new(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client).await;

    let res = client
        .patch(format!("{base}/me/password"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .json(&serde_json::json!({"current_password": "hunter2!", "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    let login_new = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "new_secret!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login_new.status(), 200);

    let login_old = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login_old.status(), 401);
}

#[sqlx::test]
async fn change_password_with_wrong_current_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client).await;

    let res = client
        .patch(format!("{base}/me/password"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .json(&serde_json::json!({"current_password": "wrongpassword", "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn change_password_without_token_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .patch(format!("{base}/me/password"))
        .json(&serde_json::json!({"current_password": "hunter2!", "new_password": "new_secret!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn change_password_with_short_new_password_returns_422(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client).await;

    let res = client
        .patch(format!("{base}/me/password"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .json(&serde_json::json!({"current_password": "hunter2!", "new_password": "short"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
}

// --- DELETE /me ---

#[sqlx::test]
async fn delete_me_returns_204_and_prevents_login(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client).await;

    let res = client
        .delete(format!("{base}/me"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    let login_after = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login_after.status(), 401);
}

#[sqlx::test]
async fn delete_me_without_token_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .delete(format!("{base}/me"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

// --- account lockout ---

#[sqlx::test]
async fn login_locked_after_10_failed_attempts(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    // Unique email avoids Redis lockout key collisions with concurrent tests.
    let email = format!("lockout-{}@example.com", Uuid::new_v4());

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": email, "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    for _ in 0..10 {
        client
            .post(format!("{base}/login"))
            .json(&serde_json::json!({"email": email, "password": "wrongpass"}))
            .send()
            .await
            .unwrap();
    }

    // 11th attempt — account must be locked even with the correct password.
    let res = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": email, "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn successful_login_resets_lockout_counter(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let email = format!("lockout-{}@example.com", Uuid::new_v4());

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": email, "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    // Fail 9 times (one under the limit).
    for _ in 0..9 {
        client
            .post(format!("{base}/login"))
            .json(&serde_json::json!({"email": email, "password": "wrongpass"}))
            .send()
            .await
            .unwrap();
    }

    // Succeed — counter must reset.
    let res = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": email, "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Fail 9 more times — should still not be locked (counter was reset).
    for _ in 0..9 {
        client
            .post(format!("{base}/login"))
            .json(&serde_json::json!({"email": email, "password": "wrongpass"}))
            .send()
            .await
            .unwrap();
    }

    let res = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": email, "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

// --- POST /me/sessions/revoke-all ---

#[sqlx::test]
async fn logout_all_revokes_all_sessions(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    // Login twice to create two sessions.
    let login1: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login2: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/me/sessions/revoke-all"))
        .bearer_auth(login1["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    // Both refresh tokens must now be rejected.
    let replay1 = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": login1["refresh_token"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(replay1.status(), 401);

    let replay2 = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": login2["refresh_token"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(replay2.status(), 401);
}

#[sqlx::test]
async fn logout_all_without_token_returns_401(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/me/sessions/revoke-all"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn logout_all_with_no_active_sessions_returns_204(pool: PgPool) {
    let base = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client).await;

    // Manually revoke the one session first.
    client
        .post(format!("{base}/logout"))
        .json(&serde_json::json!({"refresh_token": tokens["refresh_token"]}))
        .send()
        .await
        .unwrap();

    // revoke-all on an already-empty set must still succeed.
    let res = client
        .post(format!("{base}/me/sessions/revoke-all"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
}

// --- /health ---

#[sqlx::test]
async fn health_returns_200_when_db_and_redis_are_up(pool: PgPool) {
    let base = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["db"], "ok");
    assert_eq!(body["redis"], "ok");
}
