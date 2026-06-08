use std::{net::SocketAddr, sync::Arc};

use sqlx::PgPool;
use tokio::net::TcpListener;

use rauths::{
    AppState, OAuthConfig, build_router,
    domain::{JwtManager, PasswordService},
    email::{CapturedEmails, EmailClient},
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
async fn spawn_app(pool: PgPool) -> (String, CapturedEmails) {
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

fn extract_token(link: &str) -> &str {
    link.split("token=").nth(1).expect("token= in link")
}

/// Registers a user, then verifies the email using the token from the most
/// recently captured verification email addressed to it.
async fn register_and_verify(
    base: &str,
    client: &reqwest::Client,
    captured: &CapturedEmails,
    email: &str,
    password: &str,
) {
    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": email, "password": password}))
        .send()
        .await
        .unwrap();

    let link = {
        let emails = captured.lock().unwrap();
        emails
            .iter()
            .rev()
            .find(|(to, _)| to == email)
            .expect("verification email sent")
            .1
            .clone()
    };
    let token = extract_token(&link);

    let res = client
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

// --- /register ---

#[sqlx::test]
async fn register_returns_201_with_user_info(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;
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
    let (base, _captured) = spawn_app(pool).await;
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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "alice@example.com", "hunter2!").await;

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
async fn login_persists_audit_events_for_success_and_failure(pool: PgPool) {
    let (base, captured) = spawn_app(pool.clone()).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "alice@example.com", "hunter2!").await;

    client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "wrongpass"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let events = sqlx::query!(
        "SELECT user_id, event, reason, ip FROM audit_events \
         WHERE event IN ('login_failed', 'login_success') ORDER BY created_at"
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "login_failed");
    assert_eq!(events[0].reason.as_deref(), Some("invalid_password"));
    assert_eq!(events[1].event, "login_success");
    assert_eq!(events[1].reason, None);
    for e in &events {
        assert!(e.user_id.is_some());
        assert!(e.ip.is_some());
    }
}

#[sqlx::test]
async fn login_with_wrong_password_returns_401(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;
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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .get(format!("{base}/me"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn me_rejects_refresh_token(pool: PgPool) {
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

    let refresh_token = login["refresh_token"].as_str().unwrap();
    let access_token = login["access_token"].as_str().unwrap();

    let logout = client
        .post(format!("{base}/logout"))
        .bearer_auth(access_token)
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();

    assert_eq!(logout.status(), 204);

    // Revoked refresh token must be rejected on next refresh attempt.
    let replay = client
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();

    assert_eq!(replay.status(), 401);
}

#[sqlx::test]
async fn logout_revokes_the_access_token_used_to_authenticate(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "dave@example.com", "hunter2!").await;

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "dave@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let refresh_token = login["refresh_token"].as_str().unwrap();
    let access_token = login["access_token"].as_str().unwrap();

    // The access token works before logout.
    let me_before = client
        .get(format!("{base}/me"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(me_before.status(), 200);

    let logout = client
        .post(format!("{base}/logout"))
        .bearer_auth(access_token)
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 204);

    // The very same (still cryptographically valid, unexpired) access token
    // must now be rejected — it's been added to the revocation list.
    let me_after = client
        .get(format!("{base}/me"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(me_after.status(), 401);
}

// --- /register input validation ---

#[sqlx::test]
async fn register_with_invalid_email_returns_422(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;
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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;
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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "carol@example.com", "hunter2!").await;

    let login: serde_json::Value = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "carol@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/logout"))
        .bearer_auth(login["access_token"].as_str().unwrap())
        .json(&serde_json::json!({"refresh_token": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

// --- PATCH /me/password ---

async fn register_and_login(
    base: &str,
    client: &reqwest::Client,
    captured: &CapturedEmails,
) -> serde_json::Value {
    register_and_verify(base, client, captured, "alice@example.com", "hunter2!").await;
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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client, &captured).await;

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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client, &captured).await;

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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client, &captured).await;

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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client, &captured).await;

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
    let (base, _captured) = spawn_app(pool).await;

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
    let (base, _captured) = spawn_app(pool).await;
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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let email = format!("lockout-{}@example.com", Uuid::new_v4());

    register_and_verify(&base, &client, &captured, &email, "hunter2!").await;

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
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "alice@example.com", "hunter2!").await;

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
    let (base, _captured) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/me/sessions/revoke-all"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn logout_all_with_no_active_sessions_returns_204(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let tokens = register_and_login(&base, &client, &captured).await;

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
    let (base, _captured) = spawn_app(pool).await;

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

// --- /metrics ---

#[sqlx::test]
async fn metrics_exposes_request_and_auth_event_counters(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    // Trigger an HTTP request and a recorded auth event.
    client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "nobody@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let res = client.get(format!("{base}/metrics")).send().await.unwrap();

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("axum_http_requests_total"));
    assert!(body.contains(r#"auth_events_total{event="login_failed",reason="unknown_email"}"#));
}

// --- email verification ---

#[sqlx::test]
async fn register_sends_verification_email(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let emails = captured.lock().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].0, "alice@example.com");
    assert!(emails[0].1.contains("token="));
}

#[sqlx::test]
async fn login_with_unverified_email_returns_403(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;
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

    assert_eq!(res.status(), 403);
}

#[sqlx::test]
async fn login_with_wrong_password_on_unverified_account_returns_401_not_403(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    // Wrong password must fail with the generic 401 — the verification check
    // must not run (and so not leak) before the password is proven correct.
    let res = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "wrongpass"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

#[sqlx::test]
async fn confirm_verifies_email_and_allows_login(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let link = captured.lock().unwrap()[0].1.clone();
    let token = extract_token(&link);

    let confirm = client
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);

    let login = client
        .post(format!("{base}/login"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
}

#[sqlx::test]
async fn confirm_with_unknown_token_returns_400(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": "nonexistent"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

#[sqlx::test]
async fn confirm_with_already_used_token_returns_400(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let link = captured.lock().unwrap()[0].1.clone();
    let token = extract_token(&link);

    client
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();

    let replay = client
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": token}))
        .send()
        .await
        .unwrap();

    assert_eq!(replay.status(), 400);
}

#[sqlx::test]
async fn confirm_with_empty_token_returns_422(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/email-verify/confirm"))
        .json(&serde_json::json!({"token": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}

#[sqlx::test]
async fn verify_request_returns_200_and_resends_for_unverified_email(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({"email": "alice@example.com", "password": "hunter2!"}))
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!("{base}/email-verify/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // One email from registration, one from the resend request.
    assert_eq!(captured.lock().unwrap().len(), 2);
}

#[sqlx::test]
async fn verify_request_does_not_resend_for_already_verified_email(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;
    let client = reqwest::Client::new();

    register_and_verify(&base, &client, &captured, "alice@example.com", "hunter2!").await;
    assert_eq!(captured.lock().unwrap().len(), 1);

    let res = client
        .post(format!("{base}/email-verify/request"))
        .json(&serde_json::json!({"email": "alice@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Already verified — no second email should be sent.
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[sqlx::test]
async fn verify_request_returns_200_for_unknown_email(pool: PgPool) {
    let (base, captured) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/email-verify/request"))
        .json(&serde_json::json!({"email": "ghost@example.com"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert!(captured.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn verify_request_with_invalid_email_returns_422(pool: PgPool) {
    let (base, _captured) = spawn_app(pool).await;

    let res = reqwest::Client::new()
        .post(format!("{base}/email-verify/request"))
        .json(&serde_json::json!({"email": "notanemail"}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
}
