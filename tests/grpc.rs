use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::Server as TonicServer;
use tonic::transport::server::TcpIncoming;
use uuid::Uuid;

use rustauth::{
    domain::JwtManager,
    services::{AuthServiceClient, AuthServiceImpl, AuthServiceServer, VerifyTokenRequest},
};

const TEST_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIsgepUW6fIVvsGe3iwBb2mnhBFdIZ7zb+CfdLEo1pNB
-----END PRIVATE KEY-----";

const TEST_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADyia6fy2lW6Ezrs11/ZGt0axfBAfMSJu+rfdNbu62/Y=
-----END PUBLIC KEY-----";

async fn spawn_grpc(jwt: Arc<JwtManager>) -> AuthServiceClient<tonic::transport::Channel> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpIncoming::from_listener(listener, true, None).unwrap();

    tokio::spawn(async move {
        TonicServer::builder()
            .add_service(AuthServiceServer::new(AuthServiceImpl::new(jwt)))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    AuthServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

fn test_jwt() -> Arc<JwtManager> {
    Arc::new(
        JwtManager::from_ed25519_pem(TEST_PRIVATE_PEM, TEST_PUBLIC_PEM)
            .expect("valid test keypair"),
    )
}

// --- VerifyToken ---

#[tokio::test]
async fn verify_valid_access_token_returns_valid_with_claims() {
    let jwt = test_jwt();
    let user_id = Uuid::new_v4();
    let token = jwt
        .sign_access_token(user_id, "alice@example.com", &[])
        .unwrap();

    let mut client = spawn_grpc(jwt).await;
    let resp = client
        .verify_token(VerifyTokenRequest { token })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.valid);
    assert_eq!(resp.user_id, user_id.to_string());
    assert_eq!(resp.email, "alice@example.com");
    assert!(resp.roles.is_empty());
}

#[tokio::test]
async fn verify_token_returns_roles_from_claims() {
    let jwt = test_jwt();
    let user_id = Uuid::new_v4();
    let roles = vec!["admin".to_string(), "editor".to_string()];
    let token = jwt
        .sign_access_token(user_id, "alice@example.com", &roles)
        .unwrap();

    let mut client = spawn_grpc(jwt).await;
    let resp = client
        .verify_token(VerifyTokenRequest { token })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.valid);
    assert_eq!(resp.roles, roles);
}

#[tokio::test]
async fn verify_refresh_token_returns_invalid() {
    let jwt = test_jwt();
    let (token, _) = jwt
        .sign_refresh_token(Uuid::new_v4(), "alice@example.com")
        .unwrap();

    let mut client = spawn_grpc(jwt).await;
    let resp = client
        .verify_token(VerifyTokenRequest { token })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.valid);
    assert!(resp.user_id.is_empty());
    assert!(resp.email.is_empty());
}

#[tokio::test]
async fn verify_tampered_token_returns_invalid() {
    let jwt = test_jwt();
    let mut token = jwt
        .sign_access_token(Uuid::new_v4(), "eve@example.com", &[])
        .unwrap();
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });

    let mut client = spawn_grpc(jwt).await;
    let resp = client
        .verify_token(VerifyTokenRequest { token })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.valid);
}

#[tokio::test]
async fn verify_junk_string_returns_invalid() {
    let mut client = spawn_grpc(test_jwt()).await;
    let resp = client
        .verify_token(VerifyTokenRequest {
            token: "not.a.jwt".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.valid);
}

#[tokio::test]
async fn verify_empty_token_returns_invalid() {
    let mut client = spawn_grpc(test_jwt()).await;
    let resp = client
        .verify_token(VerifyTokenRequest {
            token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.valid);
}
