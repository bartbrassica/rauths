use std::{net::SocketAddr, sync::Arc};

use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server as TonicServer;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use rustauth::{
    AppState, OAuthConfig, build_production_router,
    domain::{JwtManager, PasswordService},
    email::EmailClient,
    services::{AuthServiceImpl, AuthServiceServer},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    let fmt_layer = if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt::layer().json().boxed()
    } else {
        tracing_subscriber::fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rustauth=debug,tower_http=debug".into()),
        )
        .with(fmt_layer)
        .init();

    let database_url = std::env::var("DATABASE_URL")?;
    let redis_url = std::env::var("REDIS_URL")?;
    let jwt_private_pem = std::env::var("JWT_PRIVATE_KEY_PEM")?;
    let jwt_public_pem = std::env::var("JWT_PUBLIC_KEY_PEM")?;
    let postmark_api_key = std::env::var("POSTMARK_API_KEY")?;
    let postmark_from_email = std::env::var("POSTMARK_FROM_EMAIL")?;
    let app_base_url = std::env::var("APP_BASE_URL")?;
    let http_addr = std::env::var("HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let grpc_addr: SocketAddr = std::env::var("GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    sqlx::migrate!().run(&pool).await?;
    tracing::info!("migrations applied");

    let redis = redis::Client::open(redis_url)?;

    let jwt = Arc::new(JwtManager::from_ed25519_pem(
        jwt_private_pem.as_bytes(),
        jwt_public_pem.as_bytes(),
    )?);

    let passwords = Arc::new(PasswordService::new());
    let email = Arc::new(EmailClient::new(postmark_api_key, postmark_from_email));

    let oauth = Arc::new(OAuthConfig {
        github_client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
        github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").ok(),
        google_client_id: std::env::var("GOOGLE_CLIENT_ID").ok(),
        google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").ok(),
    });

    let state = AppState {
        pool,
        jwt,
        passwords,
        redis,
        email,
        app_base_url,
        oauth,
        http: reqwest::Client::new(),
    };

    let app = build_production_router(state.clone());

    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    tracing::info!("HTTP listening on {http_addr}");
    tracing::info!("gRPC listening on {grpc_addr}");

    let grpc = TonicServer::builder()
        .add_service(AuthServiceServer::new(AuthServiceImpl::new(state.jwt)))
        .serve(grpc_addr);

    tokio::try_join!(
        async {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(anyhow::Error::from)
        },
        async { grpc.await.map_err(anyhow::Error::from) },
    )?;

    Ok(())
}
