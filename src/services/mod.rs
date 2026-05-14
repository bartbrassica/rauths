use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::domain::JwtManager;

tonic::include_proto!("auth");

pub use auth_service_client::AuthServiceClient;
pub use auth_service_server::AuthServiceServer;

use auth_service_server::AuthService;

pub struct AuthServiceImpl {
    jwt: Arc<JwtManager>,
}

impl AuthServiceImpl {
    pub fn new(jwt: Arc<JwtManager>) -> Self {
        Self { jwt }
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn verify_token(
        &self,
        request: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        let token = &request.into_inner().token;
        match self.jwt.verify_access(token) {
            Ok(claims) => Ok(Response::new(VerifyTokenResponse {
                valid: true,
                user_id: claims.sub.to_string(),
                email: claims.email,
                roles: claims.roles,
            })),
            Err(_) => Ok(Response::new(VerifyTokenResponse {
                valid: false,
                user_id: String::new(),
                email: String::new(),
                roles: vec![],
            })),
        }
    }
}
