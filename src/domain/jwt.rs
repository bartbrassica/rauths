use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::error::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Access,
    Refresh,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — user UUID.
    pub sub: Uuid,
    pub email: String,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// Unique token ID — used for refresh-token revocation in Redis.
    pub jti: Uuid,
    /// Distinguishes access tokens from refresh tokens.
    pub kind: TokenKind,
    pub roles: Vec<String>,
}

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl JwtManager {
    pub fn from_ed25519_pem(private_pem: &[u8], public_pem: &[u8]) -> Result<Self, DomainError> {
        Ok(Self {
            encoding_key: EncodingKey::from_ed_pem(private_pem)?,
            decoding_key: DecodingKey::from_ed_pem(public_pem)?,
            access_ttl: Duration::minutes(15),
            refresh_ttl: Duration::days(7),
        })
    }

    pub fn sign_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        roles: &[String],
    ) -> Result<String, DomainError> {
        let (token, _) =
            self.sign_with_claims(user_id, email, roles, self.access_ttl, TokenKind::Access)?;
        Ok(token)
    }

    /// Returns `(token, jti)` so the caller can store the JTI in Redis without re-decoding.
    pub fn sign_refresh_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<(String, Uuid), DomainError> {
        let (token, claims) =
            self.sign_with_claims(user_id, email, &[], self.refresh_ttl, TokenKind::Refresh)?;
        Ok((token, claims.jti))
    }

    pub fn verify_access(&self, token: &str) -> Result<Claims, DomainError> {
        self.decode_and_check(token, TokenKind::Access)
    }

    pub fn verify_refresh(&self, token: &str) -> Result<Claims, DomainError> {
        self.decode_and_check(token, TokenKind::Refresh)
    }

    fn decode_and_check(&self, token: &str, expected: TokenKind) -> Result<Claims, DomainError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = true;
        let claims = decode::<Claims>(token, &self.decoding_key, &validation)?.claims;
        if claims.kind != expected {
            return Err(DomainError::WrongTokenKind);
        }
        Ok(claims)
    }

    fn sign_with_claims(
        &self,
        user_id: Uuid,
        email: &str,
        roles: &[String],
        ttl: Duration,
        kind: TokenKind,
    ) -> Result<(String, Claims), DomainError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            email: email.to_owned(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            jti: Uuid::new_v4(),
            kind,
            roles: roles.to_vec(),
        };
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding_key)?;
        Ok((token, claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIsgepUW6fIVvsGe3iwBb2mnhBFdIZ7zb+CfdLEo1pNB
-----END PRIVATE KEY-----";

    const TEST_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADyia6fy2lW6Ezrs11/ZGt0axfBAfMSJu+rfdNbu62/Y=
-----END PUBLIC KEY-----";

    fn manager() -> JwtManager {
        JwtManager::from_ed25519_pem(TEST_PRIVATE_PEM, TEST_PUBLIC_PEM).unwrap()
    }

    #[test]
    fn access_token_roundtrip() {
        let mgr = manager();
        let user_id = Uuid::new_v4();
        let roles = vec!["admin".to_string(), "editor".to_string()];
        let token = mgr
            .sign_access_token(user_id, "alice@example.com", &roles)
            .unwrap();
        let claims = mgr.verify_access(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.kind, TokenKind::Access);
        assert_eq!(claims.roles, roles);
    }

    #[test]
    fn access_token_with_no_roles() {
        let mgr = manager();
        let token = mgr
            .sign_access_token(Uuid::new_v4(), "alice@example.com", &[])
            .unwrap();
        let claims = mgr.verify_access(&token).unwrap();
        assert!(claims.roles.is_empty());
    }

    #[test]
    fn refresh_token_roundtrip() {
        let mgr = manager();
        let user_id = Uuid::new_v4();
        let (token, jti) = mgr.sign_refresh_token(user_id, "bob@example.com").unwrap();
        let claims = mgr.verify_refresh(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.kind, TokenKind::Refresh);
    }

    #[test]
    fn access_token_rejected_as_refresh() {
        let mgr = manager();
        let token = mgr
            .sign_access_token(Uuid::new_v4(), "alice@example.com", &[])
            .unwrap();
        assert!(matches!(
            mgr.verify_refresh(&token),
            Err(DomainError::WrongTokenKind)
        ));
    }

    #[test]
    fn refresh_token_rejected_as_access() {
        let mgr = manager();
        let (token, _) = mgr
            .sign_refresh_token(Uuid::new_v4(), "bob@example.com")
            .unwrap();
        assert!(matches!(
            mgr.verify_access(&token),
            Err(DomainError::WrongTokenKind)
        ));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let mgr = manager();
        let user_id = Uuid::new_v4();
        let mut token = mgr
            .sign_access_token(user_id, "eve@example.com", &[])
            .unwrap();
        let last = token.pop().unwrap();
        token.push(if last == 'A' { 'B' } else { 'A' });
        assert!(mgr.verify_access(&token).is_err());
    }

    #[test]
    fn each_token_has_unique_jti() {
        let mgr = manager();
        let user_id = Uuid::new_v4();
        let t1 = mgr
            .sign_access_token(user_id, "x@example.com", &[])
            .unwrap();
        let t2 = mgr
            .sign_access_token(user_id, "x@example.com", &[])
            .unwrap();
        let c1 = mgr.verify_access(&t1).unwrap();
        let c2 = mgr.verify_access(&t2).unwrap();
        assert_ne!(c1.jti, c2.jti);
    }
}
