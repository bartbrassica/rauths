use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::data::error::DataError;

pub struct EmailVerificationTokenRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> EmailVerificationTokenRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DataError> {
        sqlx::query!(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) \
             VALUES ($1, $2, $3)",
            user_id,
            token_hash,
            expires_at,
        )
        .execute(self.pool)
        .await
        .map(|_| ())
        .map_err(DataError::from_sqlx)
    }

    /// Atomically marks the token as used and returns the associated `user_id`.
    /// Returns `None` if the token is not found, already used, or expired.
    pub async fn consume(&self, token_hash: &str) -> Result<Option<Uuid>, DataError> {
        let row = sqlx::query!(
            r#"
            UPDATE email_verification_tokens
            SET    used_at = NOW()
            WHERE  token_hash = $1
              AND  used_at    IS NULL
              AND  expires_at  > NOW()
            RETURNING user_id
            "#,
            token_hash,
        )
        .fetch_optional(self.pool)
        .await
        .map_err(DataError::from_sqlx)?;

        Ok(row.map(|r| r.user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::user_repository::UserRepository;

    #[sqlx::test]
    async fn create_and_consume_returns_user_id(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();

        let repo = EmailVerificationTokenRepository::new(&pool);
        let expires_at = Utc::now() + chrono::Duration::seconds(900);
        repo.create(user.id, "testhash", expires_at).await.unwrap();

        let uid = repo
            .consume("testhash")
            .await
            .unwrap()
            .expect("should find token");
        assert_eq!(uid, user.id);
    }

    #[sqlx::test]
    async fn consume_returns_none_on_second_use(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();

        let repo = EmailVerificationTokenRepository::new(&pool);
        let expires_at = Utc::now() + chrono::Duration::seconds(900);
        repo.create(user.id, "testhash", expires_at).await.unwrap();
        repo.consume("testhash").await.unwrap();

        let second = repo.consume("testhash").await.unwrap();
        assert!(second.is_none());
    }

    #[sqlx::test]
    async fn consume_returns_none_for_expired_token(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();

        let repo = EmailVerificationTokenRepository::new(&pool);
        let expires_at = Utc::now() - chrono::Duration::seconds(1);
        repo.create(user.id, "expiredhash", expires_at)
            .await
            .unwrap();

        let result = repo.consume("expiredhash").await.unwrap();
        assert!(result.is_none());
    }

    #[sqlx::test]
    async fn consume_returns_none_for_unknown_token(pool: PgPool) {
        let result = EmailVerificationTokenRepository::new(&pool)
            .consume("nonexistent")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
