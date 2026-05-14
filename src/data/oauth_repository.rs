use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::error::DataError;

#[derive(Debug, Clone)]
pub struct OAuthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: DateTime<Utc>,
}

pub struct OAuthRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> OAuthRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_account(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, DataError> {
        sqlx::query_as!(
            OAuthAccount,
            "SELECT * FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
            provider,
            provider_user_id,
        )
        .fetch_optional(self.pool)
        .await
        .map_err(DataError::from_sqlx)
    }

    pub async fn create_account(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<(), DataError> {
        sqlx::query!(
            "INSERT INTO oauth_accounts (user_id, provider, provider_user_id) VALUES ($1, $2, $3)",
            user_id,
            provider,
            provider_user_id,
        )
        .execute(self.pool)
        .await
        .map_err(DataError::from_sqlx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn create_and_find_account(pool: PgPool) {
        let user = sqlx::query_as!(
            crate::data::User,
            "INSERT INTO users (email) VALUES ($1) RETURNING *",
            "oauth@example.com",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let repo = OAuthRepository::new(&pool);
        repo.create_account(user.id, "github", "gh_123")
            .await
            .unwrap();

        let found = repo
            .find_account("github", "gh_123")
            .await
            .unwrap()
            .expect("account should exist");

        assert_eq!(found.user_id, user.id);
        assert_eq!(found.provider, "github");
        assert_eq!(found.provider_user_id, "gh_123");
    }

    #[sqlx::test]
    async fn find_account_returns_none_for_unknown(pool: PgPool) {
        let repo = OAuthRepository::new(&pool);
        let result = repo.find_account("github", "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[sqlx::test]
    async fn different_providers_are_distinct(pool: PgPool) {
        let user = sqlx::query_as!(
            crate::data::User,
            "INSERT INTO users (email) VALUES ($1) RETURNING *",
            "multi@example.com",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let repo = OAuthRepository::new(&pool);
        repo.create_account(user.id, "github", "user_42")
            .await
            .unwrap();
        repo.create_account(user.id, "google", "user_42")
            .await
            .unwrap();

        assert!(
            repo.find_account("github", "user_42")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repo.find_account("google", "user_42")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repo.find_account("twitter", "user_42")
                .await
                .unwrap()
                .is_none()
        );
    }
}
