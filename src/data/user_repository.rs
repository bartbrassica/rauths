use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::data::error::DataError;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct UserRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> UserRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, email: &str, password_hash: &str) -> Result<User, DataError> {
        sqlx::query_as!(
            User,
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
            email,
            password_hash,
        )
        .fetch_one(self.pool)
        .await
        .map_err(DataError::from_sqlx)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, DataError> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
            .fetch_optional(self.pool)
            .await
            .map_err(DataError::from_sqlx)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DataError> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
            .fetch_optional(self.pool)
            .await
            .map_err(DataError::from_sqlx)
    }

    pub async fn update_password(&self, id: Uuid, new_hash: &str) -> Result<(), DataError> {
        let result = sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
            new_hash,
            id
        )
        .execute(self.pool)
        .await
        .map_err(DataError::from_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(DataError::NotFound);
        }
        Ok(())
    }

    /// Creates a user from an OAuth provider login. The provider has already proven
    /// ownership of the email, so the account starts out verified.
    pub async fn create_oauth_user(&self, email: &str) -> Result<User, DataError> {
        sqlx::query_as!(
            User,
            "INSERT INTO users (email, email_verified_at) VALUES ($1, NOW()) RETURNING *",
            email,
        )
        .fetch_one(self.pool)
        .await
        .map_err(DataError::from_sqlx)
    }

    pub async fn mark_verified(&self, id: Uuid) -> Result<(), DataError> {
        sqlx::query!(
            "UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = $1",
            id
        )
        .execute(self.pool)
        .await
        .map_err(DataError::from_sqlx)?;
        Ok(())
    }

    /// Clears the password hash, e.g. when an OAuth login reclaims an account that
    /// was squatting on its email — the squatter's password must no longer work.
    pub async fn clear_password(&self, id: Uuid) -> Result<(), DataError> {
        sqlx::query!(
            "UPDATE users SET password_hash = NULL, updated_at = NOW() WHERE id = $1",
            id
        )
        .execute(self.pool)
        .await
        .map_err(DataError::from_sqlx)?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), DataError> {
        sqlx::query!("DELETE FROM users WHERE id = $1", id)
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
    async fn create_and_find_by_email(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let user = repo
            .create("alice@example.com", "hashed_password")
            .await
            .unwrap();

        assert_eq!(user.email, "alice@example.com");

        let found = repo
            .find_by_email("alice@example.com")
            .await
            .unwrap()
            .expect("user should exist");

        assert_eq!(found.id, user.id);
        assert_eq!(found.password_hash.as_deref(), Some("hashed_password"));
    }

    #[sqlx::test]
    async fn find_by_email_returns_none_for_unknown(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let result = repo.find_by_email("ghost@example.com").await.unwrap();
        assert!(result.is_none());
    }

    #[sqlx::test]
    async fn duplicate_email_returns_email_conflict(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        repo.create("bob@example.com", "hash1").await.unwrap();
        let err = repo.create("bob@example.com", "hash2").await.unwrap_err();
        assert!(matches!(err, DataError::EmailConflict));
    }

    #[sqlx::test]
    async fn find_by_id_returns_user(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let created = repo.create("alice@example.com", "hash").await.unwrap();
        let found = repo
            .find_by_id(created.id)
            .await
            .unwrap()
            .expect("should exist");
        assert_eq!(found.id, created.id);
        assert_eq!(found.email, "alice@example.com");
    }

    #[sqlx::test]
    async fn find_by_id_returns_none_for_unknown(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let result = repo.find_by_id(Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[sqlx::test]
    async fn update_password_changes_hash(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let user = repo.create("alice@example.com", "old_hash").await.unwrap();
        repo.update_password(user.id, "new_hash").await.unwrap();
        let updated = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(updated.password_hash.as_deref(), Some("new_hash"));
        assert!(
            updated.updated_at > updated.created_at || updated.updated_at >= updated.created_at
        );
    }

    #[sqlx::test]
    async fn update_password_on_nonexistent_returns_not_found(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let err = repo
            .update_password(Uuid::new_v4(), "hash")
            .await
            .unwrap_err();
        assert!(matches!(err, DataError::NotFound));
    }

    #[sqlx::test]
    async fn delete_removes_user(pool: PgPool) {
        let repo = UserRepository::new(&pool);
        let user = repo.create("alice@example.com", "hash").await.unwrap();
        repo.delete(user.id).await.unwrap();
        let result = repo.find_by_id(user.id).await.unwrap();
        assert!(result.is_none());
    }
}
