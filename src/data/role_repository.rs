use sqlx::PgPool;
use uuid::Uuid;

use crate::data::error::DataError;

pub struct RoleRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> RoleRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<String>, DataError> {
        let rows = sqlx::query!(
            "SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role",
            user_id
        )
        .fetch_all(self.pool)
        .await
        .map_err(DataError::from_sqlx)?;
        Ok(rows.into_iter().map(|r| r.role).collect())
    }

    pub async fn assign(&self, user_id: Uuid, role: &str) -> Result<(), DataError> {
        sqlx::query!(
            "INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            user_id,
            role,
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
    use crate::data::UserRepository;

    #[sqlx::test]
    async fn list_for_user_returns_empty_for_new_user(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();
        let roles = RoleRepository::new(&pool)
            .list_for_user(user.id)
            .await
            .unwrap();
        assert!(roles.is_empty());
    }

    #[sqlx::test]
    async fn assign_and_list_roles(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();
        let repo = RoleRepository::new(&pool);
        repo.assign(user.id, "admin").await.unwrap();
        repo.assign(user.id, "editor").await.unwrap();

        let roles = repo.list_for_user(user.id).await.unwrap();
        assert_eq!(roles, vec!["admin", "editor"]);
    }

    #[sqlx::test]
    async fn assign_is_idempotent(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();
        let repo = RoleRepository::new(&pool);
        repo.assign(user.id, "admin").await.unwrap();
        repo.assign(user.id, "admin").await.unwrap();

        let roles = repo.list_for_user(user.id).await.unwrap();
        assert_eq!(roles, vec!["admin"]);
    }

    #[sqlx::test]
    async fn roles_are_deleted_with_user(pool: PgPool) {
        let user_repo = UserRepository::new(&pool);
        let user = user_repo.create("alice@example.com", "hash").await.unwrap();
        RoleRepository::new(&pool)
            .assign(user.id, "admin")
            .await
            .unwrap();
        user_repo.delete(user.id).await.unwrap();

        let roles = RoleRepository::new(&pool)
            .list_for_user(user.id)
            .await
            .unwrap();
        assert!(roles.is_empty());
    }
}
