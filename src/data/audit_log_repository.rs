use sqlx::PgPool;
use uuid::Uuid;

use crate::data::error::DataError;

pub struct AuditLogRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> AuditLogRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn record(
        &self,
        user_id: Option<Uuid>,
        event: &str,
        reason: Option<&str>,
        ip: &str,
    ) -> Result<(), DataError> {
        sqlx::query!(
            "INSERT INTO audit_events (user_id, event, reason, ip) VALUES ($1, $2, $3, $4)",
            user_id,
            event,
            reason,
            ip,
        )
        .execute(self.pool)
        .await
        .map(|_| ())
        .map_err(DataError::from_sqlx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::user_repository::UserRepository;

    #[sqlx::test]
    async fn record_persists_event_with_user_and_reason(pool: PgPool) {
        let user = UserRepository::new(&pool)
            .create("alice@example.com", "hash")
            .await
            .unwrap();

        AuditLogRepository::new(&pool)
            .record(
                Some(user.id),
                "login_failed",
                Some("invalid_password"),
                "127.0.0.1",
            )
            .await
            .unwrap();

        let row = sqlx::query!("SELECT user_id, event, reason, ip FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.user_id, Some(user.id));
        assert_eq!(row.event, "login_failed");
        assert_eq!(row.reason.as_deref(), Some("invalid_password"));
        assert_eq!(row.ip.as_deref(), Some("127.0.0.1"));
    }

    #[sqlx::test]
    async fn record_persists_event_without_user_or_reason(pool: PgPool) {
        AuditLogRepository::new(&pool)
            .record(None, "login_failed", None, "10.0.0.1")
            .await
            .unwrap();

        let row = sqlx::query!("SELECT user_id, event, reason, ip FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.user_id, None);
        assert_eq!(row.event, "login_failed");
        assert_eq!(row.reason, None);
        assert_eq!(row.ip.as_deref(), Some("10.0.0.1"));
    }
}
