use redis::{AsyncCommands, Client};
use uuid::Uuid;

use super::error::DataError;

pub struct TokenStore<'a> {
    client: &'a Client,
}

impl<'a> TokenStore<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn store_refresh_token(
        &self,
        jti: Uuid,
        user_id: Uuid,
        ttl_secs: u64,
    ) -> Result<(), DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let jti_key = format!("refresh:{jti}");
        let sessions_key = format!("sessions:{user_id}");
        redis::pipe()
            .set_ex(&jti_key, user_id.to_string(), ttl_secs)
            .sadd(&sessions_key, jti.to_string())
            .expire(&sessions_key, ttl_secs as i64)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn revoke_refresh_token(&self, jti: Uuid) -> Result<Option<Uuid>, DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let jti_key = format!("refresh:{jti}");
        let val: Option<String> = conn.get_del(&jti_key).await?;
        if let Some(ref uid_str) = val
            && let Ok(user_id) = uid_str.parse::<Uuid>()
        {
            let sessions_key = format!("sessions:{user_id}");
            let _: () = conn.srem(sessions_key, jti.to_string()).await?;
        }
        Ok(val.and_then(|s| s.parse().ok()))
    }

    /// Adds an access token's `jti` to the revocation list for the remainder of its lifetime,
    /// so a stolen access token can't be used after logout even though it's still unexpired.
    pub async fn revoke_access_token(&self, jti: Uuid, ttl_secs: u64) -> Result<(), DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("revoked_access:{jti}");
        let _: () = conn.set_ex(key, "1", ttl_secs).await?;
        Ok(())
    }

    /// Returns true if the given access token `jti` has been revoked.
    pub async fn is_access_token_revoked(&self, jti: Uuid) -> Result<bool, DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("revoked_access:{jti}");
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }

    pub async fn store_oauth_state(
        &self,
        state: &str,
        provider: &str,
        code_verifier: &str,
    ) -> Result<(), DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let state_key = format!("oauth_state:{state}");
        let pkce_key = format!("oauth_pkce:{state}");
        redis::pipe()
            .set_ex(&state_key, provider, 600u64)
            .set_ex(&pkce_key, code_verifier, 600u64)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Atomically retrieves and deletes an OAuth state token and its PKCE code verifier.
    /// Returns `(provider, code_verifier)`, or None if the state is unknown or expired.
    pub async fn consume_oauth_state(
        &self,
        state: &str,
    ) -> Result<Option<(String, String)>, DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let state_key = format!("oauth_state:{state}");
        let pkce_key = format!("oauth_pkce:{state}");
        let (provider, code_verifier): (Option<String>, Option<String>) = redis::pipe()
            .get_del(&state_key)
            .get_del(&pkce_key)
            .query_async(&mut conn)
            .await?;
        Ok(provider.zip(code_verifier))
    }

    /// Revokes all active sessions for a user. Returns the number of sessions found in the index.
    pub async fn revoke_all_sessions(&self, user_id: Uuid) -> Result<usize, DataError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let sessions_key = format!("sessions:{user_id}");
        let jtis: Vec<String> = conn.smembers(&sessions_key).await?;
        let count = jtis.len();
        if count == 0 {
            return Ok(0);
        }
        let mut p = redis::pipe();
        for jti_str in &jtis {
            p.del(format!("refresh:{jti_str}"));
        }
        p.del(&sessions_key);
        p.query_async::<()>(&mut conn).await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> Client {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
        Client::open(url).expect("test redis url")
    }

    #[tokio::test]
    async fn store_creates_jti_key_and_sessions_set() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let jti = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        store.store_refresh_token(jti, user_id, 60).await.unwrap();

        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let stored_uid: Option<String> = conn.get(format!("refresh:{jti}")).await.unwrap();
        assert_eq!(stored_uid, Some(user_id.to_string()));
        let is_member: bool = conn
            .sismember(format!("sessions:{user_id}"), jti.to_string())
            .await
            .unwrap();
        assert!(is_member);

        let _: () = conn.del(format!("refresh:{jti}")).await.unwrap();
        let _: () = conn.del(format!("sessions:{user_id}")).await.unwrap();
    }

    #[tokio::test]
    async fn revoke_removes_jti_key_and_sessions_membership() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let jti = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        store.store_refresh_token(jti, user_id, 60).await.unwrap();
        let revoked = store.revoke_refresh_token(jti).await.unwrap();

        assert_eq!(revoked, Some(user_id));

        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let stored: Option<String> = conn.get(format!("refresh:{jti}")).await.unwrap();
        assert!(stored.is_none());
        let is_member: bool = conn
            .sismember(format!("sessions:{user_id}"), jti.to_string())
            .await
            .unwrap();
        assert!(!is_member);

        let _: () = conn.del(format!("sessions:{user_id}")).await.unwrap();
    }

    #[tokio::test]
    async fn revoke_unknown_jti_returns_none() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let result = store.revoke_refresh_token(Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn revoke_all_removes_all_jti_keys_and_sessions_set() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let user_id = Uuid::new_v4();
        let jti1 = Uuid::new_v4();
        let jti2 = Uuid::new_v4();

        store.store_refresh_token(jti1, user_id, 60).await.unwrap();
        store.store_refresh_token(jti2, user_id, 60).await.unwrap();

        let count = store.revoke_all_sessions(user_id).await.unwrap();
        assert_eq!(count, 2);

        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let k1: Option<String> = conn.get(format!("refresh:{jti1}")).await.unwrap();
        let k2: Option<String> = conn.get(format!("refresh:{jti2}")).await.unwrap();
        assert!(k1.is_none());
        assert!(k2.is_none());
        let set_exists: bool = conn.exists(format!("sessions:{user_id}")).await.unwrap();
        assert!(!set_exists);
    }

    #[tokio::test]
    async fn revoke_all_with_no_sessions_returns_zero() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let count = store.revoke_all_sessions(Uuid::new_v4()).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn access_token_is_not_revoked_by_default() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let revoked = store.is_access_token_revoked(Uuid::new_v4()).await.unwrap();
        assert!(!revoked);
    }

    #[tokio::test]
    async fn revoked_access_token_is_reported_as_revoked() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let jti = Uuid::new_v4();

        store.revoke_access_token(jti, 60).await.unwrap();

        assert!(store.is_access_token_revoked(jti).await.unwrap());

        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: () = conn.del(format!("revoked_access:{jti}")).await.unwrap();
    }

    #[tokio::test]
    async fn oauth_state_is_stored_and_consumed() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let state_token = Uuid::new_v4().to_string();

        store
            .store_oauth_state(&state_token, "github", "test-verifier")
            .await
            .unwrap();

        let entry = store.consume_oauth_state(&state_token).await.unwrap();
        assert_eq!(
            entry,
            Some(("github".to_string(), "test-verifier".to_string()))
        );

        let second_consume = store.consume_oauth_state(&state_token).await.unwrap();
        assert!(second_consume.is_none(), "state must be one-time-use");
    }

    #[tokio::test]
    async fn consume_unknown_oauth_state_returns_none() {
        let client = test_client();
        let store = TokenStore::new(&client);
        let result = store
            .consume_oauth_state(&Uuid::new_v4().to_string())
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
