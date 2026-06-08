use std::sync::{Arc, Mutex};

use anyhow::Context;

pub struct EmailClient {
    inner: Inner,
}

enum Inner {
    Postmark {
        api_key: String,
        from_email: String,
        http: reqwest::Client,
    },
    Capture(Arc<Mutex<Vec<(String, String)>>>),
}

impl EmailClient {
    pub fn new(api_key: impl Into<String>, from_email: impl Into<String>) -> Self {
        Self {
            inner: Inner::Postmark {
                api_key: api_key.into(),
                from_email: from_email.into(),
                http: reqwest::Client::new(),
            },
        }
    }

    /// Returns a client that stores `(to, link)` pairs instead of sending them.
    /// Used in tests to inspect outgoing emails without a real Postmark account.
    pub fn capturing() -> (Self, Arc<Mutex<Vec<(String, String)>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inner: Inner::Capture(Arc::clone(&sent)),
            },
            sent,
        )
    }

    pub async fn send_password_reset(&self, to: &str, reset_link: &str) -> anyhow::Result<()> {
        match &self.inner {
            Inner::Postmark {
                api_key,
                from_email,
                http,
            } => {
                let body = serde_json::json!({
                    "From": from_email,
                    "To": to,
                    "Subject": "Reset your password",
                    "TextBody": format!(
                        "Use the link below to reset your password.\
                        \nIt expires in 15 minutes.\n\n{reset_link}"
                    ),
                    "MessageStream": "outbound",
                });

                let res = http
                    .post("https://api.postmarkapp.com/email")
                    .header("X-Postmark-Server-Token", api_key)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach Postmark")?;

                if !res.status().is_success() {
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    anyhow::bail!("Postmark returned {status}: {text}");
                }
                Ok(())
            }
            Inner::Capture(sent) => {
                sent.lock()
                    .unwrap()
                    .push((to.to_string(), reset_link.to_string()));
                Ok(())
            }
        }
    }

    pub async fn send_verification_email(&self, to: &str, verify_link: &str) -> anyhow::Result<()> {
        match &self.inner {
            Inner::Postmark {
                api_key,
                from_email,
                http,
            } => {
                let body = serde_json::json!({
                    "From": from_email,
                    "To": to,
                    "Subject": "Verify your email",
                    "TextBody": format!(
                        "Use the link below to verify your email address.\
                        \nIt expires in 15 minutes.\n\n{verify_link}"
                    ),
                    "MessageStream": "outbound",
                });

                let res = http
                    .post("https://api.postmarkapp.com/email")
                    .header("X-Postmark-Server-Token", api_key)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach Postmark")?;

                if !res.status().is_success() {
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    anyhow::bail!("Postmark returned {status}: {text}");
                }
                Ok(())
            }
            Inner::Capture(sent) => {
                sent.lock()
                    .unwrap()
                    .push((to.to_string(), verify_link.to_string()));
                Ok(())
            }
        }
    }
}
