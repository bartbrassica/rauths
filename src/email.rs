use std::sync::{Arc, Mutex};

use anyhow::Context;

pub struct EmailClient {
    inner: Inner,
}

/// `(to, link)` pairs captured instead of being sent, for use in tests.
pub type CapturedEmails = Arc<Mutex<Vec<(String, String)>>>;

enum Inner {
    Resend {
        api_key: String,
        from_email: String,
        http: reqwest::Client,
    },
    Capture(CapturedEmails),
}

impl EmailClient {
    pub fn new(api_key: impl Into<String>, from_email: impl Into<String>) -> Self {
        Self {
            inner: Inner::Resend {
                api_key: api_key.into(),
                from_email: from_email.into(),
                http: reqwest::Client::new(),
            },
        }
    }

    /// Returns a client that stores `(to, link)` pairs instead of sending them.
    /// Used in tests to inspect outgoing emails without a real Resend account.
    pub fn capturing() -> (Self, CapturedEmails) {
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
            Inner::Resend {
                api_key,
                from_email,
                http,
            } => {
                let body = serde_json::json!({
                    "from": from_email,
                    "to": to,
                    "subject": "Reset your password",
                    "text": format!(
                        "Use the link below to reset your password.\
                        \nIt expires in 15 minutes.\n\n{reset_link}"
                    ),
                });

                let res = http
                    .post("https://api.resend.com/emails")
                    .bearer_auth(api_key)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach Resend")?;

                if !res.status().is_success() {
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    anyhow::bail!("Resend returned {status}: {text}");
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
            Inner::Resend {
                api_key,
                from_email,
                http,
            } => {
                let body = serde_json::json!({
                    "from": from_email,
                    "to": to,
                    "subject": "Verify your email",
                    "text": format!(
                        "Use the link below to verify your email address.\
                        \nIt expires in 15 minutes.\n\n{verify_link}"
                    ),
                });

                let res = http
                    .post("https://api.resend.com/emails")
                    .bearer_auth(api_key)
                    .json(&body)
                    .send()
                    .await
                    .context("failed to reach Resend")?;

                if !res.status().is_success() {
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    anyhow::bail!("Resend returned {status}: {text}");
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
