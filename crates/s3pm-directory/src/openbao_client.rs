use anyhow::{anyhow, Context, Result};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub enum OpenBaoAuth {
    Token(String),
    AppRole {
        mount: String,
        role_id: String,
        secret_id: String,
    },
}

#[derive(Clone)]
pub struct OpenBaoClient {
    address: String, // base, no trailing slash
    auth: OpenBaoAuth,
    http: reqwest::Client,
    state: Arc<Mutex<TokenState>>,
}

#[derive(Debug)]
struct TokenState {
    token: Option<String>,
    expires_at: Option<Instant>,
}

impl OpenBaoClient {
    pub fn new_token(address: impl Into<String>, token: impl Into<String>) -> Self {
        let token = token.into();
        Self {
            address: address.into().trim_end_matches('/').to_string(),
            auth: OpenBaoAuth::Token(token.clone()),
            http: reqwest::Client::new(),
            state: Arc::new(Mutex::new(TokenState {
                token: Some(token),
                expires_at: None,
            })),
        }
    }

    pub fn new_approle(
        address: impl Into<String>,
        approle_mount: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into().trim_end_matches('/').to_string(),
            auth: OpenBaoAuth::AppRole {
                mount: trim_slashes(&approle_mount.into()),
                role_id: role_id.into(),
                secret_id: secret_id.into(),
            },
            http: reqwest::Client::new(),
            state: Arc::new(Mutex::new(TokenState {
                token: None,
                expires_at: None,
            })),
        }
    }

    fn url(&self, api_path: &str) -> String {
        format!(
            "{}/v1/{}",
            self.address,
            api_path.trim_start_matches('/')
        )
    }

    async fn approle_login(&self, mount: &str, role_id: &str, secret_id: &str) -> Result<(String, u64)> {
        #[derive(Debug, Serialize)]
        struct Req<'a> {
            role_id: &'a str,
            secret_id: &'a str,
        }

        #[derive(Debug, Deserialize)]
        struct Resp {
            auth: Option<Auth>,
        }

        #[derive(Debug, Deserialize)]
        struct Auth {
            client_token: String,
            lease_duration: u64,
        }

        let api_path = format!("auth/{}/login", trim_slashes(mount));

        let resp = self
            .http
            .post(self.url(&api_path))
            .json(&Req { role_id, secret_id })
            .send()
            .await
            .context("openbao approle login send")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("openbao approle login failed: {status} {body}"));
        }

        let r: Resp = resp.json().await.context("openbao approle login json parse")?;
        let a = r
            .auth
            .ok_or_else(|| anyhow!("openbao approle login: missing auth in response"))?;

        Ok((a.client_token, a.lease_duration))
    }

    async fn ensure_token(&self) -> Result<String> {
        // Token auth is static
        if let OpenBaoAuth::Token(t) = &self.auth {
            return Ok(t.clone());
        }

        // AppRole: cached token, refreshed near expiry
        let mut st = self.state.lock().await;

        let needs_login = match (&st.token, &st.expires_at) {
            (Some(_), Some(exp)) => Instant::now() + Duration::from_secs(30) >= *exp,
            _ => true,
        };

        if !needs_login {
            return Ok(st.token.clone().unwrap());
        }

        let (mount, role_id, secret_id) = match &self.auth {
            OpenBaoAuth::AppRole { mount, role_id, secret_id } => {
                (mount.as_str(), role_id.as_str(), secret_id.as_str())
            }
            OpenBaoAuth::Token(_) => unreachable!(),
        };

        let (token, ttl) = self.approle_login(mount, role_id, secret_id).await?;
        st.token = Some(token.clone());
        st.expires_at = Some(Instant::now() + Duration::from_secs(ttl));
        Ok(token)
    }

    async fn request(&self, method: Method, api_path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.ensure_token().await?;
        Ok(self
            .http
            .request(method, self.url(api_path))
            .header("X-Vault-Token", token))
    }

    async fn send_ok(&self, rb: reqwest::RequestBuilder, ctx: &str) -> Result<reqwest::Response> {
        let resp = rb.send().await.with_context(|| format!("{ctx}: send"))?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!("{ctx}: {status} {body}"))
        }
    }

    /* ----------------------------- KV v2 ----------------------------- */

    pub async fn kv2_read_opt<T>(&self, kv_mount: &str, rel_path: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned + Send,
    {
        #[derive(Debug, Deserialize)]
        struct Resp<T> {
            data: Option<Data<T>>,
        }
        #[derive(Debug, Deserialize)]
        struct Data<T> {
            data: T,
        }

        let m = trim_slashes(kv_mount);
        let p = rel_path.trim().trim_start_matches('/');

        let api_path = format!("{}/data/{}", m, p);
        let resp = self
            .request(Method::GET, &api_path)
            .await?
            .send()
            .await
            .context("kv2 read send")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("kv2 read failed: {status} {body}"));
        }

        let r: Resp<T> = resp.json().await.context("kv2 read json parse")?;
        Ok(r.data.map(|d| d.data))
    }

    pub async fn kv2_write<T>(&self, kv_mount: &str, rel_path: &str, doc: &T) -> Result<()>
    where
        T: Serialize,
    {
        let m = trim_slashes(kv_mount);
        let p = rel_path.trim().trim_start_matches('/');

        let api_path = format!("{}/data/{}", m, p);
        let data = serde_json::to_value(doc).context("kv2 write serialize doc")?;

        self.send_ok(
            self.request(Method::POST, &api_path).await?.json(&json!({ "data": data })),
            "kv2 write",
        )
        .await?;
        Ok(())
    }

    pub async fn kv2_delete_metadata(&self, kv_mount: &str, rel_path: &str) -> Result<()> {
        let m = trim_slashes(kv_mount);
        let p = rel_path.trim().trim_start_matches('/');

        let api_path = format!("{}/metadata/{}", m, p);

        let resp = self
            .request(Method::DELETE, &api_path)
            .await?
            .send()
            .await
            .context("kv2 delete metadata send")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("kv2 delete metadata failed: {status} {body}"));
        }
        Ok(())
    }

    pub async fn kv2_list_opt(&self, kv_mount: &str, rel_path: &str) -> Result<Option<Vec<String>>> {
        #[derive(Debug, Deserialize)]
        struct Resp {
            data: Option<Data>,
        }
        #[derive(Debug, Deserialize)]
        struct Data {
            keys: Vec<String>,
        }

        let m = trim_slashes(kv_mount);
        let p = rel_path.trim().trim_start_matches('/');

        let api_path = format!("{}/metadata/{}", m, p);

        let list_method = Method::from_bytes(b"LIST").context("construct LIST method")?;
        let resp = self
            .request(list_method, &api_path)
            .await?
            .send()
            .await
            .context("kv2 list send")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("kv2 list failed: {status} {body}"));
        }

        let r: Resp = resp.json().await.context("kv2 list json parse")?;
        Ok(Some(r.data.map(|d| d.keys).unwrap_or_default()))
    }

    /* ----------------------------- Setup helpers (admin-only usage) ----------------------------- */

    pub async fn enable_auth_approle(&self, approle_mount: &str) -> Result<()> {
        let m = trim_slashes(approle_mount);
        let api_path = format!("sys/auth/{m}");

        let resp = self
            .request(Method::POST, &api_path)
            .await?
            .json(&json!({ "type": "approle" }))
            .send()
            .await
            .context("enable approle auth send")?;

        if resp.status().is_success() {
            return Ok(());
        }

        // treat "already enabled" as OK
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == StatusCode::BAD_REQUEST && body.to_ascii_lowercase().contains("path is already in use") {
            return Ok(());
        }

        Err(anyhow!("enable approle auth failed: {status} {body}"))
    }

    pub async fn set_acl_policy(&self, policy_name: &str, policy_hcl: &str) -> Result<()> {
        let name = trim_slashes(policy_name);
        let api_path = format!("sys/policies/acl/{name}");

        self.send_ok(
            self.request(Method::PUT, &api_path)
                .await?
                .json(&json!({ "policy": policy_hcl })),
            "set policy",
        )
        .await?;
        Ok(())
    }

    pub async fn set_approle_role(
        &self,
        approle_mount: &str,
        role_name: &str,
        token_policies: &[String],
    ) -> Result<()> {
        let m = trim_slashes(approle_mount);
        let r = trim_slashes(role_name);
        let api_path = format!("auth/{m}/role/{r}");

        self.send_ok(
            self.request(Method::POST, &api_path)
                .await?
                .json(&json!({
                    "token_policies": token_policies,
                    "token_no_default_policy": true
                })),
            "set approle role",
        )
        .await?;
        Ok(())
    }

    pub async fn read_approle_role_id(&self, approle_mount: &str, role_name: &str) -> Result<String> {
        #[derive(Debug, Deserialize)]
        struct Resp {
            data: Option<Data>,
        }
        #[derive(Debug, Deserialize)]
        struct Data {
            role_id: String,
        }

        let m = trim_slashes(approle_mount);
        let r = trim_slashes(role_name);
        let api_path = format!("auth/{m}/role/{r}/role-id");

        let resp = self
            .send_ok(self.request(Method::GET, &api_path).await?, "read role-id")
            .await?;
        let r: Resp = resp.json().await.context("read role-id json parse")?;

        Ok(r.data.ok_or_else(|| anyhow!("read role-id: missing data"))?.role_id)
    }

    pub async fn generate_approle_secret_id(&self, approle_mount: &str, role_name: &str) -> Result<String> {
        #[derive(Debug, Deserialize)]
        struct Resp {
            data: Option<Data>,
        }
        #[derive(Debug, Deserialize)]
        struct Data {
            secret_id: String,
        }

        let m = trim_slashes(approle_mount);
        let r = trim_slashes(role_name);
        let api_path = format!("auth/{m}/role/{r}/secret-id");

        let resp = self
            .send_ok(
                self.request(Method::POST, &api_path).await?.json(&json!({})),
                "generate secret-id",
            )
            .await?;
        let r: Resp = resp.json().await.context("generate secret-id json parse")?;

        Ok(r.data.ok_or_else(|| anyhow!("generate secret-id: missing data"))?.secret_id)
    }
}

fn trim_slashes(s: &str) -> String {
    s.trim().trim_matches('/').to_string()
}

