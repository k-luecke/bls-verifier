//! O-701 / S.03 stage 2 — x402 verification trait.
//!
//! Phase 0 ships a feature-gated `MockX402` for tests and `HttpX402`, a
//! production client over the canonical x402 facilitator `/verify`
//! endpoint. The HTTP contract is defined by the open x402 spec
//! (coinbase/x402, specs/x402-specification-v1.md) and the operator
//! configures the URL/bearer to point at whichever facilitator they
//! trust — typically Coinbase's hosted endpoint at
//! `https://api.cdp.coinbase.com/platform/v2/x402/verify`.

use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

/// x402 payment verification.
///
/// # Security contract (issue #10)
///
/// A production `X402Verifier` MUST authenticate the payload against an
/// x402 facilitator and return `Err` when the payment is missing,
/// unsettled, replayed, or otherwise invalid. Implementations that
/// unconditionally return `Ok` (such as `MockX402`) are a security
/// violation outside of test code and must never be wired into a release
/// `Device`. The trait itself cannot enforce this — operators and reviewers
/// must. `Device::new` enforces a runtime floor when the `mock-x402`
/// feature is compiled in.
///
/// # Payload framing
///
/// `payload` is forwarded verbatim to the facilitator request body. The
/// caller is responsible for encoding it as the canonical x402
/// `{ x402Version, paymentPayload, paymentRequirements }` JSON envelope;
/// the verifier does not inspect the schema. This keeps the trait
/// scheme-agnostic so future scheme evolutions (v2, alternative
/// facilitators) do not require touching this module.
#[async_trait]
pub trait X402Verifier: Send + Sync {
    async fn verify(&self, payload: &str, request_hash: &[u8; 32]) -> Result<String, String>;
}

/// Test-only verifier that accepts every payload. Gated behind the
/// `mock-x402` cargo feature so it cannot be named from a default
/// release build. Every accept is logged at WARN so a misconfigured
/// staging deploy is observable in logs.
#[cfg(feature = "mock-x402")]
pub struct MockX402;

#[cfg(feature = "mock-x402")]
#[async_trait]
impl X402Verifier for MockX402 {
    async fn verify(&self, _payload: &str, request_hash: &[u8; 32]) -> Result<String, String> {
        let id = format!("mock-{}", hex::encode(&request_hash[..8]));
        tracing::warn!(
            target: "bls_device::x402",
            id = %id,
            "MockX402 accepting payload without facilitator check (issue #10); \
             this MUST NOT appear in production logs"
        );
        Ok(id)
    }
}

/// Default request timeout for the production facilitator client.
///
/// 10 seconds matches the `maxTimeoutSeconds` upper bound observed in the
/// canonical x402 example payloads (60s) divided by a comfortable
/// settlement-vs-verify margin. The operator can override via
/// `HttpX402::with_config`.
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Production x402 facilitator client.
///
/// Schema reference: `coinbase/x402` repo, `specs/x402-specification-v1.md`.
/// Endpoint shape:
///
///   POST <facilitator_url>
///   Authorization: Bearer <token>
///   Content-Type: application/json
///   Body: { x402Version, paymentPayload, paymentRequirements }
///
///   200 OK + { "isValid": true,  "payer": "0x..." }            → success
///   200 OK + { "isValid": false, "invalidReason": "...", ... }  → failure
///
/// Note: the original audit follow-up wording (#45) referred to a
/// `payment_id` success field. The current canonical x402 verify response
/// has no such field; the documented success identifier is `payer`. The
/// trait's `Result<String, String>` therefore returns `payer` on success.
pub struct HttpX402 {
    facilitator_url: String,
    bearer: String,
    http: reqwest::Client,
}

impl HttpX402 {
    /// Build a client with the default 10s timeout.
    pub fn new(facilitator_url: String, bearer: String) -> Result<Self, String> {
        Self::with_config(facilitator_url, bearer, DEFAULT_HTTP_TIMEOUT)
    }

    /// Build a client with an explicit request timeout. Used by tests; an
    /// operator can call this if the default 10s is unsuitable for their
    /// facilitator's settlement latency.
    pub fn with_config(
        facilitator_url: String,
        bearer: String,
        timeout: Duration,
    ) -> Result<Self, String> {
        if facilitator_url.is_empty() {
            return Err("facilitator_url required".into());
        }
        if bearer.is_empty() {
            return Err("bearer auth token required".into());
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("http client build: {e}"))?;
        Ok(Self { facilitator_url, bearer, http })
    }

    /// Build a client from environment variables. Both must be set or
    /// `Device` bringup fails closed.
    ///
    /// - `BLS_X402_FACILITATOR_URL` (e.g. `https://api.cdp.coinbase.com/platform/v2/x402/verify`)
    /// - `BLS_X402_BEARER`          (Bearer token issued by the facilitator)
    pub fn from_env() -> Result<Self, String> {
        let url = std::env::var("BLS_X402_FACILITATOR_URL")
            .map_err(|_| "BLS_X402_FACILITATOR_URL not set".to_string())?;
        let bearer = std::env::var("BLS_X402_BEARER")
            .map_err(|_| "BLS_X402_BEARER not set".to_string())?;
        Self::new(url, bearer)
    }
}

/// Subset of the canonical x402 verify response we deserialise. Unknown
/// fields are ignored so the facilitator can add fields without breaking
/// us.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VerifyResponseBody {
    is_valid: bool,
    payer: Option<String>,
    invalid_reason: Option<String>,
    invalid_message: Option<String>,
}

#[async_trait]
impl X402Verifier for HttpX402 {
    async fn verify(&self, payload: &str, _request_hash: &[u8; 32]) -> Result<String, String> {
        let resp = self
            .http
            .post(&self.facilitator_url)
            .header("Authorization", format!("Bearer {}", self.bearer))
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
            .map_err(|e| format!("x402 facilitator unreachable: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            // Best-effort body capture for the operator log; never trust
            // it as a payment receipt.
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "x402 facilitator non-2xx ({status}): {}",
                body.chars().take(200).collect::<String>()
            ));
        }

        let parsed: VerifyResponseBody = resp
            .json()
            .await
            .map_err(|e| format!("x402 facilitator response parse: {e}"))?;

        if parsed.is_valid {
            Ok(parsed.payer.unwrap_or_else(|| "unknown".into()))
        } else {
            let reason = parsed
                .invalid_reason
                .or(parsed.invalid_message)
                .unwrap_or_else(|| "invalid_x402_payment".into());
            Err(reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server_uri: String) -> HttpX402 {
        HttpX402::new(format!("{server_uri}/verify"), "test-bearer-token".into()).unwrap()
    }

    #[tokio::test]
    async fn valid_response_returns_payer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .and(header("authorization", "Bearer test-bearer-token"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "isValid": true,
                "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
            })))
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        let result = client.verify("{}", &[0u8; 32]).await;
        assert_eq!(
            result,
            Ok("0x857b06519E91e3A54538791bDbb0E22373e36b66".to_string())
        );
    }

    #[tokio::test]
    async fn invalid_response_returns_invalid_reason() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "isValid": false,
                "invalidReason": "insufficient_funds",
                "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
            })))
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        let result = client.verify("{}", &[0u8; 32]).await;
        assert_eq!(result, Err("insufficient_funds".to_string()));
    }

    #[tokio::test]
    async fn invalid_response_falls_back_to_invalid_message() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "isValid": false,
                "invalidMessage": "payment authorization expired"
            })))
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        let result = client.verify("{}", &[0u8; 32]).await;
        assert_eq!(result, Err("payment authorization expired".to_string()));
    }

    #[tokio::test]
    async fn invalid_response_with_neither_field_uses_generic_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "isValid": false })))
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        let result = client.verify("{}", &[0u8; 32]).await;
        assert_eq!(result, Err("invalid_x402_payment".to_string()));
    }

    #[tokio::test]
    async fn malformed_response_body_returns_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        let result = client.verify("{}", &[0u8; 32]).await;
        match result {
            Err(e) if e.contains("response parse") => {}
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_2xx_returns_facilitator_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        let result = client.verify("{}", &[0u8; 32]).await;
        match result {
            Err(e) if e.contains("non-2xx") && e.contains("500") => {}
            other => panic!("expected non-2xx error, got {other:?}"),
        }
    }

    /// Connection that accepts but never responds; client must time out
    /// rather than hang. Uses a raw TCP listener instead of wiremock
    /// because wiremock's response delay is bounded by its own runtime
    /// scheduling and is less reliable than "accept and drop".
    #[tokio::test]
    async fn timeout_returns_unreachable_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept_task = tokio::spawn(async move {
            // Hold connections open without responding.
            let _conns: Vec<tokio::net::TcpStream> = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        // leak the stream so the kernel doesn't RST it
                        std::mem::forget(stream);
                    }
                    Err(_) => return,
                }
            }
        });
        let client = HttpX402::with_config(
            format!("http://{addr}/verify"),
            "tok".into(),
            Duration::from_millis(200),
        )
        .unwrap();
        let result = client.verify("{}", &[0u8; 32]).await;
        match result {
            Err(e) if e.contains("unreachable") => {}
            other => panic!("expected unreachable error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn constructor_rejects_empty_bearer() {
        let err =
            HttpX402::new("https://example.test/verify".into(), "".into()).unwrap_err();
        assert!(err.contains("bearer"), "got: {err}");
    }

    #[tokio::test]
    async fn constructor_rejects_empty_url() {
        let err = HttpX402::new("".into(), "tok".into()).unwrap_err();
        assert!(err.contains("facilitator_url"), "got: {err}");
    }

    #[tokio::test]
    async fn request_body_is_forwarded_verbatim() {
        let server = MockServer::start().await;
        let body = r#"{"x402Version":1,"paymentPayload":{"scheme":"exact"},"paymentRequirements":{"asset":"0x036CbD53842c5426634e7929541eC2318f3dCF7e"}}"#;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .and(wiremock::matchers::body_string(body))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "isValid": true, "payer": "0xabc" })),
            )
            .mount(&server)
            .await;
        let client = client_for(server.uri());
        assert_eq!(client.verify(body, &[0u8; 32]).await, Ok("0xabc".into()));
    }
}
