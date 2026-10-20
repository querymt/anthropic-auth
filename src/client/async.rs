use crate::transport::{AsyncHttpTransport, HttpRequest};
use oauth2::PkceCodeChallenge;
use rand::Rng;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use url::Url;

use super::shared::*;
use crate::types::{ApiKeyResponse, TokenResponse};
use crate::{OAuthConfig, OAuthFlow, OAuthMode, Result, TokenSet};

/// Asynchronous Anthropic OAuth client for authentication
///
/// This client handles the OAuth 2.0 flow with PKCE for Anthropic/Claude authentication
/// using an injected HTTP transport. The optional reqwest adapter requires Tokio;
/// custom transports can use any executor.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "reqwest-transport")]
/// # {
/// use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = AsyncOAuthClient::new(OAuthConfig::default())?;
///     let flow = client.start_flow(OAuthMode::Max)?;
///     
///     println!("Visit: {}", flow.authorization_url);
///     // User authorizes and you get the code and state...
///     
///     let tokens = client.exchange_code("code_value", "state_value", &flow.verifier).await?;
///     println!("Got tokens!");
///     Ok(())
/// }
/// # }
/// ```
pub struct AsyncOAuthClient {
    config: OAuthConfig,
    transport: Arc<dyn AsyncHttpTransport>,
}

impl AsyncOAuthClient {
    /// Create a new async OAuth client with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - OAuth configuration (client ID, redirect URI)
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    #[cfg(feature = "reqwest-transport")]
    pub fn new(config: OAuthConfig) -> Result<Self> {
        Self::with_transport(config, crate::transport::ReqwestTransport::new()?)
    }

    /// Construct a client with HTTP I/O supplied by the caller's runtime.
    ///
    /// The transport is reused for exchange, refresh, and API-key creation. This
    /// constructor does not start a runtime or perform network I/O.
    ///
    /// This offline example runs on a non-Tokio executor:
    ///
    /// ```
    /// use anthropic_auth::{AsyncOAuthClient, OAuthConfig};
    /// use anthropic_auth::transport::{AsyncHttpTransport, HttpRequest, HttpResponse, TransportFuture};
    ///
    /// struct OfflineTransport;
    /// impl AsyncHttpTransport for OfflineTransport {
    ///     fn send(&self, _request: HttpRequest) -> TransportFuture<'_> {
    ///         Box::pin(async {
    ///             Ok(HttpResponse {
    ///                 status: 200,
    ///                 body: br#"{"access_token":"access","refresh_token":"rotated","expires_in":3600}"#.to_vec(),
    ///             })
    ///         })
    ///     }
    /// }
    ///
    /// let client = AsyncOAuthClient::with_transport(OAuthConfig::default(), OfflineTransport)?;
    /// let tokens = futures::executor::block_on(client.refresh_token("old-refresh"))?;
    /// assert_eq!(tokens.refresh_token, "rotated");
    /// # Ok::<(), anthropic_auth::AnthropicAuthError>(())
    /// ```
    pub fn with_transport(
        config: OAuthConfig,
        transport: impl AsyncHttpTransport + 'static,
    ) -> Result<Self> {
        Ok(Self {
            config,
            transport: Arc::new(transport),
        })
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: serde_json::Value,
        access_token: Option<&str>,
    ) -> Result<T> {
        let mut headers = vec![("content-type".into(), "application/json".into())];
        if let Some(token) = access_token {
            headers.push(("authorization".into(), format!("Bearer {token}")));
        } else {
            headers.push(("accept".into(), TOKEN_ACCEPT.into()));
            headers.push(("user-agent".into(), TOKEN_USER_AGENT.into()));
        }
        let response = self
            .transport
            .send(HttpRequest {
                url: url.to_string(),
                headers,
                body: serde_json::to_vec(&body)?,
            })
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(create_http_error(
                response.status,
                &String::from_utf8_lossy(&response.body),
            ));
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Start the OAuth authorization flow
    ///
    /// This generates a PKCE challenge and state token, then creates the authorization URL
    /// that the user should visit to authorize the application.
    ///
    /// Note: This method is synchronous even though the client is async.
    ///
    /// # Arguments
    ///
    /// * `mode` - The OAuth mode (Max for subscription, Console for API key creation)
    ///
    /// # Returns
    ///
    /// An `OAuthFlow` containing the authorization URL, PKCE verifier, state token, and mode
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "reqwest-transport")]
    /// # {
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// let flow = client.start_flow(OAuthMode::Max)?;
    /// println!("Visit: {}", flow.authorization_url);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn start_flow(&self, mode: OAuthMode) -> Result<OAuthFlow> {
        // Generate PKCE challenge and verifier
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let verifier = pkce_verifier.secret().to_string();

        // Generate a separate random state for CSRF protection (more secure than using verifier)
        let state = generate_random_state();

        // Determine base domain based on mode
        let base_domain = match mode {
            OAuthMode::Max => "claude.ai",
            OAuthMode::Console => "platform.claude.com",
        };

        // Build authorization URL
        let auth_url = format!("https://{}/oauth/authorize", base_domain);
        let mut url = Url::parse(&auth_url)?;

        url.query_pairs_mut()
            .append_pair("code", "true")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", SCOPE)
            .append_pair("code_challenge", pkce_challenge.as_str())
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state);

        Ok(OAuthFlow {
            authorization_url: url.to_string(),
            verifier,
            state,
            mode,
        })
    }

    /// Exchange an authorization code for access and refresh tokens (async)
    ///
    /// After the user authorizes the application, Anthropic returns a combined string
    /// in the format `code#state`. This method parses that format, validates the state
    /// for CSRF protection, and exchanges the code for tokens.
    ///
    /// # Arguments
    ///
    /// * `code_with_state` - The combined authorization response (format: "code#state")
    ///   or a callback URL/query string containing both code and state
    /// * `expected_state` - The state token from the original flow (for CSRF validation)
    /// * `verifier` - The PKCE verifier from the original flow
    ///
    /// # Returns
    ///
    /// A `TokenSet` containing access token, refresh token, and expiration time
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The code, state, or verifier is invalid or empty
    /// - The state doesn't match the expected state (CSRF protection)
    /// - The token exchange fails (invalid code, network error, etc.)
    /// - The response contains invalid token data
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "reqwest-transport")]
    /// # {
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// # let flow = client.start_flow(OAuthMode::Max)?;
    /// // User pastes the combined response from Anthropic
    /// let response = "code123#state456";
    /// let tokens = client.exchange_code(response, &flow.state, &flow.verifier).await?;
    /// println!("Access token expires in: {:?}", tokens.expires_in());
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub async fn exchange_code(
        &self,
        code_with_state: &str,
        expected_state: &str,
        verifier: &str,
    ) -> Result<TokenSet> {
        // Parse code and state from the input
        let (code, state) = parse_code_and_state(code_with_state, expected_state)?;

        // Validate inputs
        validate_code(&code)?;
        validate_state(&state)?;
        validate_verifier(verifier)?;

        let request_body = build_token_request(
            &code,
            &state,
            verifier,
            &self.config.client_id,
            &self.config.redirect_uri,
        );

        let token_response: TokenResponse = self.post_json(TOKEN_URL, request_body, None).await?;
        let tokens = TokenSet::from(token_response);

        // Validate the token structure
        tokens.validate().map_err(|e| {
            crate::AnthropicAuthError::OAuth(format!("Invalid token response: {}", e))
        })?;

        Ok(tokens)
    }

    /// Refresh an expired access token (async)
    ///
    /// When an access token expires, use the refresh token to obtain a new
    /// access token without requiring the user to re-authorize.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The refresh token from a previous token exchange
    ///
    /// # Returns
    ///
    /// A new `TokenSet` with fresh access token
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh fails (invalid refresh token, network error, etc.)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "reqwest-transport")]
    /// # {
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// # let old_tokens = client.exchange_code("code", "state", "verifier").await?;
    /// let new_tokens = client.refresh_token(&old_tokens.refresh_token).await?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet> {
        if refresh_token.is_empty() {
            return Err(crate::AnthropicAuthError::OAuth(
                "Refresh token is empty".to_string(),
            ));
        }

        let request_body = build_refresh_request(refresh_token, &self.config.client_id);

        let token_response: TokenResponse = self.post_json(TOKEN_URL, request_body, None).await?;
        let tokens = TokenSet::from(token_response);

        // Validate the token structure
        tokens.validate().map_err(|e| {
            crate::AnthropicAuthError::OAuth(format!("Invalid token response: {}", e))
        })?;

        Ok(tokens)
    }

    /// Create an API key using a Console OAuth access token (async)
    ///
    /// This method is only available when using Console mode OAuth.
    /// It creates a new API key that can be used with Anthropic's API.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The access token from Console mode OAuth
    ///
    /// # Returns
    ///
    /// The API key as a string
    ///
    /// # Errors
    ///
    /// Returns an error if API key creation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "reqwest-transport")]
    /// # {
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// # let flow = client.start_flow(OAuthMode::Console)?;
    /// # let tokens = client.exchange_code("code", "state", &flow.verifier).await?;
    /// let api_key = client.create_api_key(&tokens.access_token).await?;
    /// println!("API Key: {}", api_key);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub async fn create_api_key(&self, access_token: &str) -> Result<String> {
        validate_access_token(access_token)?;

        let request_body = build_api_key_request();

        let key_response: ApiKeyResponse = self
            .post_json(API_KEY_URL, request_body, Some(access_token))
            .await?;

        // Validate API key is not empty
        if key_response.raw_key.is_empty() {
            return Err(crate::AnthropicAuthError::OAuth(
                "Received empty API key from server".to_string(),
            ));
        }

        Ok(key_response.raw_key)
    }
}

/// Generate a cryptographically random state token for CSRF protection
fn generate_random_state() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &random_bytes,
    )
}

/// Parse code and state from the authorization response
///
/// Anthropic returns the authorization response in the format "code#state".
/// This function parses that format and validates the state against the expected value.
///
/// # Arguments
///
/// * `code_with_state` - The authorization response containing both code and state
/// * `expected_state` - The state token from the original flow for validation
///
/// # Returns
///
/// A tuple of (code, state) where state has been validated against expected_state
///
/// # Errors
///
/// Returns an error if the state doesn't match the expected state (CSRF protection)
fn parse_code_and_state(input: &str, expected_state: &str) -> Result<(String, String)> {
    super::shared::parse_code_and_state(input, expected_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{HttpResponse, TransportFuture};
    use crate::AnthropicAuthError;
    use futures::executor::block_on;
    use serde_json::json;
    use std::{collections::VecDeque, sync::Mutex, task::Poll};

    #[derive(Clone, Default)]
    struct MockTransport {
        requests: Arc<Mutex<Vec<HttpRequest>>>,
        responses: Arc<Mutex<VecDeque<Result<HttpResponse>>>>,
    }

    impl MockTransport {
        fn respond(&self, status: u16, body: &[u8]) {
            self.responses.lock().unwrap().push_back(Ok(HttpResponse {
                status,
                body: body.to_vec(),
            }));
        }
    }

    impl AsyncHttpTransport for MockTransport {
        fn send(&self, request: HttpRequest) -> TransportFuture<'_> {
            Box::pin(async move {
                // Exercise wakeups and genuinely suspended I/O without a Tokio runtime.
                let mut yielded = false;
                std::future::poll_fn(move |cx| {
                    if yielded {
                        Poll::Ready(())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                self.requests.lock().unwrap().push(request);
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected HTTP request")
            })
        }
    }

    const TOKENS: &[u8] = br#"{"access_token":"access","refresh_token":"rotated","expires_in":3600,"token_type":"Bearer"}"#;

    fn assert_send<T: Send>(value: T) -> T {
        value
    }

    #[test]
    fn custom_transport_works_without_tokio() {
        let transport = MockTransport::default();
        transport.respond(200, TOKENS);
        transport.respond(200, TOKENS);
        transport.respond(200, br#"{"raw_key":"new-api-key"}"#);
        let config = OAuthConfig::builder()
            .redirect_uri("https://platform.claude.com/oauth/code/callback")
            .build();
        let client = AsyncOAuthClient::with_transport(config.clone(), transport.clone()).unwrap();
        let flow = client.start_flow(OAuthMode::Max).unwrap();
        let response = format!("authorization-code#{}", flow.state);
        let tokens = block_on(assert_send(client.exchange_code(
            &response,
            &flow.state,
            &flow.verifier,
        )))
        .unwrap();
        assert_eq!(tokens.refresh_token, "rotated");
        assert_eq!(
            block_on(client.refresh_token("old-refresh"))
                .unwrap()
                .access_token,
            "access"
        );
        assert_eq!(
            block_on(client.create_api_key("console-access")).unwrap(),
            "new-api-key"
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for request in &requests[..2] {
            assert_eq!(request.url, TOKEN_URL);
            assert!(request
                .headers
                .contains(&("accept".into(), TOKEN_ACCEPT.into())));
            assert!(request
                .headers
                .contains(&("user-agent".into(), TOKEN_USER_AGENT.into())));
            assert!(request
                .headers
                .contains(&("content-type".into(), "application/json".into())));
            assert!(!request
                .headers
                .iter()
                .any(|(name, _)| name == "authorization"));
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
            json!({
                "grant_type": "authorization_code", "code": "authorization-code", "state": flow.state,
                "code_verifier": flow.verifier, "client_id": config.client_id, "redirect_uri": config.redirect_uri,
            })
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[1].body).unwrap(),
            json!({
                "grant_type": "refresh_token", "refresh_token": "old-refresh", "client_id": config.client_id,
            })
        );
        assert_eq!(requests[2].url, API_KEY_URL);
        assert!(requests[2]
            .headers
            .contains(&("authorization".into(), "Bearer console-access".into())));
        assert_eq!(requests[2].body, b"{}");
    }

    #[test]
    fn invalid_inputs_never_reach_transport() {
        let transport = MockTransport::default();
        let client =
            AsyncOAuthClient::with_transport(OAuthConfig::default(), transport.clone()).unwrap();
        let flow = client.start_flow(OAuthMode::Max).unwrap();
        for response in [
            "authorization-code",
            "authorization-code#wrong",
            "code=x&state=wrong",
        ] {
            assert!(block_on(client.exchange_code(response, &flow.state, &flow.verifier)).is_err());
        }
        let response = format!("authorization-code#{}", flow.state);
        assert!(block_on(client.exchange_code(&response, &flow.state, "short")).is_err());
        assert!(block_on(client.refresh_token("")).is_err());
        assert!(block_on(client.create_api_key("")).is_err());
        assert!(transport.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn custom_transport_preserves_error_handling() {
        let transport = MockTransport::default();
        let client =
            AsyncOAuthClient::with_transport(OAuthConfig::default(), transport.clone()).unwrap();
        transport.respond(401, b"expired token");
        assert!(
            matches!(block_on(client.refresh_token("refresh")), Err(AnthropicAuthError::Http { status: 401, body }) if body.contains("expired token"))
        );
        transport.respond(200, b"not json");
        assert!(matches!(
            block_on(client.refresh_token("refresh")),
            Err(AnthropicAuthError::Serialization(_))
        ));
        transport.respond(200, br#"{"access_token":"","refresh_token":"refresh","expires_in":3600,"token_type":"Bearer"}"#);
        assert!(matches!(
            block_on(client.refresh_token("refresh")),
            Err(AnthropicAuthError::OAuth(_))
        ));
        transport.respond(200, br#"{"raw_key":""}"#);
        assert!(matches!(
            block_on(client.create_api_key("access")),
            Err(AnthropicAuthError::OAuth(_))
        ));
        transport
            .responses
            .lock()
            .unwrap()
            .push_back(Err(AnthropicAuthError::Transport(Box::new(
                std::io::Error::new(std::io::ErrorKind::TimedOut, "transport timed out"),
            ))));
        assert!(matches!(
            block_on(client.refresh_token("refresh")),
            Err(AnthropicAuthError::Transport(_))
        ));
    }
}
