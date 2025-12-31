use oauth2::PkceCodeChallenge;
use rand::Rng;
use url::Url;

use super::shared::*;
use crate::types::{ApiKeyResponse, TokenResponse};
use crate::{OAuthConfig, OAuthFlow, OAuthMode, Result, TokenSet};

/// Asynchronous Anthropic OAuth client for authentication
///
/// This client handles the OAuth 2.0 flow with PKCE for Anthropic/Claude authentication
/// using async I/O. Works with any async runtime (tokio, async-std, etc.).
///
/// # Example
///
/// ```no_run
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
/// ```
pub struct AsyncOAuthClient {
    config: OAuthConfig,
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
    pub fn new(config: OAuthConfig) -> Result<Self> {
        Ok(Self { config })
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
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// let flow = client.start_flow(OAuthMode::Max)?;
    /// println!("Visit: {}", flow.authorization_url);
    /// # Ok(())
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
            OAuthMode::Console => "console.anthropic.com",
        };

        // Build authorization URL
        let auth_url = format!("https://{}/oauth/authorize", base_domain);
        let mut url = Url::parse(&auth_url)?;

        url.query_pairs_mut()
            .append_pair("code", "true")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", REDIRECT_URI)
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
    ///   or just the code if already separated
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

        let client = reqwest::Client::new();
        let request_body = build_token_request(&code, &state, verifier, &self.config.client_id);

        let response = client.post(TOKEN_URL).json(&request_body).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(create_http_error(status, &body));
        }

        let token_response: TokenResponse = response.json().await?;
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
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// # let old_tokens = client.exchange_code("code", "state", "verifier").await?;
    /// let new_tokens = client.refresh_token(&old_tokens.refresh_token).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet> {
        if refresh_token.is_empty() {
            return Err(crate::AnthropicAuthError::OAuth(
                "Refresh token is empty".to_string(),
            ));
        }

        let client = reqwest::Client::new();
        let request_body = build_refresh_request(refresh_token, &self.config.client_id);

        let response = client.post(TOKEN_URL).json(&request_body).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(create_http_error(status, &body));
        }

        let token_response: TokenResponse = response.json().await?;
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
    /// # use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    /// # let flow = client.start_flow(OAuthMode::Console)?;
    /// # let tokens = client.exchange_code("code", "state", &flow.verifier).await?;
    /// let api_key = client.create_api_key(&tokens.access_token).await?;
    /// println!("API Key: {}", api_key);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_api_key(&self, access_token: &str) -> Result<String> {
        validate_access_token(access_token)?;

        let client = reqwest::Client::new();
        let request_body = build_api_key_request();

        let response = client
            .post(API_KEY_URL)
            .header("authorization", format!("Bearer {}", access_token))
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(create_http_error(status, &body));
        }

        let key_response: ApiKeyResponse = response.json().await?;

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
/// * `code_with_state` - The authorization response (may contain "#state" or just the code)
/// * `expected_state` - The state token from the original flow for validation
///
/// # Returns
///
/// A tuple of (code, state) where state has been validated against expected_state
///
/// # Errors
///
/// Returns an error if the state doesn't match the expected state (CSRF protection)
fn parse_code_and_state(code_with_state: &str, expected_state: &str) -> Result<(String, String)> {
    if let Some(hash_pos) = code_with_state.find('#') {
        // Parse "code#state" format
        let code = &code_with_state[..hash_pos];
        let returned_state = &code_with_state[hash_pos + 1..];

        // Validate state for CSRF protection
        if returned_state != expected_state {
            return Err(crate::AnthropicAuthError::OAuth(format!(
                "State mismatch - possible CSRF attack. Expected: {}, Got: {}",
                expected_state, returned_state
            )));
        }

        Ok((code.to_string(), returned_state.to_string()))
    } else {
        // No "#" found, assume just the code was provided
        // Use the expected_state directly
        Ok((code_with_state.to_string(), expected_state.to_string()))
    }
}
