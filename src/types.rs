use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// OAuth mode for Anthropic authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthMode {
    /// Claude Pro/Max subscription (uses claude.ai)
    Max,
    /// API key creation (uses console.anthropic.com)
    Console,
}

/// OAuth token set containing access token, refresh token, and expiration info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    /// The access token used to authenticate API requests
    pub access_token: String,
    /// The refresh token used to obtain new access tokens
    pub refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires
    pub expires_at: u64,
}

impl TokenSet {
    /// Check if the token is expired or will expire soon (within 5 minutes)
    ///
    /// This includes a 5-minute buffer to prevent race conditions where a token
    /// expires between checking and using it.
    pub fn is_expired(&self) -> bool {
        self.expires_in() <= Duration::from_secs(300)
    }

    /// Get the duration until the token expires
    ///
    /// Returns `Duration::ZERO` if the token is already expired.
    pub fn expires_in(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.expires_at > now {
            Duration::from_secs(self.expires_at - now)
        } else {
            Duration::ZERO
        }
    }

    /// Validate the token structure
    ///
    /// Checks that the token fields are non-empty and properly formatted.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.access_token.is_empty() {
            return Err("access_token is empty");
        }
        if self.refresh_token.is_empty() {
            return Err("refresh_token is empty");
        }
        if self.expires_at == 0 {
            return Err("expires_at is invalid");
        }
        // Check if expires_at is reasonable (not too far in past or future)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Token shouldn't be more than 1 year in the future
        if self.expires_at > now + 31536000 {
            return Err("expires_at is too far in the future");
        }
        Ok(())
    }
}

/// OAuth authorization flow information
///
/// Contains the authorization URL, PKCE verifier, and state token needed to complete
/// the OAuth flow.
#[derive(Debug, Clone)]
pub struct OAuthFlow {
    /// The URL the user should visit to authorize the application
    pub authorization_url: String,
    /// The PKCE verifier used to exchange the authorization code for tokens
    pub verifier: String,
    /// The state token for CSRF protection
    pub state: String,
    /// The OAuth mode (Max or Console)
    pub mode: OAuthMode,
}

/// Configuration for the Anthropic OAuth client
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth client ID (default: "9d1c250a-e61b-44d9-88ed-5944d1962f5e")
    pub client_id: String,
    /// Redirect URI for OAuth callback (default: "http://localhost:1455/callback")
    pub redirect_uri: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e".to_string(),
            redirect_uri: "http://localhost:1455/callback".to_string(),
        }
    }
}

impl OAuthConfig {
    /// Create a new config builder
    pub fn builder() -> OAuthConfigBuilder {
        OAuthConfigBuilder::default()
    }
}

/// Builder for OAuthConfig
#[derive(Debug, Clone, Default)]
pub struct OAuthConfigBuilder {
    client_id: Option<String>,
    redirect_uri: Option<String>,
}

impl OAuthConfigBuilder {
    /// Set the OAuth client ID
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the redirect URI
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Set the redirect URI with a custom port
    pub fn redirect_port(mut self, port: u16) -> Self {
        self.redirect_uri = Some(format!("http://localhost:{}/callback", port));
        self
    }

    /// Build the OAuthConfig
    pub fn build(self) -> OAuthConfig {
        let defaults = OAuthConfig::default();
        OAuthConfig {
            client_id: self.client_id.unwrap_or(defaults.client_id),
            redirect_uri: self.redirect_uri.unwrap_or(defaults.redirect_uri),
        }
    }
}

/// Token response from OAuth server
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

impl From<TokenResponse> for TokenSet {
    fn from(response: TokenResponse) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + response.expires_in.unwrap_or(3600);

        TokenSet {
            access_token: response.access_token,
            refresh_token: response.refresh_token.unwrap_or_default(),
            expires_at,
        }
    }
}

/// API key creation response
#[derive(Debug, Deserialize)]
pub(crate) struct ApiKeyResponse {
    pub raw_key: String,
}
