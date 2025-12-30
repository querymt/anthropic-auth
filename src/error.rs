use thiserror::Error;

/// Error types for Anthropic OAuth authentication
#[derive(Error, Debug)]
pub enum AnthropicAuthError {
    #[error("Failed to create OAuth client: {0}")]
    ClientCreation(String),

    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,

    #[error("Token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Token refresh failed: {0}")]
    TokenRefresh(String),

    #[error("Token has expired")]
    TokenExpired,

    #[error("API key creation failed: {0}")]
    ApiKeyCreation(String),

    #[error("Invalid OAuth mode for this operation")]
    InvalidMode,

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("HTTP error: {status}")]
    Http { status: u16, body: String },

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[cfg(feature = "callback-server")]
    #[error("Callback server error: {0}")]
    CallbackServer(String),

    #[cfg(feature = "browser")]
    #[error("Failed to open browser: {0}")]
    BrowserLaunch(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

/// Result type alias for Anthropic authentication operations
pub type Result<T> = std::result::Result<T, AnthropicAuthError>;
