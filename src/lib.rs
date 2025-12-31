//! # anthropic-auth
//!
//! A Rust library for Anthropic/Claude OAuth 2.0 authentication with PKCE support.
//!
//! This library provides both synchronous (blocking) and asynchronous (runtime-agnostic)
//! APIs for authenticating with Anthropic's OAuth 2.0 endpoints.
//!
//! ## Features
//!
//! - **Sync API** (default): Blocking operations, no async runtime required
//! - **Async API** (optional): Runtime-agnostic async operations
//! - **PKCE Support**: Secure PKCE (SHA-256) authentication flow with separate CSRF state tokens
//! - **Two OAuth Modes**: Max (subscription) and Console (API key creation)
//! - **Configurable**: Custom client IDs, redirect URIs
//! - **Browser Integration**: Auto-open browser for authorization (default)
//! - **Callback Server**: Local server for automatic callback handling (optional, requires tokio)
//! - **API Key Creation**: Create API keys via Console OAuth
//! - **Token Validation**: Built-in validation for tokens and parameters
//!
//! ## Choosing Between Sync and Async
//!
//! - Use [`OAuthClient`] (sync) if you're building a CLI tool or simple application without async
//! - Use [`AsyncOAuthClient`] (async) if you're building a web server or async application
//!
//! ## Quick Start (Sync API)
//!
//! ```no_run
//! use anthropic_auth::{OAuthClient, OAuthConfig, OAuthMode};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = OAuthClient::new(OAuthConfig::default())?;
//!     let flow = client.start_flow(OAuthMode::Max)?;
//!     
//!     println!("Visit: {}", flow.authorization_url);
//!     // User authorizes and receives response in format: "code#state"
//!     let response = "code123#state456";
//!     
//!     // Library automatically parses and validates the state
//!     let tokens = client.exchange_code(response, &flow.state, &flow.verifier)?;
//!     println!("Got tokens!");
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Start (Async API)
//!
//! ```no_run
//! # #[cfg(feature = "async")]
//! # {
//! use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = AsyncOAuthClient::new(OAuthConfig::default())?;
//! let flow = client.start_flow(OAuthMode::Max)?;
//!
//! println!("Visit: {}", flow.authorization_url);
//! // User authorizes and receives response in format: "code#state"
//! let response = "code123#state456";
//!
//! // Library automatically parses and validates the state
//! let tokens = client.exchange_code(response, &flow.state, &flow.verifier).await?;
//! println!("Got tokens!");
//! # Ok(())
//! # }
//! # }
//! ```

mod error;
mod types;

#[cfg(any(feature = "blocking", feature = "async"))]
mod client;

#[cfg(feature = "browser")]
mod browser;

#[cfg(feature = "callback-server")]
mod server;

// Public API exports
pub use error::{AnthropicAuthError, Result};
pub use types::{OAuthConfig, OAuthConfigBuilder, OAuthFlow, OAuthMode, TokenSet};

#[cfg(feature = "blocking")]
pub use client::OAuthClient;

#[cfg(feature = "async")]
pub use client::AsyncOAuthClient;

#[cfg(feature = "browser")]
pub use browser::open_browser;

#[cfg(feature = "callback-server")]
pub use server::{run_callback_server, CallbackData};
