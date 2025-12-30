use crate::{AnthropicAuthError, Result};

/// Open a URL in the user's default web browser
///
/// This is a convenience function for opening the OAuth authorization URL.
/// It will attempt to open the URL in the default browser on the user's system.
///
/// # Arguments
///
/// * `url` - The URL to open
///
/// # Errors
///
/// Returns an error if the browser cannot be launched
///
/// # Example
///
/// ```no_run
/// use anthropic_auth::{OAuthClient, OAuthConfig, OAuthMode, open_browser};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = OAuthClient::new(OAuthConfig::default())?;
/// let flow = client.start_flow(OAuthMode::Max)?;
///
/// // Automatically open browser
/// open_browser(&flow.authorization_url)?;
/// println!("Browser opened! Please authorize the application.");
/// # Ok(())
/// # }
/// ```
pub fn open_browser(url: &str) -> Result<()> {
    webbrowser::open(url)
        .map_err(|e| AnthropicAuthError::BrowserLaunch(format!("Failed to open browser: {}", e)))
}
