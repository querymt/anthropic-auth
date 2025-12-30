use serde_json::json;
use crate::{AnthropicAuthError, Result};

// OAuth constants
pub(super) const SCOPE: &str = "org:create_api_key user:profile user:inference";
pub(super) const TOKEN_URL: &str = "https://console.anthropic.com/v1/oauth/token";
pub(super) const API_KEY_URL: &str = "https://api.anthropic.com/api/oauth/claude_cli/create_api_key";
pub(super) const REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";

/// Build the token exchange request body
pub(super) fn build_token_request(
    code: &str,
    state: &str,
    verifier: &str,
    client_id: &str,
) -> serde_json::Value {
    json!({
        "code": code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    })
}

/// Build the refresh token request body
pub(super) fn build_refresh_request(
    refresh_token: &str,
    client_id: &str,
) -> serde_json::Value {
    json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    })
}

/// Build the API key creation request body
pub(super) fn build_api_key_request() -> serde_json::Value {
    json!({})
}

/// Create a detailed error from HTTP response
pub(super) fn create_http_error(status: u16, body: &str) -> AnthropicAuthError {
    // Provide helpful hints based on common error scenarios
    let hint = match status {
        400 => {
            if body.contains("code") {
                Some("The authorization code may be invalid, expired, or already used. Please try the flow again.")
            } else if body.contains("verifier") || body.contains("code_verifier") {
                Some("The PKCE verifier doesn't match. Make sure you're using the verifier from the same flow.")
            } else if body.contains("state") {
                Some("The state parameter is invalid. This could indicate a security issue.")
            } else {
                Some("Bad request - check that all parameters are correct.")
            }
        }
        401 => Some("Authentication failed - the access token may be invalid or expired."),
        403 => Some("Access forbidden - you may not have permission to perform this action."),
        404 => Some("Endpoint not found - the API URL may have changed."),
        429 => Some("Rate limit exceeded - please wait before retrying."),
        500..=599 => Some("Server error - this is an issue on Anthropic's side. Please try again later."),
        _ => None,
    };

    let error_message = if let Some(hint) = hint {
        format!("HTTP {} - {}\nHint: {}", status, body, hint)
    } else {
        format!("HTTP {} - {}", status, body)
    };

    AnthropicAuthError::Http {
        status,
        body: error_message,
    }
}

/// Validate authorization code format
pub(super) fn validate_code(code: &str) -> Result<()> {
    if code.is_empty() {
        return Err(AnthropicAuthError::InvalidAuthorizationCode);
    }
    // Authorization codes should be reasonably long
    if code.len() < 10 {
        return Err(AnthropicAuthError::InvalidAuthorizationCode);
    }
    Ok(())
}

/// Validate state token format
pub(super) fn validate_state(state: &str) -> Result<()> {
    if state.is_empty() {
        return Err(AnthropicAuthError::OAuth(
            "State token is empty".to_string(),
        ));
    }
    Ok(())
}

/// Validate verifier format
pub(super) fn validate_verifier(verifier: &str) -> Result<()> {
    if verifier.is_empty() {
        return Err(AnthropicAuthError::OAuth(
            "PKCE verifier is empty".to_string(),
        ));
    }
    // PKCE verifier should be between 43-128 characters (base64url encoded)
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(AnthropicAuthError::OAuth(
            "PKCE verifier has invalid length (must be 43-128 characters)".to_string(),
        ));
    }
    Ok(())
}

/// Validate access token format
pub(super) fn validate_access_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(AnthropicAuthError::OAuth(
            "Access token is empty".to_string(),
        ));
    }
    Ok(())
}
