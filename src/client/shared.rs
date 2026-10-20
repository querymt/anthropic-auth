use crate::{AnthropicAuthError, Result};
use serde_json::json;

// OAuth constants
pub(super) const SCOPE: &str = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
pub(super) const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
pub(super) const TOKEN_ACCEPT: &str = "application/json, text/plain, */*";
pub(super) const TOKEN_USER_AGENT: &str = "axios/1.13.6";
pub(super) const API_KEY_URL: &str =
    "https://api.anthropic.com/api/oauth/claude_cli/create_api_key";

/// Build the token exchange request body
pub(super) fn build_token_request(
    code: &str,
    state: &str,
    verifier: &str,
    client_id: &str,
    redirect_uri: &str,
) -> serde_json::Value {
    json!({
        "code": code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    })
}

/// Parse all callback formats accepted by the working OAuth client without losing state.
pub(super) fn parse_code_and_state(input: &str, expected_state: &str) -> Result<(String, String)> {
    let input = input.trim();
    let query = if let Ok(url) = url::Url::parse(input) {
        url.query().unwrap_or_default().to_string()
    } else if let Some((code, state)) = input.split_once('#') {
        if code.is_empty() || state.is_empty() || state.contains('#') {
            return Err(AnthropicAuthError::InvalidAuthorizationCode);
        }
        return checked_callback(code.to_string(), state.to_string(), expected_state);
    } else {
        input.trim_start_matches('?').to_string()
    };
    let params: std::collections::HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    match (params.get("code"), params.get("state")) {
        (Some(code), Some(state)) if !code.is_empty() && !state.is_empty() => {
            checked_callback(code.clone(), state.clone(), expected_state)
        }
        _ => Err(AnthropicAuthError::InvalidAuthorizationCode),
    }
}

fn checked_callback(code: String, state: String, expected_state: &str) -> Result<(String, String)> {
    if expected_state.is_empty() || state != expected_state {
        return Err(AnthropicAuthError::OAuth(
            "State mismatch - possible CSRF attack".to_string(),
        ));
    }
    Ok((code, state))
}

/// Build the refresh token request body
pub(super) fn build_refresh_request(refresh_token: &str, client_id: &str) -> serde_json::Value {
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
        500..=599 => {
            Some("Server error - this is an issue on Anthropic's side. Please try again later.")
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbacks_preserve_and_validate_state() {
        for input in [
            "  authorization-code#expected-state  ",
            "https://platform.claude.com/oauth/code/callback?code=authorization-code&state=expected-state",
            "?code=authorization-code&state=expected-state",
            "code=authorization-code&state=expected-state",
        ] {
            assert_eq!(parse_code_and_state(input, "expected-state").unwrap(),
                ("authorization-code".into(), "expected-state".into()));
        }
        assert_eq!(
            parse_code_and_state("code=hello%2Bworld&state=expected-state", "expected-state")
                .unwrap()
                .0,
            "hello+world"
        );
        for input in [
            "authorization-code",
            "code=x",
            "x#wrong",
            "x#expected-state#extra",
            "code=x&state=wrong",
        ] {
            assert!(
                parse_code_and_state(input, "expected-state").is_err(),
                "{input}"
            );
        }
    }

    #[cfg(any(
        feature = "blocking",
        all(feature = "async", feature = "reqwest-transport")
    ))]
    fn assert_flow(flow: crate::OAuthFlow, redirect_uri: &str, host: &str) {
        let url = url::Url::parse(&flow.authorization_url).unwrap();
        assert_eq!(url.host_str(), Some(host));
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["redirect_uri"], redirect_uri);
        assert_eq!(params["scope"], SCOPE);
        assert_eq!(params["state"], flow.state);
        assert_eq!(params["code_challenge_method"], "S256");
        let verifier = oauth2::PkceCodeVerifier::new(flow.verifier.clone());
        assert_eq!(
            params["code_challenge"],
            oauth2::PkceCodeChallenge::from_code_verifier_sha256(&verifier).as_str()
        );
        let body = build_token_request(
            "authorization-code",
            &flow.state,
            &flow.verifier,
            &params["client_id"],
            redirect_uri,
        );
        assert_eq!(body["redirect_uri"], redirect_uri);
        assert_eq!(body["state"], flow.state);
        assert_eq!(body["code_verifier"], flow.verifier);
    }

    #[test]
    #[cfg(any(
        feature = "blocking",
        all(feature = "async", feature = "reqwest-transport")
    ))]
    fn authorization_and_exchange_use_the_same_redirect() {
        for config in [
            crate::OAuthConfig::default(),
            crate::OAuthConfig::builder().redirect_port(9123).build(),
        ] {
            for mode in [crate::OAuthMode::Max, crate::OAuthMode::Console] {
                let host = if mode == crate::OAuthMode::Max {
                    "claude.ai"
                } else {
                    "platform.claude.com"
                };
                #[cfg(feature = "blocking")]
                assert_flow(
                    crate::OAuthClient::new(config.clone())
                        .unwrap()
                        .start_flow(mode)
                        .unwrap(),
                    &config.redirect_uri,
                    host,
                );
                #[cfg(all(feature = "async", feature = "reqwest-transport"))]
                assert_flow(
                    crate::AsyncOAuthClient::new(config.clone())
                        .unwrap()
                        .start_flow(mode)
                        .unwrap(),
                    &config.redirect_uri,
                    host,
                );
            }
        }
    }
}
