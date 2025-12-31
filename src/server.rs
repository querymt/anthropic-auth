use axum::{
    extract::Query,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::{AnthropicAuthError, Result};

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

struct ServerState {
    tx: tokio::sync::Mutex<Option<oneshot::Sender<Result<CallbackData>>>>,
    expected_state: String,
}

#[derive(Debug)]
pub struct CallbackData {
    pub code: String,
    pub state: String,
}

/// Run a local OAuth callback server
///
/// This starts a local HTTP server that listens for the OAuth callback.
/// When the callback is received, it extracts the authorization code and state,
/// validates the state, and returns the callback data.
///
/// **Note:** This feature requires tokio and is only available when the
/// `callback-server` feature is enabled.
///
/// # Arguments
///
/// * `port` - The port to listen on (e.g., 1455)
/// * `expected_state` - The CSRF state token to validate against
///
/// # Returns
///
/// A `CallbackData` struct containing the authorization code and state
///
/// # Errors
///
/// Returns an error if:
/// - The server fails to start
/// - An OAuth error is received
/// - The state token doesn't match
/// - The callback times out
///
/// # Example
///
/// ```no_run
/// use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode, run_callback_server};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = AsyncOAuthClient::new(OAuthConfig::default())?;
/// let flow = client.start_flow(OAuthMode::Max)?;
///
/// // Start callback server in background
/// let callback_future = run_callback_server(1455, &flow.state);
///
/// println!("Visit: {}", flow.authorization_url);
///
/// // Wait for callback
/// let callback = callback_future.await?;
/// let tokens = client.exchange_code(&callback.code, &callback.state, &flow.verifier).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run_callback_server(port: u16, expected_state: &str) -> Result<CallbackData> {
    let (tx, rx) = oneshot::channel();

    let state = Arc::new(ServerState {
        tx: tokio::sync::Mutex::new(Some(tx)),
        expected_state: expected_state.to_string(),
    });

    let app = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        AnthropicAuthError::CallbackServer(format!("Failed to bind to {}: {}", addr, e))
    })?;

    // Spawn server task
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Server failed to start");
    });

    // Wait for callback
    match rx.await {
        Ok(Ok(callback_data)) => Ok(callback_data),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AnthropicAuthError::CallbackServer(
            "Server shut down unexpectedly".to_string(),
        )),
    }
}

async fn handle_callback(
    Query(params): Query<CallbackQuery>,
    axum::extract::State(state): axum::extract::State<Arc<ServerState>>,
) -> impl IntoResponse {
    // Check for OAuth errors
    if let Some(error) = params.error {
        let _ = state.tx.lock().await.take().map(|tx| {
            tx.send(Err(AnthropicAuthError::OAuth(format!(
                "OAuth error: {}",
                error
            ))))
        });
        return Html(format!(
            r#"
            <html>
                <head><title>Authorization Failed</title></head>
                <body>
                    <h1>Authorization Failed</h1>
                    <p>Error: {}</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            "#,
            error
        ));
    }

    // Validate state
    let received_state = params.state.as_deref().unwrap_or("");
    if received_state != state.expected_state {
        let _ = state.tx.lock().await.take().map(|tx| {
            tx.send(Err(AnthropicAuthError::OAuth(
                "State mismatch - possible CSRF attack".to_string(),
            )))
        });
        return Html(
            r#"
            <html>
                <head><title>Authorization Failed</title></head>
                <body>
                    <h1>Authorization Failed</h1>
                    <p>Security validation failed. Please try again.</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            "#
            .to_string(),
        );
    }

    // Extract code
    match params.code {
        Some(code) => {
            let _ = state.tx.lock().await.take().map(|tx| {
                tx.send(Ok(CallbackData {
                    code: code.clone(),
                    state: received_state.to_string(),
                }))
            });
            Html(
                r#"
                <html>
                    <head><title>Authorization Successful</title></head>
                    <body>
                        <h1>Authorization Successful!</h1>
                        <p>You have successfully authorized the application.</p>
                        <p>You can close this window and return to the terminal.</p>
                    </body>
                </html>
                "#
                .to_string(),
            )
        }
        None => {
            let _ = state
                .tx
                .lock()
                .await
                .take()
                .map(|tx| tx.send(Err(AnthropicAuthError::InvalidAuthorizationCode)));
            Html(
                r#"
                <html>
                    <head><title>Authorization Failed</title></head>
                    <body>
                        <h1>Authorization Failed</h1>
                        <p>No authorization code received.</p>
                        <p>You can close this window.</p>
                    </body>
                </html>
                "#
                .to_string(),
            )
        }
    }
}
