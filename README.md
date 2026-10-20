# anthropic-auth

A Rust library for Anthropic/Claude OAuth 2.0 authentication with PKCE support.

Provides both **synchronous** (blocking) and **asynchronous** (transport-independent) APIs for authenticating with Anthropic's OAuth 2.0 endpoints.

## Features

- ✅ **Sync & Async APIs** - Choose blocking or async based on your needs
- **Transport-independent Async I/O** - Inject your own HTTP transport for any runtime, or use the optional reqwest adapter with Tokio
- ✅ **PKCE Support** - Secure SHA-256 PKCE authentication flow
- ✅ **Two OAuth Modes** - Max (subscription) or Console (API key creation)
- ✅ **Fully Configurable** - Custom client IDs, redirect URIs, ports
- **Browser Integration** - Optional `open_browser` helper (feature enabled by default)
- ✅ **Callback Server** - Optional local server for automatic callback handling
- ✅ **API Key Creation** - Create API keys via Console OAuth
- ✅ **No Token Storage** - You control how/where to persist tokens

## Installation

```toml
[dependencies]
anthropic-auth = "0.2"
```

## Changes in 0.2.0

- Update OAuth token exchange, Console authorization, and the hosted callback to `platform.claude.com`.
- Match the working OAuth scopes and token request headers.
- Honor `OAuthConfig.redirect_uri` consistently during authorization and token exchange.
- Add injectable async HTTP transports; `async` alone no longer depends on reqwest or Tokio. Existing default-feature callers retain the reqwest convenience constructor.
- Accept `code#state`, full callback URLs, and query strings; trim input and validate returned state.
- Breaking change: bare authorization codes are rejected. Pass the complete response containing both code and state.
- The default redirect is the hosted code callback, not localhost. The optional local callback server only works with a supported loopback redirect configured explicitly.

## Quick Start (Sync API)

### Claude Pro/Max Subscription

```rust
use anthropic_auth::{OAuthClient, OAuthConfig, OAuthMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow(OAuthMode::Max)?;
    
    println!("Visit: {}", flow.authorization_url);
    // Authorize in the browser, then paste the complete response (code#state or URL).
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    
    // Library automatically parses and validates the state
    let tokens = client.exchange_code(&response, &flow.state, &flow.verifier)?;
    println!("Got access token!");
    
    // Later, refresh if needed
    if tokens.is_expired() {
        let new_tokens = client.refresh_token(&tokens.refresh_token)?;
    }
    
    Ok(())
}
```

### API Key Creation

```rust
use anthropic_auth::{OAuthClient, OAuthConfig, OAuthMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow(OAuthMode::Console)?;
    
    println!("Visit: {}", flow.authorization_url);
    // Authorize in the browser, then paste the complete response (code#state or URL).
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    
    let tokens = client.exchange_code(&response, &flow.state, &flow.verifier)?;
    
    // Create API key
    let api_key = client.create_api_key(&tokens.access_token)?;
    // Store api_key securely; avoid printing credentials.
    println!("API key created successfully.");
    
    Ok(())
}
```

## Quick Start (Async API with reqwest)

This example uses the convenience reqwest adapter and Tokio. For other runtimes, use `AsyncOAuthClient::with_transport` as described in [Custom Async Transports](#custom-async-transports).

```rust
use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow(OAuthMode::Max)?;
    
    println!("Visit: {}", flow.authorization_url);
    // Authorize in the browser, then paste the complete response (code#state or URL).
    let mut response = String::new();
    let response = tokio::task::spawn_blocking(move || {
        std::io::stdin().read_line(&mut response).map(|_| response)
    }).await??;
    
    let tokens = client.exchange_code(&response, &flow.state, &flow.verifier).await?;
    println!("Got access token!");
    
    Ok(())
}
```

## OAuth Modes

### Max Mode (Claude Pro/Max Subscription)

Use this mode if you have a Claude Pro or Claude Max subscription:

```rust
let flow = client.start_flow(OAuthMode::Max)?;
```

- Authorization endpoint: `https://claude.ai/oauth/authorize`
- Provides access tokens for Claude API with your subscription
- Best for personal use with existing subscription

### Console Mode (API Key Creation)

Use this mode to create API keys programmatically:

```rust
let flow = client.start_flow(OAuthMode::Console)?;
// ... get tokens ...
let api_key = client.create_api_key(&tokens.access_token)?;
```

- Authorization endpoint: `https://platform.claude.com/oauth/authorize`
- Creates API keys that can be used independently
- Useful for programmatic access

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `blocking` | Synchronous/blocking API | ✅ Yes |
| `async` | Transport-independent asynchronous API | No |
| `reqwest-transport` | Reqwest adapter and async `new` constructor (requires Tokio at runtime) | Yes, via `blocking` / `rustls-tls` |
| `browser` | Exposes the `open_browser` helper; does not open a browser automatically | Yes |
| `callback-server` | Local server for OAuth callback (requires tokio) | ❌ No |
| `rustls-tls` | HTTPS using rustls | Yes |
| `native-tls` | HTTPS using the platform TLS implementation | No |
| `full` | Blocking, async, browser, callback server, and rustls TLS | No |

### Enable async API:

```toml
[dependencies]
anthropic-auth = { version = "0.2", default-features = false, features = ["async", "rustls-tls"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The async quick start requires these dependencies. Selecting `rustls-tls` or `native-tls` enables the reqwest adapter and HTTPS. For an injected transport, enable only `async` and configure HTTPS in your own HTTP client.

### Enable the optional local callback server

```toml
[dependencies]
anthropic-auth = { version = "0.2", features = ["callback-server"] }
tokio = { version = "1", features = ["full"] }
```

The default redirect is `https://platform.claude.com/oauth/code/callback`. It displays an authorization response to paste into your application; it does not redirect to the local callback server. Enabling `callback-server` alone does not change this flow. Use `run_callback_server` only with a loopback redirect accepted by Anthropic for your client ID.

## Custom Async Transports

To use a runtime other than Tokio, disable default features and enable only `async`:

```toml
[dependencies]
anthropic-auth = { version = "0.2", default-features = false, features = ["async"] }
```

This configuration does not pull in reqwest or Tokio. Implement `AsyncHttpTransport` using your application's HTTP client, then pass it to `AsyncOAuthClient::with_transport(config, transport)`. The protocol logic and validation are identical to the reqwest-backed path.

```rust
use anthropic_auth::{AsyncOAuthClient, OAuthConfig, Result};
use anthropic_auth::transport::{AsyncHttpTransport, HttpRequest, TransportFuture};

struct AppTransport;

impl AsyncHttpTransport for AppTransport {
    fn send(&self, request: HttpRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            // Execute a POST using your runtime's HTTP client and return
            // HttpResponse { status, body }, including non-2xx responses.
            // This placeholder deliberately performs no network I/O.
            let _ = request;
            Err(anthropic_auth::AnthropicAuthError::Transport(Box::new(
                std::io::Error::new(std::io::ErrorKind::Unsupported, "connect your HTTP client here"),
            )))
        })
    }
}

let client = AsyncOAuthClient::with_transport(OAuthConfig::default(), AppTransport)?;
```

`HttpRequest` contains the URL, complete headers, and serialized JSON body. Preserve those values, do not log credentials, and do not forward them across redirects. Return transport failures as `AnthropicAuthError::Transport`; server HTTP statuses remain `HttpResponse` values so this crate can decode errors consistently. Transport implementations must be `Send + Sync`, and their futures must be `Send`.

With `reqwest-transport` enabled, `AsyncOAuthClient::new(config)` remains the convenience constructor. It reuses a reqwest connection pool and disables redirects. The optional Axum callback server remains Tokio-specific and is independent of the injected transport.

## Custom Configuration

```rust
use anthropic_auth::{OAuthClient, OAuthConfig};

let config = OAuthConfig::builder()
    .client_id("my-client-id")
    .redirect_port(8080)  // Custom port
    .build();

let client = OAuthClient::new(config)?;
```

Custom redirect URIs must be accepted by Anthropic for the configured client ID. Setting `redirect_port` does not register a redirect URI or start a server. Both authorization and token exchange use the configured URI.

## Examples

See the `examples/` directory for complete working examples:

- `max_subscription_sync.rs` - Claude Pro/Max OAuth (sync)
- `console_api_key_sync.rs` - API key creation (sync)

Run examples with:

```bash
cargo run --example max_subscription_sync
cargo run --example console_api_key_sync
```

## Authorization Response Format

Pass the complete authorization response to `exchange_code`. Supported formats are:

- `authorization-code#returned-state`
- A full callback URL with `code` and `state` query parameters
- `code=authorization-code&state=returned-state`, optionally prefixed with `?`

Leading and trailing whitespace is trimmed. Query parameters are URL-decoded, and the returned state must match `flow.state`.

```rust
// If your callback handler has already extracted code and returned_state:
let response = format!("{}#{}", code, returned_state);
let tokens = client.exchange_code(&response, &flow.state, &flow.verifier)?;
```

**Migrating from 0.1:** Bare authorization codes are no longer accepted. Preserve the state returned by Anthropic rather than discarding it or substituting the expected state. Missing or mismatched state is rejected before token exchange.

## API Overview

### Sync API (blocking)

```rust
let client = OAuthClient::new(config)?;

// Start flow (generates PKCE and state, returns auth URL)
let flow = client.start_flow(OAuthMode::Max)?;

// Exchange code for tokens (parses "code#state" format automatically)
let tokens = client.exchange_code("code#state", &flow.state, &flow.verifier)?;

// Refresh expired tokens
let new_tokens = client.refresh_token(&tokens.refresh_token)?;

// Create API key (Console mode only)
let api_key = client.create_api_key(&tokens.access_token)?;
```

### Async API (reqwest convenience adapter)

```rust
let client = AsyncOAuthClient::new(config)?;

// Start flow (still sync - no I/O)
let flow = client.start_flow(OAuthMode::Max)?;

// Async methods
let tokens = client.exchange_code("code#state", &flow.state, &flow.verifier).await?;
let new_tokens = client.refresh_token(&tokens.refresh_token).await?;
let api_key = client.create_api_key(&tokens.access_token).await?;
```

### Browser Integration

```rust
use anthropic_auth::open_browser;

let flow = client.start_flow(OAuthMode::Max)?;
open_browser(&flow.authorization_url)?;  // Opens user's default browser
```

## Scope and Inference Integration

This crate handles authorization, token exchange, refresh, and Console API-key creation. It does not send inference requests or apply the OAuth-specific headers, system blocks, and tool-name transformations an inference client may require. Obtaining a subscription token alone does not make a standard API-key client compatible with subscription inference.

It uses Anthropic's existing OAuth client ID by default. Endpoint behavior, supported redirects, account eligibility, and subscription policies are controlled by Anthropic and can change. Third-party subscription access should not be assumed to be officially supported.

## Token Storage

This library intentionally does **not** handle token persistence. You should store tokens securely based on your application's needs.

Persist the entire `TokenSet` returned by both exchange and refresh, including the latest refresh token. Coordinate concurrent refreshes in your application so requests do not race while rotating credentials. `is_expired()` includes a five-minute expiry buffer.

Recommended approaches:
- **System Keychain**: Use [`keyring`](https://crates.io/crates/keyring) crate
- **Encrypted Files**: Encrypt tokens before writing to disk
- **Environment Variables**: For development/testing only
