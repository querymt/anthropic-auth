# anthropic-auth

A Rust library for Anthropic/Claude OAuth 2.0 authentication with PKCE support.

Provides both **synchronous** (blocking) and **asynchronous** (runtime-agnostic) APIs for authenticating with Anthropic's OAuth 2.0 endpoints.

## Features

- ✅ **Sync & Async APIs** - Choose blocking or async based on your needs
- ✅ **Runtime Agnostic** - Async API works with tokio, async-std, smol, etc.
- ✅ **PKCE Support** - Secure SHA-256 PKCE authentication flow
- ✅ **Two OAuth Modes** - Max (subscription) or Console (API key creation)
- ✅ **Fully Configurable** - Custom client IDs, redirect URIs, ports
- ✅ **Browser Integration** - Auto-open browser for authorization (default enabled)
- ✅ **Callback Server** - Optional local server for automatic callback handling
- ✅ **API Key Creation** - Create API keys via Console OAuth
- ✅ **No Token Storage** - You control how/where to persist tokens

## Installation

```toml
[dependencies]
anthropic-auth = "0.1"
```

## Quick Start (Sync API)

### Claude Pro/Max Subscription

```rust
use anthropic_auth::{OAuthClient, OAuthConfig, OAuthMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow(OAuthMode::Max)?;
    
    println!("Visit: {}", flow.authorization_url);
    // User visits URL and gets response in format: "code#state"
    let response = "l0pnTslNFOmTgp28REMrbt4wyLNR25SJePqjk4CAHjoen0TJ#FgE6g_6khGKFFhXAw3tULPM00CPaqgE3Cq6id79Surg";
    
    // Library automatically parses and validates the state
    let tokens = client.exchange_code(response, &flow.state, &flow.verifier)?;
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
    // User authorizes and you receive: "code#state"
    let response = "code123#state456";
    
    let tokens = client.exchange_code(response, &flow.state, &flow.verifier)?;
    
    // Create API key
    let api_key = client.create_api_key(&tokens.access_token)?;
    println!("API Key: {}", api_key);
    
    Ok(())
}
```

## Quick Start (Async API)

```rust
use anthropic_auth::{AsyncOAuthClient, OAuthConfig, OAuthMode};

#[tokio::main]  // or async-std, smol, etc.
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AsyncOAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow(OAuthMode::Max)?;
    
    println!("Visit: {}", flow.authorization_url);
    // User authorizes and you receive: "code#state"
    let response = "code123#state456";
    
    let tokens = client.exchange_code(response, &flow.state, &flow.verifier).await?;
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

- Authorization endpoint: `https://console.anthropic.com/oauth/authorize`
- Creates API keys that can be used independently
- Useful for programmatic access

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `blocking` | Synchronous/blocking API | ✅ Yes |
| `async` | Asynchronous API (runtime-agnostic) | ❌ No |
| `browser` | Auto-open browser for authorization | ✅ Yes |
| `callback-server` | Local server for OAuth callback (requires tokio) | ❌ No |
| `full` | Enable all features | ❌ No |

### Enable async API:

```toml
[dependencies]
anthropic-auth = { version = "0.1", features = ["async"] }
```

### Enable callback server (full automation):

```toml
[dependencies]
anthropic-auth = { version = "0.1", features = ["callback-server"] }
tokio = { version = "1", features = ["full"] }
```

## Custom Configuration

```rust
use anthropic_auth::{OAuthClient, OAuthConfig};

let config = OAuthConfig::builder()
    .client_id("my-client-id")
    .redirect_port(8080)  // Custom port
    .build();

let client = OAuthClient::new(config)?;
```

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

Anthropic returns authorization responses in the format `code#state`. The library parses this automatically and validates the state for CSRF protection:

```rust
// User receives: "abc123#xyz789"
// Library parses it and validates state matches flow.state
let tokens = client.exchange_code("abc123#xyz789", &flow.state, &flow.verifier)?;

// Or if you've already separated them:
let tokens = client.exchange_code("abc123", &flow.state, &flow.verifier)?;
```

**Important:** The state parameter is used for CSRF protection. The library validates that the state returned by Anthropic matches the state originally sent in the authorization URL.

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

### Async API (runtime-agnostic)

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

## Token Storage

This library intentionally does **not** handle token persistence. You should store tokens securely based on your application's needs.

Recommended approaches:
- **System Keychain**: Use [`keyring`](https://crates.io/crates/keyring) crate
- **Encrypted Files**: Encrypt tokens before writing to disk
- **Environment Variables**: For development/testing only
