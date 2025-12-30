//! Claude Pro/Max subscription OAuth flow (synchronous)
//!
//! This example demonstrates OAuth authentication for Claude Pro/Max subscription.
//! Uses blocking I/O, no async runtime required.
//!
//! Run with: cargo run --example 01_max_subscription_sync

use anthropic_auth::{open_browser, OAuthClient, OAuthConfig, OAuthMode};
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    println!("=== Anthropic OAuth - Claude Pro/Max (Sync) ===\n");

    let client = OAuthClient::new(OAuthConfig::default())?;

    // Start OAuth flow for Max subscription
    println!("Starting OAuth flow for Claude Pro/Max...");
    let flow = client.start_flow(OAuthMode::Max)?;

    println!("🌐 Opening browser for authorization...");

    // Automatically open browser
    match open_browser(&flow.authorization_url) {
        Ok(_) => println!("✅ Browser opened! Please authorize in your browser."),
        Err(e) => {
            println!("⚠️  Could not open browser: {}", e);
            println!("Please manually visit: {}", flow.authorization_url);
        }
    }

    print!("Paste the authorization response (code#state format): ");
    io::stdout().flush()?;

    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    let response = response.trim();

    println!("\n🔄 Exchanging code for tokens...");
    let tokens = client.exchange_code(response, &flow.state, &flow.verifier)?;

    println!("\n✅ Success!");
    println!(
        "Access token: {}...",
        &tokens.access_token[..30.min(tokens.access_token.len())]
    );
    println!(
        "Refresh token: {}...",
        &tokens.refresh_token[..30.min(tokens.refresh_token.len())]
    );
    println!("Expires in: {:?}", tokens.expires_in());

    println!("\n💡 Tip: Save these tokens securely to avoid re-authentication!");

    Ok(())
}
