//! Console OAuth to create API key (synchronous)
//!
//! This example demonstrates using Console mode OAuth to create an API key
//! that can be used with Anthropic's API.
//!
//! Run with: cargo run --example 02_console_api_key_sync

use anthropic_auth::{OAuthClient, OAuthConfig, OAuthMode};
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    println!("=== Anthropic OAuth - Console API Key Creation (Sync) ===\n");

    let client = OAuthClient::new(OAuthConfig::default())?;

    // Start OAuth flow for Console (API key creation)
    println!("Starting OAuth flow for API key creation...");
    let flow = client.start_flow(OAuthMode::Console)?;

    println!("\n📋 Please visit this URL to authorize:");
    println!("{}\n", flow.authorization_url);

    print!("Paste the authorization response (code#state format): ");
    io::stdout().flush()?;

    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    let response = response.trim();

    println!("\n🔄 Exchanging code for tokens...");
    let tokens = client.exchange_code(response, &flow.state, &flow.verifier)?;

    println!("✅ Got OAuth tokens!");

    println!("\n🔑 Creating API key...");
    let api_key = client.create_api_key(&tokens.access_token)?;

    println!("\n✅ Success!");
    println!("API Key: {}", api_key);
    println!("\n💡 Save this API key securely - it won't be shown again!");
    println!("   You can now use this key with the Anthropic API.");

    Ok(())
}
