mod shared;

#[cfg(feature = "blocking")]
mod blocking;
#[cfg(feature = "blocking")]
pub use blocking::OAuthClient;

#[cfg(feature = "async")]
mod r#async;
#[cfg(feature = "async")]
pub use r#async::AsyncOAuthClient;
