//! HTTP transport boundary for the runtime-independent async OAuth client.
use std::{future::Future, pin::Pin};

use crate::Result;

/// An owned POST request. Headers and JSON encoding are supplied by the OAuth client.
///
/// Contains credentials: do not log the headers or body. Transports should not follow
/// redirects to other origins, and must preserve the supplied headers and body.
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP status and complete response body, including bodies of non-success responses.
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A transport operation using the caller's executor.
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send + 'a>>;

/// Executes POST requests without imposing an async runtime or HTTP library.
///
/// Implementations should return HTTP error statuses as responses, not transport
/// errors, so the OAuth client can consistently decode server errors.
pub trait AsyncHttpTransport: Send + Sync {
    fn send(&self, request: HttpRequest) -> TransportFuture<'_>;
}

/// Reusable reqwest adapter. Polling its requests requires a Tokio runtime.
#[cfg(feature = "reqwest-transport")]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "reqwest-transport")]
impl ReqwestTransport {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

#[cfg(feature = "reqwest-transport")]
impl AsyncHttpTransport for ReqwestTransport {
    fn send(&self, request: HttpRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            let mut builder = self.client.post(&request.url);
            for (name, value) in request.headers {
                builder = builder.header(name, value);
            }
            let response = builder.body(request.body).send().await?;
            Ok(HttpResponse {
                status: response.status().as_u16(),
                body: response.bytes().await?.to_vec(),
            })
        })
    }
}

#[cfg(all(test, feature = "reqwest-transport"))]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        time::Duration,
    };

    #[tokio::test]
    async fn reqwest_preserves_wire_data_and_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                headers.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = [0; 2];
            reader.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"{}");
            let headers = headers.to_ascii_lowercase();
            assert!(headers.starts_with("post /token http/1.1\r\n"));
            assert!(headers.contains("user-agent: test-client\r\n"));
            assert!(headers.contains("content-type: application/json\r\n"));
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/never-forward\r\nContent-Length: 8\r\nConnection: close\r\n\r\nredirect").unwrap();
        });
        let response = ReqwestTransport::new()
            .unwrap()
            .send(HttpRequest {
                url: format!("http://{address}/token"),
                headers: vec![
                    ("user-agent".into(), "test-client".into()),
                    ("content-type".into(), "application/json".into()),
                ],
                body: b"{}".to_vec(),
            })
            .await
            .unwrap();
        server.join().unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(response.body, b"redirect");
    }
}
