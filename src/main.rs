use std::net::SocketAddr;
use bytes::Bytes;
use http_body_util::Full;
// use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;
use std::io;
use std::fs::File;
use hyper_util::server::conn::auto::Builder;
use http::{Method, StatusCode};
use hyper::body::Incoming;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};
use std::time::Duration;
use h3_quinn::VarInt;
use hyper::service::Service;
use std::future::Future;
use std::pin::Pin;

#[derive(Clone)]
struct RouteResponse {
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
}

async fn handle_unified_route(path: &str, method: &Method) -> RouteResponse {
    match (method, path) {
        (&Method::GET, "/") => RouteResponse {
            status: StatusCode::OK,
            content_type: "text/html",
            body: Bytes::from("<h1>Welcome to the root page!</h1>"),
        },
        (&Method::GET, "/api/hello") => RouteResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: Bytes::from("{\"message\": \"Hello from API!\"}"),
        },
        (&Method::POST, "/echo") => RouteResponse {
            status: StatusCode::OK,
            content_type: "text/plain",
            body: Bytes::from("Echo endpoint"),
        },
        _ => RouteResponse {
            status: StatusCode::NOT_FOUND,
            content_type: "text/plain",
            body: Bytes::from("404 Not Found"),
        },
    }
}

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let route_response = handle_unified_route(req.uri().path(), req.method()).await;
    
    let response = Response::builder()
        .status(route_response.status)
        .header("alt-svc", "h3=\":4433\"; ma=86400")
        .header("content-type", route_response.content_type)
        .body(Full::from(route_response.body))
        .unwrap();
    
    Ok(response)
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    println!("handling request: {:?}", req);
    
    let route_response = handle_unified_route(req.uri().path(), req.method()).await;

    let response = Response::builder()
        .status(route_response.status)
        .header("alt-svc", "h3=\":4433\"; ma=86400")
        .header("content-type", route_response.content_type)
        .body(())
        .unwrap();

    stream.send_response(response).await?;
    stream.send_data(route_response.body).await?;
    stream.finish().await?;

    println!("response sent successfully");
    Ok(())
}

async fn handle_h3_connection(
    connection: quinn::Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("HTTP/3 connection established from {:?}", connection.remote_address());
    
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
    
    loop {
        match h3_conn.accept().await {
            Ok(Some((req, stream))) => {
                println!("got HTTP/3 request: {:?}", req);
                tokio::spawn(async move {
                    if let Err(e) = handle_request(req, stream).await {
                        println!("failed to handle HTTP/3 request: {}", e);
                    }
                });
            }
            Ok(None) => {
                println!("HTTP/3 connection complete");
                break;
            }
            Err(e) => {
                match e.get_error_level() {
                    ErrorLevel::ConnectionError => {
                        println!("HTTP/3 connection error: {}", e);
                        break;
                    }
                    ErrorLevel::StreamError => {
                        println!("HTTP/3 stream error: {}", e);
                        continue;
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct EchoService;

impl Service<Request<Incoming>> for EchoService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        Box::pin(echo(req))
    }
}

async fn handle_tcp_connection<S>(
    stream: tokio::net::TcpStream,
    tls_acceptor: Arc<TlsAcceptor>,
    service: S,
) where
    S: Service<Request<Incoming>, Response = Response<Full<Bytes>>, Error = hyper::Error> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(tls_stream) => tls_stream,
        Err(err) => {
            eprintln!("failed to perform TLS handshake: {err:#}");
            return;
        }
    };

    let protocol = tls_stream.get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());

    match protocol.as_deref() {
        Some("h2") => println!("Using HTTP/2"),
        Some("http/1.1") => println!("Using HTTP/1.1"),
        _ => println!("Unknown protocol"),
    }

    if let Err(err) = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls_stream), service)
        .await
    {
        eprintln!("Failed to serve connection: {err:#}");
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

fn configure_transport() -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    
    transport_config.max_idle_timeout(Some(VarInt::from_u32(10_000).into())); // 10 seconds
    transport_config.keep_alive_interval(Some(Duration::from_secs(2)));
    transport_config.send_window(VarInt::from_u32(8_000_000).into());
    transport_config.receive_window(VarInt::from_u32(8_000_000));
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(100));
    
    transport_config
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs = load_certs("cert.pem")?;
    let key = load_private_key("key.pem")?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
    
    server_config.alpn_protocols = vec![
        b"h3".to_vec(),
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    
    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_config.clone())));
    let service = EchoService;
    let addr: SocketAddr = ([0, 0, 0, 0], 4433).into();

    let mut h3server_config = quinn::ServerConfig::with_crypto(
        Arc::new(QuicServerConfig::try_from(server_config)?));
    h3server_config.transport_config(Arc::new(configure_transport()));

    let tcp_listener = TcpListener::bind(addr).await?;
    let h3_endpoint = quinn::Endpoint::server(h3server_config, addr)?;
    
    println!("Listening on https://{} (HTTP/3, HTTP/2, HTTP/1.1)", addr);

    loop {
        tokio::select! {
            accept_result = h3_endpoint.accept() => {
                if let Some(connecting) = accept_result {
                    println!("Incoming HTTP/3 connection attempt from {:?}", connecting.remote_address());
                    
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(connection) => {
                                if let Err(e) = handle_h3_connection(connection).await {
                                    println!("HTTP/3 connection error: {}", e);
                                }
                            },
                            Err(e) => {
                                println!("Failed to establish HTTP/3 connection: {}", e);
                            }
                        }
                    });
                }
            }

            tcp_accept_result = tcp_listener.accept() => {
                if let Ok((tcp_stream, _)) = tcp_accept_result {
                    println!("Fallback: accepting TCP connection for HTTP/2 or HTTP/1.1");
                    let tls_acceptor = tls_acceptor.clone();
                    let service = service.clone();
                    
                    tokio::spawn(async move {
                        handle_tcp_connection(tcp_stream, tls_acceptor, service).await;
                    });
                }
            }
        }
    }
}