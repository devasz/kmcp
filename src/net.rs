//! One place that turns an endpoint string (`/path.sock`, `unix:/path`, `tcp:host:port`)
//! into split async halves, with a bounded retry for sockets QEMU is still creating.

use crate::Res;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
pub type Writer = Box<dyn AsyncWrite + Send + Unpin>;

#[derive(Clone, Debug)]
pub enum Endpoint {
    Unix(String),
    Tcp(String),
}

impl Endpoint {
    pub fn parse(s: &str) -> Res<Self> {
        match s.split_once(':') {
            Some(("tcp", addr)) if addr.contains(':') => Ok(Self::Tcp(addr.to_string())),
            Some(("unix", path)) if path.starts_with('/') => Ok(Self::Unix(path.to_string())),
            _ if s.starts_with('/') => Ok(Self::Unix(s.to_string())),
            _ => Err(format!("bad endpoint '{s}': use /abs/path.sock, unix:/abs/path or tcp:host:port")),
        }
    }

    async fn connect_once(&self) -> std::io::Result<(Reader, Writer)> {
        match self {
            Self::Unix(p) => {
                let (r, w) = UnixStream::connect(p).await?.into_split();
                Ok((Box::new(r), Box::new(w)))
            }
            Self::Tcp(a) => {
                let s = TcpStream::connect(a).await?;
                s.set_nodelay(true)?;
                let (r, w) = s.into_split();
                Ok((Box::new(r), Box::new(w)))
            }
        }
    }

    pub async fn connect(&self, wait: Duration) -> Res<(Reader, Writer)> {
        let deadline = Instant::now() + wait;
        loop {
            match self.connect_once().await {
                Ok(halves) => return Ok(halves),
                Err(e) if Instant::now() >= deadline => return Err(format!("connect {self:?}: {e}")),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }
}
