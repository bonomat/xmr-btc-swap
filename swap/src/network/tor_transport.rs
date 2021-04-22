use data_encoding::BASE32;
use futures::future::Ready;
use futures::prelude::*;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::core::transport::TransportError;
use libp2p::core::Transport;
use libp2p::tcp::tokio::{Tcp, TcpStream};
use libp2p::tcp::{GenTcpConfig, TcpListenStream, TokioTcpConfig};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::IntoTargetAddr;

/// Represents the configuration for a TCP/IP transport capability for libp2p.
#[derive(Clone)]
pub struct TorTcpConfig {
    inner: GenTcpConfig<Tcp>,
    /// Tor SOCKS5 proxy port number.
    socks_port: u16,
}

impl TorTcpConfig {
    pub fn new(tcp: TokioTcpConfig, socks_port: u16) -> Self {
        Self {
            inner: tcp,
            socks_port,
        }
    }
}

impl Transport for TorTcpConfig {
    type Output = TcpStream;
    type Error = io::Error;
    type Listener = TcpListenStream<Tcp>;
    type ListenerUpgrade = Ready<Result<Self::Output, Self::Error>>;
    #[allow(clippy::type_complexity)]
    type Dial = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        self.inner.listen_on(addr)
    }

    // dials via Tor's socks5 proxy if configured and if the provided address is an
    // onion address. or it falls back to Tcp dialling
    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        async fn do_tor_dial(socks_port: u16, dest: String) -> Result<TcpStream, io::Error> {
            tracing::trace!("Connecting through Tor proxy to address: {}", dest);
            let stream = connect_to_socks_proxy(dest, socks_port)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            tracing::trace!("Connection through Tor established");
            Ok(stream)
        }

        match to_onion_address(addr.clone()) {
            Some(tor_address_string) => {
                Ok(Box::pin(do_tor_dial(self.socks_port, tor_address_string)))
            }
            _ => self.inner.dial(addr),
        }
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.inner.address_translation(listen, observed)
    }
}

/// iterates trhough multi address until we have onion protocol, else return
/// None Tor expects address in form: ADDR.onion:PORT
fn to_onion_address(multi: Multiaddr) -> Option<String> {
    let components = multi.iter();
    for protocol in components {
        match protocol {
            Protocol::Onion(addr, port) => {
                tracing::warn!("Onion service v2 is being deprecated, consider upgrading to v3");
                return Some(format!(
                    "{}.onion:{}",
                    BASE32.encode(addr.as_ref()).to_lowercase(),
                    port
                ));
            }
            Protocol::Onion3(addr) => {
                return Some(format!(
                    "{}.onion:{}",
                    BASE32.encode(addr.hash()).to_lowercase(),
                    addr.port()
                ));
            }
            _ => {
                // ignore
            }
        }
    }
    None
}

/// Connect to the SOCKS5 proxy socket.
async fn connect_to_socks_proxy<'a>(
    dest: impl IntoTargetAddr<'a>,
    port: u16,
) -> Result<TcpStream, tokio_socks::Error> {
    let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let stream = Socks5Stream::connect(sock, dest).await?;
    Ok(TcpStream(stream.into_inner()))
}

#[cfg(test)]
pub mod test {
    use crate::network::tor_transport::to_onion_address;

    #[test]
    fn test_tor_address_string() {
        let address =
            "/onion3/oarchy4tamydxcitaki6bc2v4leza6v35iezmu2chg2bap63sv6f2did:1024/p2p/12D3KooWPD4uHN74SHotLN7VCH7Fm8zZgaNVymYcpeF1fpD2guc9"
        ;
        let address_base32 = to_onion_address(address.parse().unwrap())
            .expect("To be a multi address formatted to base32 ");
        assert_eq!(
            address_base32,
            "oarchy4tamydxcitaki6bc2v4leza6v35iezmu2chg2bap63sv6f2did.onion:1024"
        );
    }
}
