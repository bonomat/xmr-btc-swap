use crate::network::transport;
use crate::protocol::{alice, bob};
use crate::seed::Seed;
use anyhow::Result;
use libp2p::swarm::{NetworkBehaviour, SwarmBuilder};
use libp2p::{PeerId, Swarm};

pub fn alice(seed: &Seed, tor_socks5_port: Option<u16>) -> Result<Swarm<alice::Behaviour>> {
    new(seed, alice::Behaviour::default(), tor_socks5_port)
}

pub fn bob(
    seed: &Seed,
    alice: PeerId,
    tor_socks5_port: Option<u16>,
) -> Result<Swarm<bob::Behaviour>> {
    new(seed, bob::Behaviour::new(alice), tor_socks5_port)
}

fn new<B>(seed: &Seed, behaviour: B, tor_socks5_port: Option<u16>) -> Result<Swarm<B>>
where
    B: NetworkBehaviour,
{
    let identity = seed.derive_libp2p_identity();
    let transport = transport::build(&identity, tor_socks5_port)?;

    let swarm = SwarmBuilder::new(transport, behaviour, identity.public().into_peer_id())
        .executor(Box::new(|f| {
            tokio::spawn(f);
        }))
        .build();

    Ok(swarm)
}
