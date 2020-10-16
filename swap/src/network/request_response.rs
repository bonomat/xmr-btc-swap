use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade,
    request_response::{ProtocolName, RequestResponseCodec},
};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, io};

use crate::{bitcoin, monero, SwapParams};

/// Time to wait for a response back once we send a request.
pub const TIMEOUT: u64 = 3600; // One hour.

/// Messages Bob sends to Alice.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BobToAlice {
    AmountsFromBtc(bitcoin::Amount),
    AmountsFromXmr(monero::Amount),
    /* TODO: How are we going to do this when the messages are not Clone?
     * Msg(bob::Message), */
}

/// Messages Alice sends to Bob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AliceToBob {
    Amounts(SwapParams),
    /* TODO: How are we going to do this when the messages are not Clone?
     * Msg(alice::Message) */
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Protocol;

impl ProtocolName for Protocol {
    fn protocol_name(&self) -> &[u8] {
        b"/xmr/btc/1.0.0"
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Codec;

#[async_trait]
impl RequestResponseCodec for Codec {
    type Protocol = Protocol;
    type Request = BobToAlice;
    type Response = AliceToBob;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let message = upgrade::read_one(io, 1024)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut de = serde_json::Deserializer::from_slice(&message);
        let msg = BobToAlice::deserialize(&mut de)?;

        Ok(msg)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let message = upgrade::read_one(io, 1024)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut de = serde_json::Deserializer::from_slice(&message);
        let msg = AliceToBob::deserialize(&mut de)?;

        Ok(msg)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = serde_json::to_vec(&req)?;
        upgrade::write_one(io, &bytes).await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = serde_json::to_vec(&res)?;
        upgrade::write_one(io, &bytes).await?;

        Ok(())
    }
}