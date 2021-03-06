pub use alice::Alice;
pub use bob::Bob;

use anyhow::{anyhow, bail, Context, Result};
use itertools::Itertools;
use libp2p::PeerId;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

mod alice;
mod bob;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum Swap {
    Alice(Alice),
    Bob(Bob),
}

impl From<Alice> for Swap {
    fn from(from: Alice) -> Self {
        Swap::Alice(from)
    }
}

impl From<Bob> for Swap {
    fn from(from: Bob) -> Self {
        Swap::Bob(from)
    }
}

impl Display for Swap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Swap::Alice(alice) => Display::fmt(alice, f),
            Swap::Bob(bob) => Display::fmt(bob, f),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq)]
#[error("Not in the role of Alice")]
struct NotAlice;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq)]
#[error("Not in the role of Bob")]
struct NotBob;

impl Swap {
    pub fn try_into_alice(self) -> Result<Alice> {
        match self {
            Swap::Alice(alice) => Ok(alice),
            Swap::Bob(_) => bail!(NotAlice),
        }
    }

    pub fn try_into_bob(self) -> Result<Bob> {
        match self {
            Swap::Bob(bob) => Ok(bob),
            Swap::Alice(_) => bail!(NotBob),
        }
    }
}

pub struct Database {
    swaps: sled::Tree,
    peers: sled::Tree,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        tracing::debug!("Opening database at {}", path.display());

        let db =
            sled::open(path).with_context(|| format!("Could not open the DB at {:?}", path))?;

        let swaps = db.open_tree("swaps")?;
        let peers = db.open_tree("peers")?;

        Ok(Database { swaps, peers })
    }

    pub async fn insert_peer_id(&self, swap_id: Uuid, peer_id: PeerId) -> Result<()> {
        let peer_id_str = peer_id.to_string();

        let key = serialize(&swap_id)?;
        let value = serialize(&peer_id_str).context("Could not serialize peer-id")?;

        self.peers.insert(key, value)?;

        self.peers
            .flush_async()
            .await
            .map(|_| ())
            .context("Could not flush db")
    }

    pub fn get_peer_id(&self, swap_id: Uuid) -> Result<PeerId> {
        let key = serialize(&swap_id)?;

        let encoded = self
            .peers
            .get(&key)?
            .ok_or_else(|| anyhow!("No peer-id found for swap id {} in database", swap_id))?;

        let peer_id: String = deserialize(&encoded).context("Could not deserialize peer-id")?;
        Ok(PeerId::from_str(peer_id.as_str())?)
    }

    pub async fn insert_latest_state(&self, swap_id: Uuid, state: Swap) -> Result<()> {
        let key = serialize(&swap_id)?;
        let new_value = serialize(&state).context("Could not serialize new state value")?;

        let old_value = self.swaps.get(&key)?;

        self.swaps
            .compare_and_swap(key, old_value, Some(new_value))
            .context("Could not write in the DB")?
            .context("Stored swap somehow changed, aborting saving")?;

        self.swaps
            .flush_async()
            .await
            .map(|_| ())
            .context("Could not flush db")
    }

    pub fn get_state(&self, swap_id: Uuid) -> Result<Swap> {
        let key = serialize(&swap_id)?;

        let encoded = self
            .swaps
            .get(&key)?
            .ok_or_else(|| anyhow!("Swap with id {} not found in database", swap_id))?;

        let state = deserialize(&encoded).context("Could not deserialize state")?;
        Ok(state)
    }

    pub fn all_alice(&self) -> Result<Vec<(Uuid, Alice)>> {
        self.all_alice_iter().collect()
    }

    fn all_alice_iter(&self) -> impl Iterator<Item = Result<(Uuid, Alice)>> {
        self.all_swaps_iter().map(|item| {
            let (swap_id, swap) = item?;
            Ok((swap_id, swap.try_into_alice()?))
        })
    }

    pub fn all_bob(&self) -> Result<Vec<(Uuid, Bob)>> {
        self.all_bob_iter().collect()
    }

    fn all_bob_iter(&self) -> impl Iterator<Item = Result<(Uuid, Bob)>> {
        self.all_swaps_iter().map(|item| {
            let (swap_id, swap) = item?;
            Ok((swap_id, swap.try_into_bob()?))
        })
    }

    fn all_swaps_iter(&self) -> impl Iterator<Item = Result<(Uuid, Swap)>> {
        self.swaps.iter().map(|item| {
            let (key, value) = item.context("Failed to retrieve swap from DB")?;

            let swap_id = deserialize::<Uuid>(&key)?;
            let swap = deserialize::<Swap>(&value).context("Failed to deserialize swap")?;

            Ok((swap_id, swap))
        })
    }

    pub fn unfinished_alice(&self) -> Result<Vec<(Uuid, Alice)>> {
        self.all_alice_iter()
            .filter_ok(|(_swap_id, alice)| !matches!(alice, Alice::Done(_)))
            .collect()
    }
}

pub fn serialize<T>(t: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    Ok(serde_cbor::to_vec(t)?)
}

pub fn deserialize<T>(v: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    Ok(serde_cbor::from_slice(&v)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::alice::{Alice, AliceEndState};
    use crate::database::bob::{Bob, BobEndState};

    #[tokio::test]
    async fn can_write_and_read_to_multiple_keys() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();

        let state_1 = Swap::Alice(Alice::Done(AliceEndState::BtcRedeemed));
        let swap_id_1 = Uuid::new_v4();
        db.insert_latest_state(swap_id_1, state_1.clone())
            .await
            .expect("Failed to save second state");

        let state_2 = Swap::Bob(Bob::Done(BobEndState::SafelyAborted));
        let swap_id_2 = Uuid::new_v4();
        db.insert_latest_state(swap_id_2, state_2.clone())
            .await
            .expect("Failed to save first state");

        let recovered_1 = db
            .get_state(swap_id_1)
            .expect("Failed to recover first state");

        let recovered_2 = db
            .get_state(swap_id_2)
            .expect("Failed to recover second state");

        assert_eq!(recovered_1, state_1);
        assert_eq!(recovered_2, state_2);
    }

    #[tokio::test]
    async fn can_write_twice_to_one_key() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();

        let state = Swap::Alice(Alice::Done(AliceEndState::SafelyAborted));

        let swap_id = Uuid::new_v4();
        db.insert_latest_state(swap_id, state.clone())
            .await
            .expect("Failed to save state the first time");
        let recovered = db
            .get_state(swap_id)
            .expect("Failed to recover state the first time");

        // We insert and recover twice to ensure database implementation allows the
        // caller to write to an existing key
        db.insert_latest_state(swap_id, recovered)
            .await
            .expect("Failed to save state the second time");
        let recovered = db
            .get_state(swap_id)
            .expect("Failed to recover state the second time");

        assert_eq!(recovered, state);
    }

    #[tokio::test]
    async fn all_swaps_as_alice() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();

        let alice_state = Alice::Done(AliceEndState::BtcPunished);
        let alice_swap = Swap::Alice(alice_state.clone());
        let alice_swap_id = Uuid::new_v4();
        db.insert_latest_state(alice_swap_id, alice_swap)
            .await
            .expect("Failed to save alice state 1");

        let alice_swaps = db.all_alice().unwrap();
        assert_eq!(alice_swaps.len(), 1);
        assert!(alice_swaps.contains(&(alice_swap_id, alice_state)));

        let bob_state = Bob::Done(BobEndState::SafelyAborted);
        let bob_swap = Swap::Bob(bob_state);
        let bob_swap_id = Uuid::new_v4();
        db.insert_latest_state(bob_swap_id, bob_swap)
            .await
            .expect("Failed to save bob state 1");

        let err = db.all_alice().unwrap_err();

        assert_eq!(err.downcast_ref::<NotAlice>().unwrap(), &NotAlice);
    }

    #[tokio::test]
    async fn all_swaps_as_bob() {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();

        let bob_state = Bob::Done(BobEndState::SafelyAborted);
        let bob_swap = Swap::Bob(bob_state.clone());
        let bob_swap_id = Uuid::new_v4();
        db.insert_latest_state(bob_swap_id, bob_swap)
            .await
            .expect("Failed to save bob state 1");

        let bob_swaps = db.all_bob().unwrap();
        assert_eq!(bob_swaps.len(), 1);
        assert!(bob_swaps.contains(&(bob_swap_id, bob_state)));

        let alice_state = Alice::Done(AliceEndState::BtcPunished);
        let alice_swap = Swap::Alice(alice_state);
        let alice_swap_id = Uuid::new_v4();
        db.insert_latest_state(alice_swap_id, alice_swap)
            .await
            .expect("Failed to save alice state 1");

        let err = db.all_bob().unwrap_err();

        assert_eq!(err.downcast_ref::<NotBob>().unwrap(), &NotBob);
    }

    #[tokio::test]
    async fn can_save_swap_state_and_peer_id_with_same_swap_id() -> Result<()> {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();

        let alice_id = Uuid::new_v4();
        let alice_state = Alice::Done(AliceEndState::BtcPunished);
        let alice_swap = Swap::Alice(alice_state);
        let peer_id = PeerId::random();

        db.insert_latest_state(alice_id, alice_swap.clone()).await?;
        db.insert_peer_id(alice_id, peer_id).await?;

        let loaded_swap = db.get_state(alice_id)?;
        let loaded_peer_id = db.get_peer_id(alice_id)?;

        assert_eq!(alice_swap, loaded_swap);
        assert_eq!(peer_id, loaded_peer_id);

        Ok(())
    }

    #[tokio::test]
    async fn test_reopen_db() -> Result<()> {
        let db_dir = tempfile::tempdir().unwrap();
        let alice_id = Uuid::new_v4();
        let alice_state = Alice::Done(AliceEndState::BtcPunished);
        let alice_swap = Swap::Alice(alice_state);

        let peer_id = PeerId::random();

        {
            let db = Database::open(db_dir.path()).unwrap();
            db.insert_latest_state(alice_id, alice_swap.clone()).await?;
            db.insert_peer_id(alice_id, peer_id).await?;
        }

        let db = Database::open(db_dir.path()).unwrap();

        let loaded_swap = db.get_state(alice_id)?;
        let loaded_peer_id = db.get_peer_id(alice_id)?;

        assert_eq!(alice_swap, loaded_swap);
        assert_eq!(peer_id, loaded_peer_id);

        Ok(())
    }
}
