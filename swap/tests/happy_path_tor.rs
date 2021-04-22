pub mod harness;

use harness::SlowCancelConfig;
use swap::protocol::{alice, bob};
use tokio::join;

/// Run the following tests with RUST_MIN_STACK=10000000

/// Note: for this test to work, Tor needs to be running with control port 9051
/// and socks5 proxy port on 9050
#[tokio::test]
async fn swap_through_tor() {
    harness::setup_test_with_tor(SlowCancelConfig, |mut ctx| async move {
        let (bob_swap, _) = ctx.bob_swap().await;
        let bob_swap = tokio::spawn(bob::run(bob_swap));

        // Running through tor is slow
        let alice_swap = ctx.alice_next_swap_with_timout(60).await;
        let alice_swap = tokio::spawn(alice::run(alice_swap));

        let (bob_state, alice_state) = join!(bob_swap, alice_swap);

        ctx.assert_alice_redeemed(alice_state??).await;
        ctx.assert_bob_redeemed(bob_state??).await;

        Ok(())
    })
    .await;
}
