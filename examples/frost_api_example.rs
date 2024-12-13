// This code demonstrates the FROST protocol using the `frost_dalek` library, focusing on API behavior
// and error handling. It includes distributed key generation, precomputation, partial signing,
// signature aggregation, and verification.

use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, Parameters,
    Participant, SignatureAggregator,
};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ------------------------------------------------------------
    // ------------ Usage
    // ------------------------------------------------------------

    // Define parameters
    let params = Parameters { t: 2, n: 3 };

    // ------------------------------------------------------------
    // ------------ Distributed key generation
    // ------------------------------------------------------------

    // Distributed key generation
    let (alice, alice_coefficients) = Participant::new(&params, 1);
    let (bob, bob_coefficients) = Participant::new(&params, 2);
    let (carol, carol_coefficients) = Participant::new(&params, 3);

    // Verify zk proof of secret keys
    alice
        .proof_of_secret_key
        .verify(&alice.index, &alice.public_key().unwrap())
        .map_err(|_| "Alice's proof of secret key verification failed")?;
    bob.proof_of_secret_key
        .verify(&bob.index, &bob.public_key().unwrap())
        .map_err(|_| "Bob's proof of secret key verification failed")?;
    carol
        .proof_of_secret_key
        .verify(&carol.index, &carol.public_key().unwrap())
        .map_err(|_| "Carol's proof of secret key verification failed")?;

    println!("All participants verified their proofs of secret keys!");

    // Alice enters round one of the distributed key generation protocol:
    let mut alice_other_participants: Vec<Participant> = vec![bob.clone(), carol.clone()];
    let alice_state = DistributedKeyGeneration::<_>::new(
        &params,
        &alice.index,
        &alice_coefficients,
        &mut alice_other_participants,
    )
    .map_err(|err| format!("DistributedKeyGeneration failed for Alice: {:?}", err))?;

    // Alice collect secret shares
    let alice_their_secret_shares = alice_state
        .their_secret_shares()
        .map_err(|_| "Alice secret shares failed")?;

    // Bob does the same:
    let mut bob_other_participants: Vec<Participant> = vec![alice.clone(), carol.clone()];
    let bob_state = DistributedKeyGeneration::<_>::new(
        &params,
        &bob.index,
        &bob_coefficients,
        &mut bob_other_participants,
    )
    .map_err(|err| format!("DistributedKeyGeneration failed for Bob: {:?}", err))?;

    let bob_their_secret_shares = bob_state
        .their_secret_shares()
        .map_err(|_| "Bob secret shares failed")?;

    // Carol does the same:
    let mut carol_other_participants: Vec<Participant> = vec![alice.clone(), bob.clone()];
    let carol_state = DistributedKeyGeneration::<_>::new(
        &params,
        &carol.index,
        &carol_coefficients,
        &mut carol_other_participants,
    )
    .map_err(|err| format!("DistributedKeyGeneration failed for Carol: {:?}", err))?;

    let carol_their_secret_shares = carol_state
        .their_secret_shares()
        .map_err(|_| "Carol secret shares failed")?;

    // Each participant vector of secret shares given to them by the other participants:
    let alice_my_secret_shares = vec![
        bob_their_secret_shares[0].clone(),
        carol_their_secret_shares[0].clone(),
    ];
    let bob_my_secret_shares = vec![
        alice_their_secret_shares[0].clone(),
        carol_their_secret_shares[1].clone(),
    ];
    let carol_my_secret_shares = vec![
        alice_their_secret_shares[1].clone(),
        bob_their_secret_shares[1].clone(),
    ];

    // The participants then use these secret shares from the other participants to advance to round two of the distributed key generation protocol

    let alice_state = alice_state
        .to_round_two(alice_my_secret_shares)
        .map_err(|_| "Alice state failed")?;
    let bob_state = bob_state
        .to_round_two(bob_my_secret_shares)
        .map_err(|_| "Bob state failed")?;
    let carol_state = carol_state
        .to_round_two(carol_my_secret_shares)
        .map_err(|_| "Carol state failed")?;

    // Derive the long-lived, personal secret keys and the group’s public key for each participant.
    // They should all derive the same group public key. They also derive their IndividualPublicKeys from their IndividualSecretKeys.

    let (alice_group_key, alice_secret_key) = alice_state
        .finish(alice.public_key().unwrap())
        .map_err(|_| "Alice group key failed")?;
    let (bob_group_key, _bob_secret_key) = bob_state
        .finish(bob.public_key().unwrap())
        .map_err(|_| "Bob group key failed")?;
    let (carol_group_key, carol_secret_key) = carol_state
        .finish(carol.public_key().unwrap())
        .map_err(|_| "Carol group key failed")?;

    // Ensure all participants derive the same group key
    assert!(alice_group_key == bob_group_key);
    assert!(carol_group_key == bob_group_key);

    let alice_public_key = alice_secret_key.to_public();
    let _bob_public_key = _bob_secret_key.to_public();
    let carol_public_key = carol_secret_key.to_public();

    // ------------------------------------------------------------
    // ------------ Precomputation and Partial Signatures
    // ------------------------------------------------------------

    // Alice, Bob, and Carol can create partial threshold signatures over an agreed upon message with their respective secret keys,
    // which they can then give to an untrusted SignatureAggregator
    // To do this, they each pre-compute (using generate_commitment_share_lists) and publish a list of commitment shares.

    let (alice_public_comshares, mut alice_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, 1, 1);
    let (_bob_public_comshares, mut _bob_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, 2, 1);
    let (carol_public_comshares, mut carol_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, 3, 1);

    let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
    let message = b"This is a test of the tsunami alert system. This is only a test.";

    // Every signer should compute a hash of the message to be signed, along with, optionally,
    // some additional context, such as public information about the run of the protocol.
    let message_hash = compute_message_hash(&context[..], &message[..]);

    let mut aggregator =
        SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);

    // The aggregator takes note of each expected signer for this run of the protocol.
    // For this run, we’ll have Alice and Carol sign.

    aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
    aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);

    // The aggregator should then publicly announce which participants are expected to be signers.
    let signers = aggregator.get_signers();

    println!("Signers should be:");
    for signer in signers {
        println!("Participant Index: {:?}", signer.participant_index);
    }

    // Alice and Carol each then compute their partial signatures, and send these to the signature aggregator.

    let alice_partial = alice_secret_key.sign(
        &message_hash,
        &alice_group_key,
        &mut alice_secret_comshares,
        0,
        signers,
    )?;
    let carol_partial = carol_secret_key.sign(
        &message_hash,
        &carol_group_key,
        &mut carol_secret_comshares,
        0,
        signers,
    )?;

    aggregator.include_partial_signature(alice_partial);
    aggregator.include_partial_signature(carol_partial);

    // ------------------------------------------------------------
    // ------------ Signature Aggregation
    // ------------------------------------------------------------

    // The aggregator attempts to finalize its state, ensuring that there are no errors thus far in the partial signature
    let aggregator = aggregator
        .finalize()
        .map_err(|err| format!("Error: {:?}", err))?;

    // println!("Aggregated signature: {:?}", aggregator);

    // Same for the aggregate
    let threshold_signature = aggregator
        .aggregate()
        .map_err(|err| format!("Error: {:?}", err))?;

    // Anyone with the group public key can then verify the threshold signature in the same way they would for a standard Schnorr signature.

    let verified = threshold_signature.verify(&alice_group_key, &message_hash);

    match verified {
        Ok(()) => println!("The signature is valid!"),
        Err(()) => println!("The signature is invalid!"),
    }
    println!("FROST test completed!");
    Ok(())
}
