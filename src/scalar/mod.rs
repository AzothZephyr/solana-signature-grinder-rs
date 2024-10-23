use rand::rngs::OsRng;
use solana_sdk::{compute_budget::ComputeBudgetInstruction,signer::Signer};
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use sha2::{Sha256, Digest};
use bs58;

pub fn grind_signature_scalar(prefix: &str) -> Option<(String, u64, f64)> {
    // setup
    let mut rng = OsRng;
    let signer = Arc::new(Keypair::generate(&mut rng));

    let recipient = Pubkey::from_str("godeYaXfVFa32acSUa39BTfFYrr9TeBkzgDanYowdo8").unwrap();
    let amount = 1_000_000;

    let signer_pubkey = Pubkey::new_from_array(signer.pubkey().to_bytes());
    let transfer_ix = system_instruction::transfer(&signer_pubkey, &recipient, amount);

    let start = Instant::now();
    let mut attempts = 0u64;

    loop {
        // prepare message
        let compute_ix = ComputeBudgetInstruction::set_compute_unit_limit(attempts as u32);
        let message = Message::new(
            &[compute_ix.into(), transfer_ix.clone()],
            Some(&signer_pubkey),
        );

        // serialize message
        let serialized_message = message.serialize();

        // hash message
        let mut hasher = Sha256::new();
        hasher.update(&serialized_message);
        let hashed_message = hasher.finalize();

        // sign message
        let signature = signer.sign_message(&hashed_message);

        // encode signature
        let encoded_signature = bs58::encode(signature).into_string();

        // check for prefix
        if encoded_signature.starts_with(prefix) {
            let duration = start.elapsed();
            // TODO: return the signature and its input as well 
            return Some((encoded_signature, attempts, duration.as_secs_f64()));
        }

        attempts += 1;

        if attempts % 100000 == 0 {
            println!("executed {} attempts..", attempts);
        }

        // optional: add a timeout check
        if start.elapsed().as_secs() > 300 {  // 5 minutes timeout
            return None;
        }
    }
}
