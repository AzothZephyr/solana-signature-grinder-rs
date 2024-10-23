// declare modules
mod base58_avx512;
mod ed25519_avx512;
mod sha256_avx512;

#[cfg(not(target_feature = "avx512f"))]
pub fn grind_signature_avx512(_prefix: &str) -> Option<(String, u64, f64)> {
    None
}

#[cfg(target_feature = "avx512f")]
mod avx512_impl {
    // export modules
    pub use super::base58_avx512::base58_encode_avx512;
    pub use super::ed25519_avx512::ed25519_sign_avx512;
    pub use super::sha256_avx512::sha256_avx512;

    // import modules
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use solana_sdk::compute_budget::ComputeBudgetInstruction;
    use solana_sdk::instruction::Instruction;
    use solana_sdk::message::Message;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::system_instruction;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::select;
    use tokio::sync::mpsc;
    use tokio::time;

    // main avx512 optimized tx hash grinding function
    pub async fn grind_signature_avx512(prefix: &str) -> Option<(String, u64, f64)> {
        // ----
        // necessary setup
        // ----
        let mut rng = OsRng;
        let signer = Arc::new(Keypair::generate(&mut rng));

        let recipient = Pubkey::from_str("godeYaXfVFa32acSUa39BTfFYrr9TeBkzgDanYowdo8").unwrap();
        let amount = 1_000_000;

        // convert ed25519-dalek PublicKey to solana Pubkey
        let signer_pubkey = Pubkey::new_from_array(signer.public.to_bytes());
        let transfer_ix = system_instruction::transfer(&signer_pubkey, &recipient, amount);

        // define batch size to process in parallel
        const BATCH_SIZE: usize = 16;
        const BATCH: Vec<[u8; BATCH_SIZE]> = Vec::new();
        // ----

        // ----
        // instantiate channels
        // --
        // preparation thread is sender, calculation thread is receiver
        let (prep_sender, mut prep_receiver) = mpsc::channel::<Vec<Vec<u8>>>(1000);
        // calculation thread is sender, confirmation thread is receiver
        let (calc_sender, mut calc_receiver) = mpsc::channel::<Vec<String>>(1000);
        // confirmation thread is sender, main thread is receiver
        let (success_sender, mut success_receiver) = mpsc::channel::<Option<(String, u64, f64)>>(1);

        // ----
        // preparation thread
        // --
        // this thread prepares messages for the calculation thread by creating compute budget instructions and keeping a channel
        // populated with messages ready to be hashed, signed, and encoded.
        tokio::spawn(async move {
            let i = 0u64;
            loop {
                // prepare messages
                let compute_ixs: Vec<Instruction> = (0..i)
                    .map(|j| ComputeBudgetInstruction::set_compute_unit_limit((i + j as u64) as u32))
                    .map(|compute_budget_ix| compute_budget_ix.into())
                    .collect();

                let messages: Vec<Message> = compute_ixs
                    .iter()
                    .map(|compute_ix| {
                        Message::new(
                            &[compute_ix.clone(), transfer_ix.clone()],
                            Some(&signer_pubkey),
                        )
                    })
                    .collect();

                // serialize messages without size restriction
                // TODO: fiddle fuck around w defining the sizes of objects we're passing to aid the compiler in assisting us
                let serialized_messages: Vec<Vec<u8>> =
                    messages.iter().map(|msg| msg.serialize()).collect();

                if let Err(err) = prep_sender.send(serialized_messages).await {
                    // log the error but keep looping, wait 5 seconds, and keep looping
                    // this is start of pipeline so it should only ever stop processing
                    // downstream.
                    println!("preparation thread error: {}", err.to_string());
                }
            }
        });

        // ----
        // calculation thread
        // --
        // this thread does the heavy lifting of hashing, signing, and encoding signatures. it receives messages from the preparation thread
        // in batches of 16, does hashing, signing, and encoding using avx512, then sends encoded signatures to the confirmation thread to
        // be checked for the prefix.
        let calc_signer = Arc::clone(&signer);
        tokio::spawn(async move {
            while let Some(serialized_messages) = prep_receiver.recv().await {
                // ensure we're working with Vec<Vec<u8>>
                let messages: Vec<Vec<u8>> = serialized_messages.into_iter().collect();

                // TODO: remove and handle w typing. this reads each message into an array of type: &[[u8; 88]; 16]
                let mut message_array: [[u8; 88]; 16] = [[0; 88]; 16];
                for (i, message) in messages.iter().take(16).enumerate() {
                    let len = std::cmp::min(message.len(), 88);
                    message_array[i][..len].copy_from_slice(&message[..len]);
                }

                // hash messages using avx512
                let hashed_messages: [[u8; 32]; 16] = unsafe { sha256_avx512(&message_array) };

                // sign hashed messages using avx512
                let signatures: [[u8; 64]; 16] =
                    unsafe { ed25519_sign_avx512(calc_signer.secret.as_bytes(), &hashed_messages) };

                // encode signatures using base58 avx512
                let encoded_signatures: Vec<String> = signatures
                    .iter()
                    .map(|sig| unsafe { base58_encode_avx512(&[*sig]) })
                    .flatten()
                    .collect();

                if let Err(err) = calc_sender.send(encoded_signatures).await {
                    // log the error but keep looping, wait 5 seconds, and keep looping
                    // this is start of pipeline so it should only ever stop processing
                    // downstream.
                    println!("calculation thread error: {}", err.to_string());
                }
            }
        });

        // ----
        // confirmation thread
        // --
        // this thread receives encoded signatures from the calculation thread and checks for the prefix. if found, it sends the result to the
        // main thread.
        let start = Instant::now();
        let local_prefix = prefix.to_owned();
        let mut i = 0u64;
        tokio::spawn(async move {
            while let Some(encoded_signatures) = calc_receiver.recv().await {
                for (index, signature) in encoded_signatures.iter().enumerate() {
                    if signature.starts_with(&local_prefix) {
                        // verify the message:
                        let duration = start.elapsed();
                        let result =
                            Some((signature.clone(), i + index as u64, duration.as_secs_f64()));

                        if let Err(err) = success_sender.send(result).await {
                            println!("confirmation thread error: {}", err.to_string());
                        }
                        return;
                    }
                }
                i += encoded_signatures.len() as u64;
            }
        });

        // wait for success or timeout
        // TODO: trigger to beginning of pipeline a blockhash change
        select! {
            result = success_receiver.recv() => result.flatten(),
            _ = time::sleep(time::Duration::from_secs(300)) => None,
        }
    }
}

// re-export the avx512 implementation if the feature is available
#[cfg(target_feature = "avx512f")]
pub use avx512_impl::*;
