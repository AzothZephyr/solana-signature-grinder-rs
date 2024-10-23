#[cfg(target_feature = "avx512f")]
mod tests {
    use crate::avx512::ed25519_avx512::ed25519_sign_avx512;
    use ed25519_dalek::{Keypair, Signer, Verifier};
    use rand::rngs::OsRng;
    use sha2::{Sha512, Digest};

    const BATCH_SIZE: usize = 16;

    #[test]
    fn test_ed25519_sign_avx512() {
        unsafe {
            let mut csprng = OsRng{};
            let keypair: Keypair = Keypair::generate(&mut csprng);

            let messages: Vec<[[u8; 32]; BATCH_SIZE]> = (0..BATCH_SIZE)
                .map(|i| {
                    let mut msg = [0u8; 32];
                    msg[0] = i as u8;
                    msg
                })
                .collect();

            let private_key = vec![keypair.secret.to_bytes()];
            let signatures = ed25519_sign_avx512(&private_key, &messages);

            for (i, signature) in signatures.iter().enumerate() {
                let message = &messages[i];
                assert!(keypair.public.verify(message, &ed25519_dalek::Signature::from_bytes(&signature[0]).unwrap()).is_ok(),
                        "signature verification failed for message {}", i);
            }
        }
    }

    #[test]
    fn test_ed25519_sign_avx512_different_messages() {
        unsafe {
            let mut csprng = OsRng{};
            let keypair: Keypair = Keypair::generate(&mut csprng);

            let messages: Vec<[[u8; 32]; BATCH_SIZE]> = (0..BATCH_SIZE)
                .map(|_| {
                    let mut msg = [0u8; 32];
                    csprng.fill_bytes(&mut msg);
                    msg
                })
                .collect();

            let private_key = vec![keypair.secret.to_bytes()];
            let signatures = ed25519_sign_avx512(&private_key, &messages);

            for (i, signature) in signatures.iter().enumerate() {
                let message = &messages[i];
                assert!(keypair.public.verify(message, &ed25519_dalek::Signature::from_bytes(&signature[0]).unwrap()).is_ok(),
                        "signature verification failed for random message {}", i);
            }
        }
    }

    #[test]
    fn test_ed25519_sign_avx512_edge_cases() {
        unsafe {
            let mut csprng = OsRng{};
            let keypair: Keypair = Keypair::generate(&mut csprng);

            let mut messages = vec![[0u8; 32]; BATCH_SIZE];
            messages[0] = [0u8; 32];  // all zeros
            messages[1] = [255u8; 32];  // all ones
            // leave the rest as zeros

            let private_key = vec![keypair.secret.to_bytes()];
            let signatures = ed25519_sign_avx512(&private_key, &messages);

            for (i, signature) in signatures.iter().enumerate() {
                let message = &messages[i];
                assert!(keypair.public.verify(message, &ed25519_dalek::Signature::from_bytes(&signature[0]).unwrap()).is_ok(),
                        "signature verification failed for edge case message {}", i);
            }
        }
    }

    #[test]
    fn test_ed25519_sign_avx512_multiple_keys() {
        unsafe {
            let mut csprng = OsRng{};
            let keypairs: Vec<Keypair> = (0..BATCH_SIZE)
                .map(|_| Keypair::generate(&mut csprng))
                .collect();

            let messages: Vec<[[u8; 32]; BATCH_SIZE]> = (0..BATCH_SIZE)
                .map(|_| {
                    let mut msg = [0u8; 32];
                    csprng.fill_bytes(&mut msg);
                    msg
                })
                .collect();

            let private_keys: Vec<[u8; 32]> = keypairs.iter().map(|kp| kp.secret.to_bytes()).collect();
            let signatures = ed25519_sign_avx512(&private_keys, &messages);

            for (i, signature) in signatures.iter().enumerate() {
                let message = &messages[i];
                assert!(keypairs[i].public.verify(message, &ed25519_dalek::Signature::from_bytes(&signature[0]).unwrap()).is_ok(),
                        "signature verification failed for multiple keys test, message {}", i);
            }
        }
    }

    #[test]
    fn test_ed25519_sign_avx512_consistency() {
        unsafe {
            let mut csprng = OsRng{};
            let keypair: Keypair = Keypair::generate(&mut csprng);

            let message = [1u8; 32];
            let messages = vec![[message; BATCH_SIZE]];

            let private_key = vec![keypair.secret.to_bytes()];
            let signatures = ed25519_sign_avx512(&private_key, &messages);

            // all signatures should be identical
            for signature in signatures.iter().skip(1) {
                assert_eq!(signature, &signatures[0], "inconsistent signatures for identical messages");
            }
        }
    }
}