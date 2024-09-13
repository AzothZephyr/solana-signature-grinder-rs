#![feature(stdarch_x86_avx512)]

use ed25519_dalek::{Keypair, Signer as DalekSigner};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Signature, Signer},
    system_instruction,
    transaction::Transaction,
    hash::Hash,
};
use std::str::FromStr;
use std::time::Instant;
use rayon::prelude::*;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

struct SolanaKeypair(Keypair);

impl Signer for SolanaKeypair {
    fn try_pubkey(&self) -> Result<Pubkey, solana_sdk::signer::SignerError> {
        Ok(Pubkey::new_from_array(self.0.public.to_bytes()))
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, solana_sdk::signer::SignerError> {
        let signature = self.0.sign(message);
        Ok(Signature::from(signature.to_bytes()))
    }

    fn is_interactive(&self) -> bool {
        false  // This implementation is not interactive
    }
}


fn to_solana_pubkey(public_key: &ed25519_dalek::PublicKey) -> Pubkey {
    Pubkey::new_from_array(public_key.to_bytes())
}

fn is_avx512_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

fn grind_signature_scalar(prefix: &str) -> (String, u64, f64) {
    let mut rng = OsRng;
    let signer = SolanaKeypair(Keypair::generate(&mut rng));
    
    let recipient = Pubkey::from_str("godeYaXfVFa32acSUa39BTfFYrr9TeBkzgDanYowdo8").unwrap();
    let amount = 1_000_000;
    
    let transfer_ix = system_instruction::transfer(&signer.try_pubkey().unwrap(), &recipient, amount);
    
    let mut i = 0u64;
    let start = Instant::now();
    
    loop {
        let compute_ix = ComputeBudgetInstruction::set_compute_unit_limit(i as u32);
        
        let message = Message::new(
            &[compute_ix, transfer_ix.clone()],
            Some(&signer.try_pubkey().unwrap()),
        );
        
        let transaction = Transaction::new(&[&signer], message, Hash::default());
        let signature = transaction.signatures[0];
        let hash = hex::encode(signature.as_ref());
        
        if hash.starts_with(prefix) {
            let duration = start.elapsed();
            return (hash, i, duration.as_secs_f64());
        }
        
        if i != 0 && i % 1_000 == 0 {
            println!("{} attempts...", i);
        }
        
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn grind_signature_avx512(prefix: &str) -> (String, u64, f64) {
    let mut rng = OsRng;
    let signer = SolanaKeypair(Keypair::generate(&mut rng));
    
    let recipient = Pubkey::from_str("godeYaXfVFa32acSUa39BTfFYrr9TeBkzgDanYowdo8").unwrap();
    let amount = 1_000_000;
    
    let transfer_ix = system_instruction::transfer(&signer.try_pubkey().unwrap(), &recipient, amount);
    
    let mut i = 0u64;
    let start = Instant::now();
    
    let prefix_bytes = prefix.as_bytes();
    let prefix_len = prefix_bytes.len();
    let mut prefix_vec = _mm512_set1_epi8(0);
    for (i, &byte) in prefix_bytes.iter().enumerate() {
        let byte_vec = _mm512_set1_epi8(byte as i8);
        let mask = _mm512_mask_mov_epi8(_mm512_set1_epi8(0), 1 << i, _mm512_set1_epi8(-1));
        prefix_vec = _mm512_or_si512(prefix_vec, _mm512_and_si512(byte_vec, mask));
    }
    
    loop {
        let compute_ixs: Vec<_> = (0..16).map(|j| ComputeBudgetInstruction::set_compute_unit_limit((i + j) as u32)).collect();
        
        let messages: Vec<_> = compute_ixs.iter().map(|compute_ix| {
            Message::new(
                &[compute_ix.clone(), transfer_ix.clone()],
                Some(&signer.try_pubkey().unwrap()),
            )
        }).collect();
        
        let transactions: Vec<_> = messages.iter().map(|message| {
            Transaction::new(&[&signer], message.clone(), Hash::default())
        }).collect();
        
        let signatures: Vec<_> = transactions.iter().map(|tx| tx.signatures[0]).collect();
        
        for (index, signature) in signatures.iter().enumerate() {
            let hash = bs58::encode(signature.as_ref()).into_string();
            if hash.starts_with(prefix) {
                let duration = start.elapsed();
                return (hash, i + index as u64, duration.as_secs_f64());
            }
        }
        
        // if i != 0 && i % 1_000 == 0 {
        //     println!("{} attempts...", i);
        // }
        
        i += 16;
    }
}

fn grind_signature(prefix: &str) -> (String, u64, f64) {
    if is_avx512_supported() {
        println!("using avx512 implementation");
        unsafe { grind_signature_avx512(prefix) }
    } else {
        println!("using scalar implementation");
        grind_signature_scalar(prefix)
    }
}

fn main() {
    let prefix = "joe";
    println!("grinding signature with prefix {}...", prefix);
    
    let (hash, attempts, duration) = grind_signature(prefix);
    
    println!("\n");
    println!("transaction signature found after {} attempts: {}", attempts, hash);
    println!("total time elapsed: {:.2} ms", duration * 1000.0);
    
    // Benchmark
    println!("\nbenchmark:");
    let iterations = 5;
    let mut total_duration = 0.0;
    let mut total_attempts = 0;
    
    for i in 1..=iterations {
        println!("run {}:", i);
        let (hash, attempts, duration) = grind_signature(prefix);
        println!("  attempts: {}", attempts);
        println!("  duration: {:.2} ms", duration * 1000.0);
        total_duration += duration;
        total_attempts += attempts;
    }
    
    println!("\naverage over {} runs:", iterations);
    println!("  attempts: {}", total_attempts / iterations);
    println!("  duration: {:.2} ms", (total_duration / iterations as f64) * 1000.0);
}