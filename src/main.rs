// #![feature(stdarch_x86_avx512)]
use std::time::Instant;

mod avx512;
mod scalar;

fn is_avx512_supported() -> bool {
    #[cfg(target_feature = "avx512f")]
    unsafe {
        std::is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

async fn grind_signature(prefix: &str) -> Option<(String, u64, f64)> {
    if is_avx512_supported() {
        println!("avx-512 available, using avx512 implementation");
        std::thread::sleep(std::time::Duration::from_millis(100));
        avx512::grind_signature_avx512(prefix)
    } else {
        println!("avx-512 unavailable, using scalar implementation");
        std::thread::sleep(std::time::Duration::from_millis(100));
        scalar::grind_signature_scalar(prefix)
    }
}

#[tokio::main]
async fn main() {
    let prefix = "joe";
    println!("grinding signature with prefix {}...", prefix);
    
    let start = Instant::now();
    let result = grind_signature(prefix).await;
    let duration = start.elapsed();
    
    match result {
        Some((hash, attempts, _)) => {
            println!("\n");
            println!("transaction signature found after {} attempts: {}", attempts, hash);
            println!("total time elapsed: {:.2} ms", duration.as_secs_f64() * 1000.0);
        },
        None => {
            println!("\nno signature found within the time limit");
        }
    }
    
    // benchmark
    println!("\nbenchmark:");
    let iterations = 5;
    let mut total_duration = 0.0;
    let mut total_attempts = 0;
    
    for i in 1..=iterations {
        println!("run {}:", i);
        let start = Instant::now();
        if let Some((_, attempts, _)) = grind_signature(prefix).await {
            let duration = start.elapsed();
            println!("  attempts: {}", attempts);
            println!("  duration: {:.2} ms", duration.as_secs_f64() * 1000.0);
            total_duration += duration.as_secs_f64();
            total_attempts += attempts;
        } else {
            println!("  failed to find signature within time limit");
        }
    }
    
    println!("\naverage over {} runs:", iterations);
    println!("  attempts: {}", total_attempts / iterations);
    println!("  duration: {:.2} ms", (total_duration / iterations as f64) * 1000.0);
}
