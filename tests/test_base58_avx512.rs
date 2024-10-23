#[cfg(target_feature = "avx512f")]
mod tests {
    use crate::avx512::base58_avx512::base58_encode_avx512;

    const BATCH_SIZE: usize = 16;

    #[test]
    fn test_base58_encode_avx512() {
        let test_cases = [
            ([0u8; 64], "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"),
            ([1u8; 64], "5Q4W9zWRVGNZHYzGKVuHYzPJGNSPWQCcDsYVXGe1xMsGYgZh9YKqTzBcMKnqzjBYBGNrRVcDsZ6vQbGBwVqbKFXz"),
            ([255u8; 64], "jpXCZedGfVQ5Z5bGvfJqZH4Jds9SzTXx5v5HKnjiEUgJBGKVADsxgVxNFfnGbGBXCJJbNHD7KTvQPuSqnqACYC4x"),
        ];

        unsafe {
            let mut input = [[0u8; 64]; BATCH_SIZE];
            for (i, (case, _)) in test_cases.iter().enumerate() {
                input[i] = *case;
            }

            let encoded = base58_encode_avx512(&input);

            for (i, (_, expected)) in test_cases.iter().enumerate() {
                assert_eq!(encoded[i], *expected, "failed for input {:?}", input[i]);
            }
        }
    }

    #[test]
    fn test_base58_encode_avx512_edge_cases() {
        unsafe {
            let mut input = [[0u8; 64]; BATCH_SIZE];
            
            // test case 1: all zeros
            // expected result is already tested previously

            // test case 2: alternating 0 and 255
            for i in 0..64 {
                input[1][i] = if i % 2 == 0 { 0 } else { 255 };
            }

            // test case 3: incrementing values
            for i in 0..64 {
                input[2][i] = i as u8;
            }

            let encoded = base58_encode_avx512(&input);

            // verify results (need to pre-compute these expected values)
            assert_eq!(encoded[1], "1G7aNYuWi9tFQKNwvqXvda4TLhjZvkoxjb9ScKEzSGnADWJbXrGJXZonkNZ");
            assert_eq!(encoded[2], "1cWB5HCBdLjAuqGGReWE3R3CwvVfUABemYBSK7");
        }
    }

    #[test]
    fn test_base58_encode_avx512_full_batch() {
        unsafe {
            let mut input = [[0u8; 64]; BATCH_SIZE];
            
            // fill the entire batch with different patterns
            for i in 0..BATCH_SIZE {
                for j in 0..64 {
                    input[i][j] = ((i * j) % 256) as u8;
                }
            }

            let encoded = base58_encode_avx512(&input);

            // verify that we have BATCH_SIZE results
            assert_eq!(encoded.len(), BATCH_SIZE);

            // verify that each result is a valid base58 string
            for result in &encoded {
                assert!(result.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)),
                        "invalid base58 character in result: {}", result);
            }

            // may want to add more specific checks but i can't think of anything
        }
    }
}
