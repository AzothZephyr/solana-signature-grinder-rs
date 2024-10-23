mod tests {

    use sha2::{Sha256, Digest};

    #[cfg(target_feature = "avx512f")]
    use crate::avx512::sha256_avx512::sha256_avx512;

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_sha256_avx512() {
        // test vectors
        let test_cases = [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ];

        for (input, expected) in test_cases {
            let mut messages = [[0u8; 88]; 16];
            messages[0][..input.len()].copy_from_slice(input.as_bytes());
            
            let result = unsafe { sha256_avx512(&messages) };
            assert_eq!(hex::encode(result[0]), expected);
        }
    }
    
    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_sha256_avx512_against_scalar() {
        let test_data = [
            vec![],
            vec![0u8; 63],
            vec![0u8; 64],
            vec![0u8; 65],
            vec![0u8; 88],
            vec![0u8; 128],
        ];

        for data in test_data {
            let mut messages = [[0u8; 88]; 16];
            messages[0][..data.len()].copy_from_slice(&data);

            let avx512_results = unsafe { sha256_avx512(&messages) };
            let scalar_result = sha256_scalar(&data);
            
            assert_eq!(avx512_results[0], scalar_result, "mismatch for input length {}", data.len());
            
            // check that all other results are zero (as they should be for empty input)
            for result in &avx512_results[1..] {
                assert_eq!(*result, [0u8; 32], "non-zero result for empty input");
            }
        }
    }

    // placeholder until i figure out how im testing this
    fn sha256_scalar(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[test]
    fn test_sha256_scalar() {
        // this test always runs to ensure the scalar implementation is correct
        let test_cases = [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ];

        for (input, expected) in test_cases {
            let result = sha256_scalar(input.as_bytes());
            assert_eq!(hex::encode(result), expected);
        }
    }
}
