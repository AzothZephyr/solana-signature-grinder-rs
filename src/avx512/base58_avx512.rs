#[cfg(target_feature = "avx512f")]
use std::arch::x86_64::*;

// constants for base58 encoding
#[cfg(target_feature = "avx512f")]
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// BATCH_SIZE should align w the number of avx512 registers available, so iterations of 16
#[cfg(target_feature = "avx512f")]
const BATCH_SIZE: usize = 16;

#[cfg(target_feature = "avx512f")]
pub unsafe fn base58_encode_avx512(data: &[[u8; 64]]) -> Vec<String> {
    let mut big_ints = [[0u64; 8]; BATCH_SIZE];
    for i in 0..BATCH_SIZE {
        big_ints[i] = convert_to_big_integer(&data[i]).try_into().unwrap();
    }
    let mut encoded_chunks = Vec::with_capacity(BATCH_SIZE);

    // step 1: perform base58 encoding in parallel
    while !all_zero(&big_ints) {
        let (quotients, remainders) = divide_by_58_avx512_batch(&big_ints);
        for (i, remainder) in remainders.iter().enumerate() {
            encoded_chunks[i].push(BASE58_ALPHABET[*remainder as usize]);
        }
        big_ints = quotients.try_into().unwrap();
    }

    // step 2: handle leading zeros
    for (i, data_slice) in data.iter().enumerate() {
        for &byte in data_slice.iter().take_while(|&&x| x == 0) {
            encoded_chunks[i].push(BASE58_ALPHABET[0]);
        }
    }

    // step 3: reverse the results
    for encoded_chunk in &mut encoded_chunks {
        encoded_chunk.reverse();
    }

    // convert to strings and return results
    let mut results = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        results[i] = String::from_utf8(encoded_chunks[i].clone()).unwrap();
    }
    results
}


// convert input bytes to a big integer representation
#[cfg(target_feature = "avx512f")]
fn convert_to_big_integer(data: &[u8; 64]) -> Vec<u64> {
    let mut big_int = Vec::with_capacity(4);
    for chunk in data.rchunks(8) {
        let mut value = 0u64;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u64) << (i * 8);
        }
        big_int.push(value);
    }
    big_int
}

// perform division by 58 using avx512 instructions for multiple big integers
#[cfg(target_feature = "avx512f")]
unsafe fn divide_by_58_avx512_batch(big_ints: &[[u64; 8]; BATCH_SIZE]) -> (Vec<Vec<u64>>, Vec<u8>) {
    let mut quotients = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        quotients[i] = Vec::with_capacity(big_ints[i].len());
    }
    let mut remainders = vec![0u8; BATCH_SIZE];

    let divisor = _mm512_set1_epi64(58);
    let zero = _mm512_setzero_si512();

    for i in (0..big_ints[0].len()).rev() {
        let mut carry = zero;

        for j in 0..BATCH_SIZE {
            let mut dividend = if i < big_ints[j].len() {
                _mm512_set1_epi64(big_ints[j][i] as i64)
            } else {
                zero
            };

            dividend = _mm512_add_epi64(dividend, carry);

            let quotient = _mm512_div_epu64(dividend, divisor);
            let remainder = _mm512_rem_epu64(dividend, divisor);

            quotients[j].push(_mm512_extract_epi64::<0>(quotient) as u64);
            carry = _mm512_slli_epi64(remainder, 64);
        }

        if i == 0 {
            for j in 0..BATCH_SIZE {
                remainders[j] = _mm512_extract_epi8::<0>(_mm512_castsi512_si128(carry)) as u8;
            }
        }
    }

    for quotient in &mut quotients {
        quotient.reverse();
    }

    (quotients, remainders)
}

// check if all big integers are zero
#[cfg(target_feature = "avx512f")]
fn all_zero(big_ints: &[[u64; 8]; BATCH_SIZE]) -> bool {
    big_ints.iter().all(|bi| bi.iter().all(|&x| x == 0))
}

// helper function to perform vectorized multiplication for multiple big integers
#[cfg(target_feature = "avx512f")]
unsafe fn multiply_by_256_avx512_batch(big_ints: &mut [[u64; 8]; BATCH_SIZE]) {
    let mul_256 = _mm512_set1_epi64(256);
    let zero = _mm512_setzero_si512();

    for big_int in big_ints.iter_mut() {
        let mut carry = zero;

        for chunk in big_int.iter_mut() {
            let chunk_vec = _mm512_set1_epi64(*chunk as i64);
            let result = _mm512_mul_epu32(chunk_vec, mul_256);
            let sum = _mm512_add_epi64(result, carry);
            
            *chunk = _mm512_extract_epi64::<0>(sum) as u64;
            carry = _mm512_srli_epi64(sum, 64);
        }

        if _mm512_extract_epi64::<0>(carry) != 0 {
            big_int.push(_mm512_extract_epi64::<0>(carry) as u64);
        }
    }
}

// helper function to perform vectorized addition for multiple big integers
#[cfg(target_feature = "avx512f")]
unsafe fn add_byte_avx512_batch(big_ints: &mut [[u64; 8]; BATCH_SIZE], bytes: &[u8; BATCH_SIZE]) {
    let bytes_vec = _mm512_loadu_si512(bytes.as_ptr() as *const __m512i);
    let one = _mm512_set1_epi64(1);

    for (big_int, &byte) in big_ints.iter_mut().zip(bytes.iter()) {
        let mut carry = _mm512_set1_epi64(byte as i64);

        for chunk in big_int.iter_mut() {
            let chunk_vec = _mm512_set1_epi64(*chunk as i64);
            let sum = _mm512_add_epi64(chunk_vec, carry);
            
            *chunk = _mm512_extract_epi64::<0>(sum) as u64;
            carry = _mm512_and_si512(_mm512_srli_epi64(sum, 63), one);
        }

        if _mm512_extract_epi64::<0>(carry) != 0 {
            big_int.push(_mm512_extract_epi64::<0>(carry) as u64);
        }
    }
}

#[inline(always)]
#[cfg(target_feature = "avx512f")]
unsafe fn _mm512_div_epu64(a: __m512i, b: __m512i) -> __m512i {
    let mut result = _mm512_setzero_si512();
    for i in 0..8 {
        let dividend = _mm512_extract_epi64::<i>(a);
        let divisor = _mm512_extract_epi64::<0>(b);
        let quotient = dividend / divisor;
        result = _mm512_insert_epi64::<i>(result, quotient);
    }
    result
}
