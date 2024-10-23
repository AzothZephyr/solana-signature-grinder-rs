#[cfg(target_feature = "avx512f")]
use std::arch::x86_64::*;

// sha256 constants
#[cfg(target_feature = "avx512f")]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// helper functions
#[inline(always)]
#[cfg(target_feature = "avx512f")]
unsafe fn ch(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
    _mm512_ternarylogic_epi32(x, y, z, 0xca)
}

#[inline(always)]
#[cfg(target_feature = "avx512f")]
unsafe fn maj(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
    _mm512_ternarylogic_epi32(x, y, z, 0xe8)
}

#[inline(always)]
#[cfg(target_feature = "avx512f")]
unsafe fn ep0(x: __m512i) -> __m512i {
    let r2 = _mm512_ror_epi32(x, 2);
    let r13 = _mm512_ror_epi32(x, 13);
    let r22 = _mm512_ror_epi32(x, 22);
    _mm512_xor_si512(_mm512_xor_si512(r2, r13), r22)
}

#[inline(always)]
#[cfg(target_feature = "avx512f")]
unsafe fn ep1(x: __m512i) -> __m512i {
    let r6 = _mm512_ror_epi32(x, 6);
    let r11 = _mm512_ror_epi32(x, 11);
    let r25 = _mm512_ror_epi32(x, 25);
    _mm512_xor_si512(_mm512_xor_si512(r6, r11), r25)
}

// sha256 hash messages using avx512: this function requires exactly 16 messages and returns 16 hashes
#[cfg(target_feature = "avx512f")]
pub unsafe fn sha256_avx512(messages: &[[u8; 88]; 16]) -> [[u8; 32]; 16] {
    assert!(messages.len() == 16, "this implementation of sha256_avx512 currently requires exactly 16 messages");

    let mut state = [
        _mm512_set1_epi32(0x6a09e667),
        _mm512_set1_epi32(0xbb67ae85),
        _mm512_set1_epi32(0x3c6ef372),
        _mm512_set1_epi32(0xa54ff53a),
        _mm512_set1_epi32(0x510e527f),
        _mm512_set1_epi32(0x9b05688c),
        _mm512_set1_epi32(0x1f83d9ab),
        _mm512_set1_epi32(0x5be0cd19),
    ];

    let mut w = [_mm512_setzero_si512(); 64];

    // prepare message schedule
    for i in 0..16 {
        let mut chunk = [0u32; 16];
        for j in 0..16 {
            let msg = &messages[j];
            let word_index = i * 4;
            if word_index < msg.len() {
                let end = (word_index + 4).min(msg.len());
                let mut word_bytes = [0u8; 4];
                word_bytes[..end - word_index].copy_from_slice(&msg[word_index..end]);
                chunk[j] = u32::from_be_bytes(word_bytes);
            }
        }
        w[i] = _mm512_loadu_si512(chunk.as_ptr() as *const __m512i);
    }

    // extend the first 16 words into the remaining 48 words of the message schedule
    for i in 16..64 {
        let s0 = _mm512_xor_si512(
            _mm512_xor_si512(
                _mm512_ror_epi32(w[i - 15], 7),
                _mm512_ror_epi32(w[i - 15], 18)
            ),
            _mm512_srli_epi32(w[i - 15], 3)
        );
        let s1 = _mm512_xor_si512(
            _mm512_xor_si512(
                _mm512_ror_epi32(w[i - 2], 17),
                _mm512_ror_epi32(w[i - 2], 19)
            ),
            _mm512_srli_epi32(w[i - 2], 10)
        );
        w[i] = _mm512_add_epi32(
            _mm512_add_epi32(
                _mm512_add_epi32(w[i - 16], s0),
                w[i - 7]
            ),
            s1
        );
    }

    // initialize working variables
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7]
    );

    // main loop
    for i in 0..64 {
        let s1 = ep1(e);
        let ch = ch(e, f, g);
        let temp1 = _mm512_add_epi32(
            _mm512_add_epi32(
                _mm512_add_epi32(
                    _mm512_add_epi32(h, s1),
                    ch
                ),
                _mm512_set1_epi32(K[i])
            ),
            w[i]
        );
        let s0 = ep0(a);
        let maj = maj(a, b, c);
        let temp2 = _mm512_add_epi32(s0, maj);

        h = g;
        g = f;
        f = e;
        e = _mm512_add_epi32(d, temp1);
        d = c;
        c = b;
        b = a;
        a = _mm512_add_epi32(temp1, temp2);
    }

    // update state
    for i in 0..8 {
        state[i] = _mm512_add_epi32(state[i], [a, b, c, d, e, f, g, h][i]);
    }

    // store results
    let mut results = [[0u8; 32]; 16];
    for i in 0..8 {
        let state_bytes = state[i].as_array();
        for j in 0..16 {
            results[j][i * 4..(i + 1) * 4].copy_from_slice(&state_bytes[j * 4..(j + 1) * 4]);
        }
    }

    results
}
