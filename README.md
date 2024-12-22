# solana signature grinder

## warning:
this repository is an attempt at fucking around with an avx512 pipeline for grinding signatures and honestly is a bit of a retarded implementation. i wouldn't recommend using the avx-512 logic as its fairly unstable and honestly not any better than the scalar implementation herein. 

### compiling:
because this uses "unsafe" code, you need to compile / run with nightly rust:

```
rustup install nightly
cargo +nightly build --release
cargo +nightly run --release
```

### running:

```
cargo +nightly run --release -- --help
```
