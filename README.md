# solana signature grinder


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