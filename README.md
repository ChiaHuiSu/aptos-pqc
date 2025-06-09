# Aptos PQC
## Introduction
This repository profiles post-quantum cryptographic (PQC) schemes applied to Move raw transaction signing. It also provides example Move modules and scripts demonstrating PQC integration.

## Run the experiment
Run Rust experiment
```bash=
git clone --recursive https://github.com/ChiaHuiSu/aptos-pqc.git
cd aptos-pqc/experiment
cargo run -p single_ed25519
```

Build liboqs static library
```bash=
cd liboqs
mkdir build && cd build
cmake -DOQS_USE_CPU_EXTENSIONS=ON ..
make -j
```
