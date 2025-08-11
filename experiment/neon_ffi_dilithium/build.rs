// build.rs
fn main() {
    println!("cargo:rustc-link-search=native=/home/chsu/aptos-pqc/experiment/avx_ffi_dilithium/");
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=crypto");
}