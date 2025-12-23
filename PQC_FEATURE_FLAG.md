# Post-Quantum Cryptography Feature Flag

## Issue

The `pqcrypto-kyber` crate (version 0.5) has compatibility issues on macOS/ARM (AArch64) platforms. 

### Technical Details

`pqcrypto-kyber` v0.5.0 is designed to automatically select the appropriate implementation:
- **x86/x86_64**: Uses AVX2-optimized implementation if available at runtime, falls back to "clean" (generic/portable) implementation
- **AArch64 (ARM)**: Should automatically use the "clean" (generic/portable) implementation using `PQCLEAN_KYBER*_CLEAN_*` functions

However, there is a **bug** in `pqcrypto-kyber` v0.5.0 where AVX2 FFI function declarations (`PQCLEAN_KYBER*_AVX2_*`) are not properly guarded with `#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]` in the FFI bindings. This causes compilation failures on AArch64 platforms even though:
1. The code would never call these functions (runtime feature detection only runs on x86)
2. The "clean" implementation functions are available and should work correctly on AArch64

**Answer to your question**: Yes, on AArch64 we should be using the "clean" (generic/portable) implementation, not AVX2. The bug prevents the crate from compiling, but if it did compile, it would use the clean implementation.

## Solution

Post-quantum cryptography support has been made **optional** via a Cargo feature flag. This allows the library to compile and work on all platforms, with PQC support available when explicitly enabled.

## Usage

### Without Post-Quantum Support (Default)

The library compiles and works normally without PQC dependencies:

```bash
cargo build
cargo test
```

This is the default behavior and works on all platforms, including macOS/ARM.

### With Post-Quantum Support

To enable post-quantum cryptography support:

```bash
cargo build --features post-quantum
cargo test --features post-quantum
```

**Note**: On macOS/ARM, you may still encounter AVX2-related compilation errors with `pqcrypto-kyber`. If this occurs, you have several options:

1. **Use only ML-DSA and SLH-DSA** (signatures work, encryption doesn't):
   - Comment out `pqcrypto-kyber` in `Cargo.toml`
   - Remove `pqcrypto-kyber` from the `post-quantum` feature
   - ML-DSA and SLH-DSA should work fine

2. **Wait for pqcrypto-kyber fixes**: The crate maintainers may fix the AVX2 issues in future versions

3. **Use alternative ML-KEM implementations**: Consider other Rust ML-KEM crates that don't have AVX2 issues

## What's Included

When the `post-quantum` feature is enabled:

- **ML-KEM-768** and **ML-KEM-1024** encryption (if `pqcrypto-kyber` compiles)
- **ML-DSA-44**, **ML-DSA-65**, **ML-DSA-87** signatures
- **SLH-DSA-128s**, **SLH-DSA-192s**, **SLH-DSA-256s** signatures
- **Hybrid encryption** (ML-KEM + X25519)

## Code Changes

All post-quantum code is conditionally compiled:

```rust
#[cfg(feature = "post-quantum")]
pub struct MlKem768Key { ... }

#[cfg(feature = "post-quantum")]
pub fn mlkem768_encrypt(...) { ... }
```

The library gracefully handles missing PQC support - functions that require PQC will simply not be available when the feature is disabled.

## Testing

PQC tests are also conditionally compiled:

```rust
#[cfg(feature = "post-quantum")]
#[test]
fn test_mlkem768_encryption() { ... }
```

Run PQC tests with:
```bash
cargo test --features post-quantum
```

## Recommendations

1. **For production use on macOS/ARM**: Currently, only ML-DSA and SLH-DSA signatures are reliable. ML-KEM encryption may not compile.

2. **For x86_64 Linux/Windows**: Full PQC support should work when the feature is enabled.

3. **For maximum compatibility**: Keep PQC disabled by default and enable it only when needed and when the platform supports it.

## Future Improvements

- Monitor `pqcrypto-kyber` for fixes to AVX2 issues
- Consider alternative ML-KEM implementations
- Add platform-specific feature flags (e.g., `post-quantum-x86_64`)

