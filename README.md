# AES-CTR

This repository provides a compact AES-128 CTR implementation in plain C.

Files:
- `aes.h`: public API
- `aes.c`: AES-128 CTR implementation
- `main.c`: correctness tests
- `CMakeLists.txt`: build configuration

## API

The library exposes:

```c
void aes_encrypt_msg(const uint8_t *key,
                     const uint8_t *iv,
                     const uint8_t *plaintext,
                     uint8_t *ciphertext,
                     const size_t msg_len);

void aes_decrypt_msg(const uint8_t *key,
                     const uint8_t *iv,
                     const uint8_t *ciphertext,
                     uint8_t *plaintext,
                     const size_t msg_len);
```

Notes:
- The implementation is AES-128 CTR.
- `key` must point to 16 bytes.
- `iv` must point to a 16-byte initial counter block.
- Encryption and decryption use the same CTR core.

## Runtime Optimization

The library always includes a portable backend.

When supported by the target architecture and detected at runtime, it will use:
- AES-NI on x86/x86_64
- ARMv8 AES/crypto instructions on arm64/aarch64

If no hardware AES support is available, it falls back to the portable implementation automatically.

## Build

Configure and build:

```sh
cmake -S . -B build
cmake --build build
```

Run the test executable:

```sh
./build/aes_ctr_test
```

Or run through CTest:

```sh
ctest --test-dir build --output-on-failure
```

## Validation

`main.c` checks:
- a NIST AES-128-CTR known-answer test vector
- a partial-block round-trip test

## Reference

The AES block core was adapted from:
- https://github.com/mrdcvlsc/AES
