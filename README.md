# se-crypt

Utility to seal and unseal files using MacOS Secure Enclave. Inspired heavily by https://github.com/remko/age-plugin-se/.

# Design

## Encryption

1. Generating an ephemeral private key (`epk`).
2. Generating Secure Enclave private key (`sepk`). `sepk` is accessible only after authentication (biometry or password).
3. Deriving the shared secret (`shk`) as `shk = ECDH(epk, sepk_pub)`.
4. Deriving the salt (`salt`) as `salt = epk_pub ^ sepk_pub`.
5. Deriving the symmetric key (`syk`) as `syk = HKDF_SHA256(salt=salt, IKM=shk, info="se-crypt/1.0", length=32)`.
6. Deriving the ciphertext (`ct`) as `ct = ChaChaPoly.seal(data=file_contents, key=syk)`.
7. Serializing `[epk_pub, sepk_repr, ct]` and store as a result.

## Decryption

1. Parsing `[epk_pub, sepk_repr, ct]` from the input file.
2. Regenerate `sepk` from `sepk_repr` using Secure Enclave.
3. Deriving the shared secret (`shk`) as `shk = ECDH(sepk, epk_pub)`. You'll be promted for authentication.
4. Deriving the salt (`salt`) as `salt = epk_pub ^ sepk_pub`.
5. Deriving the symmetric key (`syk`) as `syk = HKDF_SHA256(salt=salt, IKM=shk, info="se-crypt/1.0", length=32)`.
6. Deriving the plaintext (`pt`) as `pt = ChaChaPoly.open(data=ct, key=syk)` and store as a result.

# Security Considerations

- This project is made for fun, not for security.
- The project has no tests.
- The author (me) never used Swift before.
- `sepk_rep` is not a private key itself but rather an opaque handle that can be used by Secure Enclave to regenerate key.
    - You can't decrypt the file on the other Mac. Secure Enclave private keys are tied to their, well, Secure Enclave. That's a very poetic way to lose your data.
- Access control rules of the key require that biometry or password authentication are provided to use the private key.
- One might be tempted to say that the data is encrypted or decrypted **in** Secure Enclave. **It's not**. The nasty Secure Enclave keys can be used solely for signing or key agreement, not encryption. The data is encrypted using `syk` that is made accessible after some Secure Enclave magic. The `syk` and `shk` live in RAM for some period of time. Whether this period is brief or not, may they possibly get swapped or find themselves in a coredump depends heavily on CryptoKit's implementation of SymmetricKey and SharedSecret classes. I dunno.
- There is more subtle issue with `epk`. It must be reliably destroyed after the encryption step or it can be used to recreate `shk` and `syk`. Storing it somewhere else is a funny way to backdoor your own encryption system.

# Bugs

Issues are welcome.
