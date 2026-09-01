# Side-Channel Analysis

> This analysis documents limitations; it does not make the implementation suitable for production.

## Table-Based AES

`SubBytes`, `InvSubBytes`, and the key schedule's `SubWord` read S-Box or inverse S-Box entries using secret-dependent indices. Those indices can influence cache-line activity. An observer able to measure execution time, cache hits, or shared-cache behavior may correlate observations with the secret key. This is the cache-timing weakness of this implementation.

`MixColumns` and `InvMixColumns` do not use lookup tables here. They call `gf_multiply`, which always performs eight mask-based iterations; `xtime` also uses a mask rather than a data-dependent branch. The secret-indexed cache-access surface is therefore the S-Box/inverse S-Box lookups, not a T-table implementation of the column transforms. This source-level distinction is not a guarantee about every compiler's generated machine code.

The project accepts this risk because its purpose is algorithm study and standards validation. It is not a production cryptographic library, and the README states that limitation prominently.

## Mitigations

Production implementations should use one or more of the following:

- bitsliced or otherwise constant-time AES implementations;
- hardware AES instructions rather than software lookup tables;
- carefully reviewed, maintained cryptographic libraries;
- isolation and threat-model controls that reduce observation opportunities.

On ARMv8-A, `AESE`, `AESD`, `AESMC`, and `AESIMC` provide hardware-assisted AES rounds. Apple platforms expose these capabilities through reviewed system APIs such as CryptoKit; application code should prefer those APIs for real secrets.

## Constant-Time Portions

The MAC tag comparison accumulates all byte differences and does not return early. PKCS#7 validation scans all 16 bytes of the final block and applies masks before making the final validity decision. These properties reduce timing leakage in the authentication boundary, but they do not change the table-based AES limitation.

The implementation also avoids `memcmp` for tags and avoids early-return padding checks. Length and structural validation may return early because those values are public message metadata, not secret-dependent comparisons.

## Memory-Wiping Limits

The C `aes_secure_zero` helper uses volatile writes and a `size_t` counter, including for buffers larger than 255 bytes. This prevents the explicit clearing loop from being removed as a dead store.

Swift `Data` uses copy-on-write storage. `withUnsafeMutableBytes` can detach a shared buffer, so `CryptoEngine.wipe` may clear a new copy while another copy remains alive. It is best-effort cleanup, not proof that every historical copy was erased. Swift strings, password-field storage, registers, and the in-memory plaintext display cache also cannot be given a complete zeroization guarantee by this implementation. Copies and lifetimes are limited, fields are cleared after submission, and the display cache is dropped on lock. Production code needs a reviewed cryptographic implementation and a memory model designed for secrets.
