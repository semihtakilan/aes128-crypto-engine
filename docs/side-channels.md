# Side-Channel Analysis

> This analysis documents limitations; it does not make the implementation suitable for production.

## Table-Based AES

`SubBytes` reads an S-Box using a byte derived from the current state. Because the state depends on key material, the table index can influence cache-line activity. An observer able to measure execution time, cache hits, or shared-cache behavior may correlate those observations with the secret key. This is the classic cache-timing weakness of table-based AES.

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
