# TPMVault

## Overview

TPMVault is a Windows/.NET educational security project comparing software-backed
and TPM-backed RSA keys, hybrid secret encryption, TPM 2.0 PCR access, and local
and offline Quote verification. It is a student portfolio project, not a complete
remote attestation service or an audited production secrets manager.

## Architecture

```text
Secure storage
==============
Secret -- AES-256-GCM --> Ciphertext + Nonce + Authentication Tag
             ^
             |
       Fresh AES-256 key -- RSA-OAEP-SHA256 --> Wrapped AES key
                                  |
                       Persistent RSA-2048 key
                         /                 \
                 Software KSP          Platform KSP (TPM)

TPM Quote
=========
Random nonce + SHA-256 PCR selection (0, 2, 4, 7)
                         |
                  Microsoft.TSS / Tpm2Lib
                         |
                     Windows TBS
                         |
                      TPM 2.0
                         |
                 TPM2_Quote (transient RSA key)
                         |
              TPMS_ATTEST + signature + public key
                         + PCR snapshot read from TPM
                         |
                 Local verification
                         |
                     quote.json
                         |
             Offline evidence consistency verification
```

Source layout:

```text
Program.cs                     Minimal entry point
TpmVaultApp.cs                  CLI routing and presentation
Configuration/                 Backend configuration and repository path rules
Crypto/                        Persistent CNG key management and crypto demos
Storage/                       Vault models, validation and encryption
Native/                        Windows CNG interop and key enumeration
Tpm/                           Windows TBS lifecycle and PCR/capability reads
  Quote/                       Quote creation, evidence export and verification
  Experimental/                Unsuccessful NCryptCreateClaim experiment
 tests/                        Software-only regression checks
 docs/                         Experimental notes and release review
 vault/                        Ignored runtime entries; never source code
```

`Storage/` uses the namespace `TPMVault.Vault`. A source folder named `Vault/`
would collide with runtime `vault/` on case-insensitive Windows filesystems.
No dependency-injection framework or simulator is used.

## Features

### Working

- Persistent named RSA-2048 keys through Microsoft Software Key Storage Provider
  and Microsoft Platform Crypto Provider.
- RSA signing/verification and intentional private-key export comparison.
- AES-256-GCM encryption and RSA-OAEP-SHA256 key wrapping.
- Backend-separated Vault put/get/list/inspect/delete and CNG key enumeration/deletion.
- Windows TBS connection, TPM manufacturer/firmware query, and SHA-256 PCR reads
  for PCRs 0, 2, 4, 7, including partial PCR responses.
- Transient RSA TPM2 Quote creation and local nonce, selection, digest, type/magic,
  and signature verification.
- Verified public-evidence export and offline verification with tamper detection.

Hardware functionality was demonstrated on the host machine before this cleanup.
Software regression tests and offline verification are separate from hardware tests.

### Experimental

`NCryptCreateClaim / NCRYPT_CLAIM_PLATFORM` currently returns `0x80070057`
(`E_INVALIDARG`). The `attest` command opens/creates an identity-style CNG key,
but successful CNG platform attestation has **not** been demonstrated.
It is retained for education/debugging, not repaired or hidden.
See [experimental notes](docs/experimental-cng-attestation.md).

### Not implemented

AIK enrollment, EK trust, certificate-chain validation, a remote verifier,
server-generated challenges/replay protection, and Azure Attestation integration.

## Security design

Each Vault entry uses a fresh random 32-byte AES key and 12-byte nonce. AES-256-GCM
encrypts the secret with a 16-byte authentication tag; RSA-OAEP-SHA256 wraps only
the AES key. RSA keys remain persistent and separate for each backend:
`TPMVault.SoftwareKeyV2` and `TPMVault.TpmKeyV2`.

The software private key is intentionally exportable for comparison. The TPM
private key is non-exportable in the demonstrated Windows CNG flow. This does
not prevent a compromised process with permission to use the key from decrypting
secrets. Vault decryption is not sealed to PCR values. Version 1 does not bind
entry names or other metadata as GCM associated data, and does not prevent rollback.

`get` opens an existing key only; missing keys produce an error, never a replacement.
`inspect`, `list-secrets`, and `verify-quote` do not open keys. Mutable AES-key,
plaintext, and exported private-key arrays are cleared in `finally`. Immutable
.NET strings cannot be securely erased. Interactive `put` input is not echoed;
`get` intentionally prints the secret, so protect terminal logs and redirected output.

Vault files retain their existing version-1 PascalCase JSON schema. Reads reject
malformed JSON, missing/null/duplicate/unknown properties, wrong versions/backends,
invalid Base64, wrong wrapped-key/nonce/tag sizes, and excessive input. Limits are
1 MiB for UTF-8 secret bytes/ciphertext and 2 MiB per Vault JSON file. Empty
ciphertext is structurally valid for an empty GCM plaintext; the CLI rejects empty
secret input. Structural validation does not replace GCM authentication during `get`.

Quote creates a transient RSA-2048 primary under the null hierarchy with SHA-256
and RSASSA. Attributes are `Sign | Restricted | FixedTPM | FixedParent |
SensitiveDataOrigin | UserWithAuth`; no persistent handle is assigned. A fresh
32-byte random nonce is supplied as `qualifyingData`. The key is flushed in
`finally`, and TBS is disposed before evidence export. Cleanup errors are reported.
PCR snapshot changes after Quote cause verification failure, not false success.

Repository-local paths are anchored to the checkout location embedded at build
time. Rebuild after moving the checkout. Paths outside that root, UNC/device paths,
alternate streams, reserved Windows names, ambiguous trailing spaces/dots and
links/junctions are rejected. Evidence cannot target `vault/` or repository-internal
directories. Existing evidence is never overwritten; output parents must exist.
These checks assume other processes are not concurrently replacing directory
components. Do not use an attacker-writable checkout as a filesystem security boundary.

## Command reference

Run commands from the repository with `dotnet run -- <command>`. A bare invocation
shows usage and returns nonzero without creating a key. Malformed arguments fail
before command execution. Replace `<backend>` with `software` or `tpm`.

| Command | Behavior / state effects |
| --- | --- |
| `software` | Crypto demo; opens/creates the persistent software key |
| `tpm` | Crypto demo; opens/creates the persistent TPM key |
| `list` | Enumerates keys in both CNG providers |
| `delete <backend> <key-name>` | Deletes the named persistent key; may make dependent entries unrecoverable |
| `put <backend> <secret-name>` | Prompts for a secret, opens/creates a key and writes/replaces the entry |
| `get <backend> <secret-name>` | Validates and decrypts an existing entry using an existing key |
| `list-secrets <backend>` | Lists entry names without opening keys |
| `inspect <backend> <secret-name>` | Validates stored structure and displays metadata without decrypting |
| `delete-secret <backend> <secret-name>` | Deletes the named Vault entry |
| `tpm-info` | Reads TPM capabilities through TBS |
| `pcrs` | Reads SHA-256 PCRs 0, 2, 4, 7 |
| `quote` | Creates and locally verifies a transient-key TPM Quote |
| `quote --output <file>` | Exports only after local verification; refuses existing output |
| `verify-quote <file>` | Reads/verifies evidence offline; no TPM/TBS access |
| `attest` | **Experimental**; may create a persistent identity-style key; platform claim currently fails |

Examples (state-changing commands are manual operations):

```text
dotnet run -- software
dotnet run -- tpm
dotnet run -- list
dotnet run -- put tpm github-token
dotnet run -- get tpm github-token
dotnet run -- list-secrets tpm
dotnet run -- inspect tpm github-token
dotnet run -- delete-secret tpm github-token
dotnet run -- tpm-info
dotnet run -- pcrs
dotnet run -- quote
dotnet run -- quote --output quote.json
dotnet run -- verify-quote quote.json
dotnet run -- attest
```

Commands return 0 on success and nonzero on failure. `attest` reports native status;
claim creation, even if it eventually succeeds, is not claim verification.

## Evidence format

Versioned UTF-8 JSON contains only portable public data; binary fields use Base64.

| Field | Version 1 |
| --- | --- |
| `format`, `version` | `TPMVault.TpmQuote`, `1` |
| `hashAlgorithm` | `SHA-256` for PCR bank, composite digest and signature hash |
| `pcrIndexes` | `[0, 2, 4, 7]` |
| `pcrValues` | Decimal index keys mapped to Base64 of 32 raw PCR bytes |
| `nonce` | Base64 of the 32-byte challenge |
| `attestationFormat`, `attestation` | `TPMS_ATTEST`; signed bytes without an outer TPM2B size prefix |
| `signatureAlgorithm`, `signature` | `RSASSA-PKCS1-v1_5`; raw 256-byte RSA signature, no TPMT_SIGNATURE wrapper |
| `publicKeyFormat`, `publicKey` | `SubjectPublicKeyInfo-DER`; canonical DER X.509 RSA-2048 SubjectPublicKeyInfo |

Evidence contains **no RSA private keys, AES keys, Vault secrets, TPM
sensitive/private structures, or authorization values**. The public key contains
only the modulus and exponent, not a certificate. Local `quote.json` is ignored
by Git and is not a published identity or trust anchor. Do not delete it merely
for cleanup. Review any other exported filenames before committing.

The offline verifier limits files to 64 KiB, parses `TPMS_ATTEST` with the TSS.Net
marshaller, rejects trailing bytes, and checks magic, Quote type, nonce and exact
SHA-256 PCR selection. Zero selection padding is semantically immaterial. It hashes
raw PCR values in index order with SHA-256, without length prefixes, then compares
the result with the signed PCR digest. `RSA.ImportSubjectPublicKeyInfo` reconstructs
the public key; `RSA.VerifyData` verifies PKCS#1 v1.5/SHA-256 over the **original
serialized attestation bytes**. All checks must pass for `VERIFIED`.

## Trust model

Offline verification establishes structural consistency, correct magic/type,
nonce and PCR selection consistency, the PCR digest, and a valid signature under
the embedded public key. It does **not** establish external trust in that key,
trusted TPM origin, AIK/EK certificate trust, device identity, remote verifier trust,
a server-generated freshness challenge, replay protection, or Azure Attestation trust.

Anyone able to replace the entire evidence can sign internally consistent evidence
using their own key. Matching a nonce stored in the same file establishes consistency,
not freshness. The accurate scope is **local TPM Quote verification** and **offline
Quote evidence consistency verification**, not fully trusted remote attestation.

## Requirements

- Windows and the .NET 10 SDK (`net10.0-windows`).
- TPM 2.0 with Windows TBS access for hardware commands.
- Microsoft.TSS 2.1.1 (the `Tpm2Lib` namespace), restored by NuGet.

This project does not claim cross-platform TPM support or request elevation.
On a normal development machine:

```text
dotnet build
```

## Testing

The tests are a dependency-light console regression suite, not a `dotnet test`
framework project. They use synthetic software-signed evidence and repository-local
files under ignored `tests/obj/`; they create no persistent keys and use no TPM.
A project reference ensures tests use the selected build configuration.

```text
dotnet run --project tests/QuoteVerifierChecks.csproj
```

After dependencies are restored, use `--no-restore` for restricted/offline builds.
Coverage includes Vault schema/size/path validation, hybrid encryption, public
evidence serialization, failed-export protection, Quote tampering, substituted
public keys, CLI errors and read-only preservation. Synthetic fixtures do not prove
hardware origin.

Manual hardware integration is separate: `tpm-info`, `pcrs`, `quote` and
`quote --output <new-file>` require TPM access; demos and `attest` can create persistent
keys. Do not include them in a software-only CI run. The host previously demonstrated
`Local TPM Quote verified`; cleanup verification only reuses existing evidence:

```text
dotnet run -- verify-quote quote.json
```

See [release review](docs/release-review.md) for cleanup findings and final results.
