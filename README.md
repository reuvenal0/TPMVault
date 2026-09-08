# TPMVault

TPMVault demonstrates software-backed and TPM-backed cryptographic keys on
Windows and uses them to protect encrypted vault entries.

## Status

Working (existing functionality):
- TPM-backed secure storage
- TBS/TSS.Net TPM connection (confirmed by the user on the actual machine)
- TPM capability query (confirmed by the user)
- SHA-256 PCR reading (confirmed by the user)

- Transient TPM2 Quote and all five local verification checks (confirmed by the
  user on the actual machine: `Local TPM Quote verified`)

Implemented and software-tested:
- Portable JSON evidence export after successful local verification
- Offline verification of exported evidence against its embedded RSA public key

Experimental:
- NCryptCreateClaim platform-claim path (currently returns `0x80070057`)

Not implemented yet:
- Remote attestation
- AIK enrollment and certificate trust
- Server-side verification

## Local TPM Quote

```text
dotnet run -- quote
dotnet run -- quote --output quote.json
```

The command creates a temporary RSA-2048 primary in the **null hierarchy** using
`CreatePrimary`. No existing key is opened and no persistent handle is assigned.
The template uses SHA-256 for its name and **RSASSA / SHA-256** for signing,
with a null symmetric algorithm and attributes `Sign | Restricted | FixedTPM |
FixedParent | SensitiveDataOrigin | UserWithAuth`. The key has empty authorization
for its brief lifetime. `TestParms` checks RSA parameter support before creation.
The restricted-signing template follows Microsoft's
[PCRandKeys sample](https://github.com/microsoft/TSS.MSR/blob/main/TSS.NET/Samples/PCRandKeys/Program.cs).
The [TPM command specification](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3_Commands-V185-RC4_12Dec2025.pdf)
describes temporary null-hierarchy objects in section 24.1 and Quote in section 18.4.

A cryptographically random 32-byte nonce is passed directly as `qualifyingData`
to `Quote`, selecting SHA-256 PCRs **0, 2, 4, 7**. The existing PCR reader collects
the current values after Quote, retaining its partial-response and update-counter
checks. Evidence stays in memory unless `--output` is supplied. No private
material is exported.

Five checks run independently:
- Quote attestation type and TPM-generated magic.
- Exact 32-byte challenge match against signed `extraData`.
- Exactly the expected SHA-256 PCR indexes (zero bitmap padding is immaterial).
- SHA-256 of the concatenated raw PCR digests in index order, compared to
  `QuoteInfo.pcrDigest`. No TPM2B lengths or selection bytes are hashed. This
  matches Microsoft's `VerifyQuote` digest rule; a PCR change between Quote and
  the subsequent read causes a mismatch, never a false success.
- RSASSA-SHA256 signature verification with the returned public key using
  `TpmPublic.VerifySignatureOverData(Attest.GetTpmRepresentation(), signature)`.

Microsoft's [VerifyQuote implementation](https://github.com/microsoft/TSS.MSR/blob/main/TSS.NET/TSS.Net/TpmKey.cs)
short-circuits at the first failure. Separate checks provide complete diagnostics.
`VERIFIED` is printed only when all five pass. This proves local consistency and
possession of the signing key; it does not establish a trusted device identity.

The transient handle returned by this invocation is flushed in `finally`, then
the TBS connection is disposed. Flush failures are reported, including alongside
an earlier command failure. There is no `EvictControl`, key enrollment, TPM
configuration change, or persistent-key deletion.

Validation: build passed with 0 warnings and 0 errors; 12 software-only verifier
checks passed, including nonce, selection, digest, type, and signature tampering.
These synthetic fixtures are **not** hardware attestation evidence. The sandbox
run of `quote` exited with code 1 before key creation:

```text
TPMVault - TPM Quote
--------------------
Quote creation failed (evidence collection or cleanup may have failed).
Exception: Can't create TBS context: Error {TbsInternalError}
```

The user subsequently demonstrated an actual-machine verified Quote with all
five checks valid and the transient key flushed. No connectivity or configuration
changes were attempted. To repeat the software-only checks after a Debug build:

```text
dotnet restore tests/QuoteVerifierChecks.csproj --source .
dotnet run --project tests/QuoteVerifierChecks.csproj --no-restore
```

## Portable Quote evidence

`quote --output quote.json` creates and verifies the same transient-key Quote,
then exports **only public attestation material** if every check passes. The key
is already flushed and TBS disposed before serialization starts. Plain `quote`
retains its existing behavior. The serializer independently enforces the existing
local verification checks before writing; a failed check creates no file.

The UTF-8 JSON schema is versioned. Every binary value, including PCR values,
uses **Base64**. Required fields:

| Field | Version 1 representation |
| --- | --- |
| `format` | `TPMVault.TpmQuote` |
| `version` | Integer `1` |
| `hashAlgorithm` | `SHA-256`, for PCR bank, PCR composite digest, and signature hash |
| `pcrIndexes` | `[0, 2, 4, 7]` |
| `pcrValues` | Object with decimal index keys `"0"`, `"2"`, `"4"`, `"7"`; each value is Base64 of 32 raw PCR bytes |
| `nonce` | Base64 of the original 32-byte challenge |
| `attestationFormat` | `TPMS_ATTEST` |
| `attestation` | Base64 of `Attest.GetTpmRepresentation()`: signed TPM attestation structure, **without** an outer TPM2B size prefix |
| `signatureAlgorithm` | `RSASSA-PKCS1-v1_5` |
| `signature` | Base64 of the raw 256-byte RSA signature, **without** a TPMT_SIGNATURE wrapper |
| `publicKeyFormat` | `SubjectPublicKeyInfo-DER` |
| `publicKey` | Base64 of DER-encoded X.509 SubjectPublicKeyInfo containing only the RSA modulus and exponent |

The SPKI key can be imported with `.NET RSA.ImportSubjectPublicKeyInfo` or another
standard cryptographic library. It is a public key, not a certificate, TPM private
blob, or serialized TSS.Net runtime object. No authorization values, private RSA
parameters, sensitive TPM structures, AES keys, or vault secrets are included.
No unsigned `verified: true` field is used as a substitute for future verification.

Relative output paths are resolved against the repository root embedded at build
time; absolute paths must remain within that same root. Rebuild after relocating
the repository. The parent directory must already exist. Outside paths, UNC/device
paths, alternate data streams, Windows device names, ambiguous trailing dots/spaces,
links/junctions beneath the root, and destinations under `vault`, `.git`, `.codex`,
or `.agents` are rejected. Path checks run before TPM access and again before file
creation. `FileMode.CreateNew` prevents overwriting an existing file, including a
target that appears after preflight. No output directories are created by the command.

`Deserialize` checks schema/version, required fields, binary encodings and sizes,
and the public-key structure only. It does **not** verify file authenticity, nonce
freshness, or a Quote. Use the dedicated `verify-quote` command below for offline
verification. Remote attestation and certificate trust remain out of scope.

Export validation: build passed with 0 warnings and 0 errors; **70 software-only
checks passed**, including round-trip serialization, malformed Base64, unsupported
versions, missing/null fields, traversal rejection, existing-file preservation,
and refusal to write failed verification evidence. Fixtures are synthetic and
stored only under `tests/obj`; they do not claim TPM origin. No hardware command
was run for this export milestone. The host user can run:

```text
dotnet run -- quote --output quote.json
```

## Offline Quote verification

```text
dotnet run -- verify-quote quote.json
```

This command only reads the evidence file; it never connects to TBS or the TPM,
creates keys, reads vault secrets, or changes evidence. It reuses the export path
restrictions, requires an existing regular file, and rejects links/junctions.
Evidence is limited to 64 KiB. Unknown, duplicate, missing, and null required
fields are rejected, as are unsupported formats, versions, algorithms and encodings.

The verifier parses `TPMS_ATTEST` using the TSS.Net marshaller and rejects trailing
bytes. It checks TPM magic and Quote type separately, compares the signed nonce
and SHA-256 PCR selection to the evidence, and hashes the raw 32-byte PCR values
in index order (0, 2, 4, 7) with SHA-256 to compare against the signed PCR digest.
The RSA public key is imported with `RSA.ImportSubjectPublicKeyInfo`, requiring
one canonical DER RSA-2048 SPKI value. `RSA.VerifyData` checks the signature with
SHA-256 and PKCS#1 v1.5 padding over the **original attestation bytes**.
Every check must pass for `VERIFIED` and exit code 0; failures return nonzero.

**Trust model:** this establishes internal consistency and a valid signature under
the included public key. It does not establish external trust in that key, genuine
or approved TPM origin, AIK certificates, EK trust, remote identity binding, or
Azure Attestation trust. Comparing two stored nonce values does not establish
freshness or prevent replay. An attacker able to replace the entire evidence can
sign consistent replacement evidence with their own key. Remote attestation,
enrollment, certificate trust, and server-side policy remain unimplemented.

Software tests include valid synthetic exports and tampering with nonce, type,
magic, PCR selection/values/digest, signature, public key, and JSON metadata.
They require no TPM hardware and also check read-only file handling and CLI exits.

Milestone validation: `dotnet build --no-restore` passed with 0 warnings and 0
errors; all **131 software-only checks** passed. The existing repository
`quote.json` passed all 11 offline checks and returned `Quote evidence: VERIFIED`
with exit code 0. No evidence was regenerated and no TPM/TBS access was used.

## Read-only TPM 2.0 commands

```text
dotnet run -- tpm-info
dotnet run -- pcrs
```

These commands use **Microsoft.TSS 2.1.1** (namespace `Tpm2Lib`), Microsoft's
[TSS.Net NuGet package](https://www.nuget.org/packages/Microsoft.TSS/2.1.1),
with `TbsDevice` over Windows TBS. They require an accessible TPM 2.0.
There is no simulator fallback or provisioning step.

`tpm-info` queries manufacturer and firmware properties with `GetCapability`.
Manufacturer is the raw TPM identifier; firmware is two vendor-specific 32-bit
words, printed in hexadecimal without assuming a vendor version format.

`pcrs` reads PCRs **0, 2, 4, 7** from the **SHA-256** bank with `PcrRead`.
It maps digests using the returned selection, handles partial responses, and
rejects unavailable PCRs, unexpected digest sizes, or an update-counter change
between reads. It does not fall back to SHA-1. PCR values describe current state;
they are not signed attestation evidence.

Only `GetCapability` and `PcrRead` TPM commands are issued by these two commands.
The commands do not create keys, enroll an AIK, change PCRs, or access vault entries.
TBS resources are disposed on success and failure.

Earlier validation in the restricted development environment (before the user's
successful actual-machine confirmation):
- The initial repository-local restore attempt failed with `NU1301` because
  socket access to NuGet was forbidden.
- Subsequently available project restore assets resolved Microsoft.TSS 2.1.1;
  `dotnet build --no-restore` passed with 0 warnings and 0 errors.
- Both commands were run with `--no-build --no-restore`. Each exited with code 1:
  `Exception: Can't create TBS context: Error {TbsInternalError}`.
- Compilation and dependency loading were verified in that run. The user has
  since confirmed successful connection, capability queries, and PCR reads on
  the actual machine. Sandbox results do not invalidate that confirmation.

On a machine where normal NuGet restore and TBS access are permitted, run
`dotnet build` followed by the two commands above. The application does not
request elevation or change platform configuration.

## Attestation experiment

The attestation path uses a separate TPM identity key:

- Provider: Microsoft Platform Crypto Provider
- Key name: `TPMVault.AttestationKeyV1`
- RSA size: 2048 bits
- PCP key usage policy: `NCRYPT_PCP_IDENTITY_KEY` (`0x8`)

The command:

```text
dotnet run -- attest
```

creates or opens this identity key and requests an `NCRYPT_CLAIM_PLATFORM`
claim with:

- PCR mask buffer type 80
- nonce buffer type 81
- PCR mask selecting PCRs 0 through 23
- a fresh random 32-byte nonce

This is an experimental local TPM attestation path. Platform attestation also
depends on Windows TPM/AIK provisioning. A failure status is printed verbatim
instead of being treated as proof that attestation succeeded.
