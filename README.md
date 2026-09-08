# TPMVault

TPMVault demonstrates software-backed and TPM-backed cryptographic keys on
Windows and uses them to protect encrypted vault entries.

## Status

Working (existing functionality):
- TPM-backed secure storage
- TBS/TSS.Net TPM connection (confirmed by the user on the actual machine)
- TPM capability query (confirmed by the user)
- SHA-256 PCR reading (confirmed by the user)

Implemented; actual-machine Quote verification pending:
- Transient TPM2 Quote and independent local verification checks

Experimental:
- NCryptCreateClaim platform-claim path (currently returns `0x80070057`)

Not implemented yet:
- Remote attestation
- AIK enrollment and certificate trust
- Server-side verification

## Local TPM Quote

```text
dotnet run -- quote
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
checks. Evidence stays in memory; no private material or evidence is written to disk.

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

Actual-machine verification is pending. No connectivity or configuration changes
were attempted. To repeat the software-only checks after a Debug build:

```text
dotnet restore tests/QuoteVerifierChecks.csproj --source .
dotnet run --project tests/QuoteVerifierChecks.csproj --no-restore
```

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
