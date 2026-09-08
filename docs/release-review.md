# Final cleanup review

## Scope and verification

The read-only review covered every production/test C# file, both project files,
README, `.gitignore`, namespaces, CLI routes, native declarations and ownership,
and the tracked-file inventory. Generated build artifacts and private runtime
Vault contents were not treated as source or read for secret inspection.

Final results:

| Check | Result |
| --- | --- |
| `dotnet build --no-restore` | 0 warnings, 0 errors |
| `dotnet build -c Release --no-restore` | 0 warnings, 0 errors |
| Console software suite, Debug | 180 checks passed |
| Console software suite, Release | 180 checks passed |
| `verify-quote quote.json` (existing file) | All 11 checks valid; `Quote evidence: VERIFIED`; exit 0 |
| `git diff --check` | No whitespace errors; Git reported normal LF/CRLF normalization notices |

The suite preserves the original 131 checks and adds 49 justified regression
checks. Tests use software-generated RSA and synthetic files under `tests/obj/`;
they do not open TBS or create persistent keys. The existing hardware evidence
was read, not regenerated or modified. No hardware command, persistent-key
operation, Vault mutation, system configuration change, or elevation was used.

## Findings and fixes

| Category | Finding | Action |
| --- | --- | --- |
| Correctness / security | `get` called `GetOrCreateKey` | Added `KeyManager.GetExistingKey`; validate entry before opening key; no creation fallback |
| Safety | Bare invocation ran the TPM demo; `software`, `tpm`, `list` ignored extra arguments | Bare invocation now shows usage/nonzero; extra arguments fail before execution |
| Safety | Invalid `put` requests could create a key before name/size validation | Added non-mutating write preflight before opening/creating the key |
| Robustness | Vault JSON allowed absent/null fields; backend dereference could throw | Added strict version-1 parsing with controlled `InvalidDataException` messages |
| Robustness | Vault sizes, Base64 and cryptographic field lengths were unchecked before use | Validate 256-byte wrapped key, 12-byte nonce, 16-byte tag, ciphertext presence and input limits; enforce 32-byte unwrapped AES key |
| Robustness | CLI did not catch `InvalidDataException` (it is not an `IOException`) | Catch it explicitly, including oversized evidence errors |
| Security | Vault paths relied on filename validation and the process working directory; links were not rejected | Shared checkout-anchored path policy rejects outside paths, device names, streams and reparse points |
| Sensitive data | Interactive secret input was echoed | Read interactive input without echo; retain redirected-input support and document string lifetime limitations |
| Correctness | A false RSA demo verification result still returned success | Raise a controlled cryptographic error after displaying failure |
| Maintainability | Production files were flat and shared one namespace | Grouped source by responsibility; kept the simple CLI coordinator and minimal entry point |
| Maintainability | Tests referenced only Debug DLLs by path | Use a project reference, verified in Debug and Release |
| Documentation | TBS service summary incorrectly implied it was exclusively read-only | Explain its connection ownership and internal use by Quote |
| Experimental | CNG comments/output could imply working attestation or a newly created key when one was opened | Label all experimental service summaries and CLI diagnostics accurately; preserve unresolved native invocation |
| Repository hygiene | `.vs/` was not ignored; local `quote.json` ignore was a pre-existing working-tree change | Add `.vs/`, preserve `quote.json` ignore and evidence itself |
| Documentation | README mixed old build counts and chronological sandbox logs with public usage | Rewrite as a project guide; retain meaningful unsuccessful CNG investigation separately |

No obvious embedded credentials or private-key literals were found in the reviewed
source/configuration. No generated binaries or runtime evidence were tracked in
the inspected index. This is a working-tree review, not a forensic audit of all
Git history or a formal security certification.

## Organization and file inventory

Before: all 22 production `.cs` files were in the root, with three test `.cs`
files under `tests/`. README, project and ignore files were at the root.

Twenty existing production files moved without deleting their functionality:

| Destination | Files moved from root | Responsibility |
| --- | --- | --- |
| `Configuration/` | `KeyBackend.cs`, `KeyConfiguration.cs` | Backend settings |
| `Crypto/` | `CryptoDemoService.cs`, `KeyManager.cs`, `StoredKeyInfo.cs` | CNG RSA management and demonstrations |
| `Storage/` | `VaultService.cs`, `VaultEntry.cs`, `VaultEntryMetadata.cs` | Encrypted storage; namespace `TPMVault.Vault` |
| `Native/` | `NativeMethods.cs`, `KeyEnumerator.cs` | Interop and CNG enumeration |
| `Tpm/` | `TpmDeviceService.cs` | TBS lifecycle, capability/PCR reads |
| `Tpm/Quote/` | `TpmQuoteService.cs`, `TpmQuoteEvidence.cs`, `TpmQuoteVerifier.cs`, `TpmQuoteEvidenceFile.cs`, `TpmQuoteEvidenceSerializer.cs`, `TpmQuoteEvidenceVerifier.cs` | Working Quote and portable evidence flow |
| `Tpm/Experimental/` | `AttestationKeyManager.cs`, `AttestationService.cs`, `AttestationResult.cs` | Unsuccessful CNG experiment |

`Storage/` avoids a Windows case-insensitive collision between source `Vault/`
and runtime `vault/`. Production namespaces follow the new responsibility groups;
test helpers use `TPMVault.Tests`.

Added files:

- `Configuration/RepositoryPaths.cs`: shared runtime path rules.
- `Storage/VaultEntrySerializer.cs`: focused encrypted-format validation.
- `tests/VaultValidationChecks.cs`: software-only Vault and CLI regressions.
- `docs/experimental-cng-attestation.md`: retained investigation notes.
- `docs/release-review.md`: this review and results.

Changed in place: `TpmVaultApp.cs`, `README.md`, `.gitignore`,
`tests/Program.cs`, `tests/EvidenceSerializationChecks.cs`,
`tests/QuoteEvidenceVerificationChecks.cs`, and `tests/QuoteVerifierChecks.csproj`.
Moved files have namespace/import changes; functional edits are concentrated in
`KeyManager`, `CryptoDemoService`, `VaultService`, and evidence path delegation.
`TpmDeviceService` and experimental service summaries were clarified.
`Program.cs` and `TPMVault.csproj` remain unchanged. No functionality was removed.

## Preserved security behavior

- AES keys, plaintext arrays and temporary exported software-private-key arrays
  were already cleared in `finally`; that cleanup remains. No claim is made that
  immutable strings or terminal logs can be securely erased.
- CNG `using` lifetimes and the single duplicated `CngKey.Handle` ownership pattern
  were preserved. `DangerousAddRef`/`DangerousRelease`, pinned inputs and native
  memory cleanup remain balanced. No native parameter experiments were made.
- Quote still uses a transient null-hierarchy RSA key and flushes its returned
  handle in `finally`; TBS disposal and cleanup-error propagation remain intact.
- PCR digest verification still hashes raw PCR bytes in index order. Offline
  signatures still cover the original serialized `TPMS_ATTEST` bytes. SPKI exports
  remain public-only. No verification check was removed or weakened.
- `dotnet run -- attest` remains available. `NCryptCreateClaim /
  NCRYPT_CLAIM_PLATFORM` remains experimental and unresolved at `0x80070057`;
  this existing failure is not a cleanup regression.

## Remaining limitations and publication

**Ready with minor caveats** for a student portfolio, with the documented scope:

- Hardware paths were reviewed and compiled, not rerun during cleanup. Host
  hardware success predates this pass; missing-key CNG behavior was inspected
  statically rather than tested by creating/deleting real keys.
- Offline consistency is not trusted remote attestation, device identity,
  AIK/EK/certificate trust, freshness, replay protection or Azure Attestation trust.
- Vault v1 does not authenticate entry names/metadata as associated data, provide
  rollback prevention, or implement transactional/durable replacement. Existing
  `put` replacement semantics are preserved; back up important data.
- Path checks reject existing links but do not claim atomic protection against
  hostile concurrent directory replacement. The checkout must be trusted.
- New Vault size limits intentionally reject oversized historical entries;
  no runtime entries were inspected or migrated.
- Checkout anchoring uses build metadata: rebuild after moving the source. Do
  not distribute local build artifacts as a relocatable installed product.
- No project license was present. Choose a license before offering reuse rights;
  no license or copyright ownership was invented by this cleanup.
- Local `quote.json` and `vault/` remain ignored, intact, and unpublished. Review
  any differently named evidence files before committing. No commit, remote
  change, history rewrite, publication, or release tag was performed.
