# TPMVault

TPMVault demonstrates software-backed and TPM-backed cryptographic keys on
Windows and uses them to protect encrypted vault entries.

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
