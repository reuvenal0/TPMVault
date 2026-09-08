# Experimental CNG platform attestation

The `attest` command is retained for education and debugging. Its implementation
is in `Tpm/Experimental/`; its native declarations remain in `Native/NativeMethods.cs`.
It has **not** demonstrated successful Windows platform attestation.

The observed sequence is:

1. Open/create `TPMVault.AttestationKeyV1` through Microsoft Platform Crypto Provider.
2. Request RSA-2048 with `PCP_KEY_USAGE_POLICY = NCRYPT_PCP_IDENTITY_KEY` (`0x8`).
3. Call `NCryptCreateClaim` with `NCRYPT_CLAIM_PLATFORM` (`0x00010000`), the
   identity-style key as subject, and a null authority handle.
4. Supply a DWORD PCR mask `0x00FFFFFF` using buffer type 80 and a fresh 32-byte
   nonce using buffer type 81, through an `NCryptBufferDesc`.
5. Attempt a null-output sizing call followed by a claim-output call.

The platform-claim operation returns `0x80070057` (`E_INVALIDARG`). This HRESULT
does not identify which parameter or provisioning assumption was rejected.
The above describes the attempted invocation, **not a validated recipe**.
An identity-style CNG key alone has not been shown here to satisfy the Windows
platform-claim requirements. No claim verification is implemented on this path.

The retained code duplicates `CngKey.Handle` once, keeps that same safe handle
alive for both calls with balanced `DangerousAddRef`/`DangerousRelease`, pins its
input buffers, and frees native memory in `finally`. These lifetime safeguards
do not establish that the claim parameters or architectural assumptions are correct.

The final cleanup deliberately leaves this experiment unresolved. It does not
alter provisioning, enroll an AIK, or try alternative claim parameters.
Running `attest` may create a persistent identity-style key; it is excluded from
automated software tests and final cleanup verification.

The working flow is separate: Microsoft.TSS/Tpm2Lib over Windows TBS issues
`TPM2_Quote` using a transient RSA key. The host has demonstrated local Quote
verification, and exported evidence has passed offline consistency verification.
Use `quote` for that hardware flow and `verify-quote` for existing evidence.
