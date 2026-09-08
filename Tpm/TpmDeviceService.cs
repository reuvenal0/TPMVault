using Tpm2Lib;

namespace TPMVault.Tpm;

/// <summary>
/// Owns Windows TBS access for capability/PCR reads and the internal Quote service.
/// Instances are used on one thread and own their TBS connection.
/// </summary>
public sealed class TpmDeviceService : IDisposable
{
    private readonly Tpm2 _tpm;
    private bool _disposed;

    // Shared connection for the focused Quote service; not exposed to CLI code.
    internal Tpm2 Commands
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _tpm;
        }
    }

    public TpmDeviceService()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("TPM access requires Windows TBS.");
        }

        Tpm2Device device = new TbsDevice();
        try
        {
            device.Connect();
            _tpm = new Tpm2(device);
        }
        catch
        {
            device.Dispose();
            throw;
        }
    }

    public TpmInformation GetInformation()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Each query requests exactly one property and validates its returned tag.
        // Firmware words are vendor-specific; report the raw values, not a guessed version.
        return new TpmInformation(
            ReadProperty(Pt.Manufacturer),
            ReadProperty(Pt.FirmwareVersion1),
            ReadProperty(Pt.FirmwareVersion2));
    }

    private uint ReadProperty(Pt property)
    {
        _tpm.GetCapability(Cap.TpmProperties, (uint)property, 1, out var capability);
        if (capability is not TaggedTpmPropertyArray properties ||
            properties.tpmProperty is not { Length: 1 } ||
            properties.tpmProperty[0].property != property)
        {
            throw new InvalidOperationException($"TPM did not return property {property}.");
        }

        return properties.tpmProperty[0].value;
    }

    public IReadOnlyDictionary<uint, string> ReadSha256Pcrs()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var pending = new SortedSet<uint> { 0, 2, 4, 7 };
        var result = new SortedDictionary<uint, string>();
        uint? updateCounter = null;

        // PCR_Read may return only part of the requested selection. Map digests
        // using the returned selection, then request only the remaining PCRs.
        while (pending.Count > 0)
        {
            PcrSelection[] requested =
                [new PcrSelection(TpmAlgId.Sha256, pending.ToArray())];
            uint currentCounter = _tpm.PcrRead(requested, out var selected, out var digests);

            if (updateCounter.HasValue && updateCounter.Value != currentCounter)
            {
                throw new InvalidOperationException("PCRs changed during the read. Run pcrs again.");
            }
            updateCounter = currentCounter;

            if (selected is not { Length: 1 } || selected[0].hash != TpmAlgId.Sha256)
            {
                throw new InvalidOperationException("TPM did not return the requested SHA-256 PCR bank.");
            }

            uint[] indexes = selected[0].GetSelectedPcrs();
            if (indexes.Length == 0 || digests is null || indexes.Length != digests.Length)
            {
                throw new InvalidOperationException("Requested SHA-256 PCRs are unavailable or the TPM returned an incomplete response.");
            }

            for (int i = 0; i < indexes.Length; i++)
            {
                if (!pending.Remove(indexes[i]) || digests[i]?.buffer is not { Length: 32 })
                {
                    throw new InvalidOperationException("TPM returned an unexpected PCR selection or digest length.");
                }

                result.Add(indexes[i], Convert.ToHexString(digests[i].buffer));
            }
        }

        return result;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        // Tpm2.Dispose also disposes its Tpm2Device, closing the TBS context.
        _tpm.Dispose();
    }
}

public sealed record TpmInformation(
    uint Manufacturer,
    uint FirmwareVersion1,
    uint FirmwareVersion2);
