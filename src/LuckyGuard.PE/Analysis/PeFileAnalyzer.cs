using System.Buffers.Binary;
using System.Text;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.PE.Analysis;

public sealed class PeFileAnalyzer
{
    private const uint ImageScnMemExecute = 0x20000000;
    private const uint ImageScnMemRead = 0x40000000;
    private const uint ImageScnMemWrite = 0x80000000;

    public IReadOnlyList<DetectionFinding> Analyze(string path, long maxFileBytes)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length < 0x100 || info.Length > maxFileBytes) return Array.Empty<DetectionFinding>();
        return AnalyzeBytes(File.ReadAllBytes(path), path);
    }

    public IReadOnlyList<DetectionFinding> AnalyzeBytes(byte[] data, string displayPath)
    {
        var findings = new List<DetectionFinding>();
        if (data.Length < 0x40 || data[0] != (byte)'M' || data[1] != (byte)'Z') return findings;

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3C, 4));
        if (peOffset < 0x40 || peOffset > data.Length - 24) return findings;
        if (data[peOffset] != (byte)'P' || data[peOffset + 1] != (byte)'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0) return findings;

        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(peOffset + 6, 2));
        ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(peOffset + 20, 2));
        int optionalOffset = peOffset + 24;
        if (optionalHeaderSize < 20 || optionalOffset > data.Length - optionalHeaderSize) return findings;

        uint entryPointRva = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(optionalOffset + 16, 4));
        int sectionTable = optionalOffset + optionalHeaderSize;
        if (sectionCount == 0 || sectionCount > 96 || sectionTable > data.Length - (sectionCount * 40)) return findings;

        bool rcdFound = false;
        bool entryInRcd = false;
        for (int i = 0; i < sectionCount; i++)
        {
            int o = sectionTable + (i * 40);
            string name = Encoding.ASCII.GetString(data, o, 8).TrimEnd('\0');
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(o + 8, 4));
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(o + 12, 4));
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(o + 16, 4));
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(o + 36, 4));
            bool executable = (characteristics & ImageScnMemExecute) != 0;
            bool readable = (characteristics & ImageScnMemRead) != 0;
            bool writable = (characteristics & ImageScnMemWrite) != 0;
            uint mappedSize = Math.Max(virtualSize, rawSize);
            bool entryInside = mappedSize > 0 && entryPointRva >= virtualAddress && entryPointRva < virtualAddress + mappedSize;

            if (name.StartsWith(".rcd", StringComparison.OrdinalIgnoreCase))
            {
                rcdFound = true;
                entryInRcd |= entryInside;
                findings.Add(new DetectionFinding(
                    "LW.PE.RCD_SECTION",
                    "LuckyWare-style .rcd PE section",
                    DetectionCategory.PE,
                    executable ? DetectionSeverity.High : DetectionSeverity.Suspicious,
                    DetectionConfidence.Community,
                    executable
                        ? $"PE section '{name}' matches the community-reported LuckyWare .rcd* pattern and is executable."
                        : $"PE section '{name}' matches the community-reported LuckyWare .rcd* pattern.",
                    displayPath,
                    [new Evidence("section", name), new Evidence("executable", executable.ToString()), new Evidence("entryPointInside", entryInside.ToString())]));
            }

            if (executable && readable && writable)
            {
                findings.Add(new DetectionFinding(
                    "LG.PE.RWX_SECTION",
                    "Writable executable PE section",
                    DetectionCategory.PE,
                    DetectionSeverity.Suspicious,
                    DetectionConfidence.Heuristic,
                    $"Section '{name}' is readable, writable, and executable. This can be legitimate for some packers/JIT stubs and is not LuckyWare-specific.",
                    displayPath,
                    [new Evidence("section", name)]));
            }
        }

        if (rcdFound && entryInRcd)
        {
            findings.Add(new DetectionFinding(
                "LW.PE.ENTRYPOINT_RCD",
                "PE entry point is inside .rcd section",
                DetectionCategory.PE,
                DetectionSeverity.Critical,
                DetectionConfidence.Community,
                "The executable entry point resolves inside a LuckyWare-style .rcd* section. This is a high-value infection indicator.",
                displayPath));
        }

        return findings;
    }
}
