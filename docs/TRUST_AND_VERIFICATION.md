# Trust, release verification and false positives

LuckyGuard is security software. Users should be able to verify where an executable came from and whether the bytes they received are the bytes the project published.

## Official distribution boundary

The only official source repository is:

`https://github.com/Malthaeel/LuckyGuard`

Stable binaries should be obtained from that repository's GitHub Releases or through the repository's `install.ps1` bootstrap. Mirrors, reuploads and renamed executables are outside the project's trust boundary.

## Release evidence

A stable LuckyGuard release is expected to publish:

1. the versioned portable ZIP;
2. the versioned signed installer;
3. `LuckyGuard-Setup-win-x64.exe` stable installer alias;
4. `SHA256SUMS.txt`;
5. `release-manifest.json`;
6. `TRUST-EVIDENCE.md`.

`TRUST-EVIDENCE.md` is generated from the final packaged bytes and contains SHA-256 hashes, Authenticode state where applicable, official release locations and VirusTotal hash lookup links.

## Why VirusTotal is generated after signing

Authenticode signing changes the executable bytes and therefore changes the SHA-256. Uploading a pre-signing build to VirusTotal and later pointing users at that report would prove nothing about the final signed installer.

LuckyGuard therefore publishes VirusTotal evidence for the **frozen, final signed artifact**.

VirusTotal file reports are addressed by a cryptographic file hash. The project uses the SHA-256 form:

`https://www.virustotal.com/gui/file/<SHA256>`

A report can change over time as engines reclassify a file. VirusTotal is useful transparency evidence but is not a guarantee of safety.

## Local SHA-256 verification

```powershell
Get-FileHash .\LuckyGuard-Setup-win-x64.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

The hash must match the release checksum exactly.

## Authenticode verification

```powershell
$sig = Get-AuthenticodeSignature .\LuckyGuard-Setup-win-x64.exe
$sig | Format-List Status,StatusMessage,SignerCertificate
```

Stable public releases require `Status = Valid`. Compare the full signer subject with the publisher documented in the corresponding release evidence.

## GitHub release digest verification

During publication, LuckyGuard re-queries the GitHub Releases API after upload. Every uploaded asset must have a GitHub `sha256:` digest equal to the local file SHA-256 or publication fails.

This protects against publishing one set of bytes while documenting hashes for another.

## Source review

Users who do not want to trust distributed binaries can build from the public source tag:

```powershell
git clone https://github.com/Malthaeel/LuckyGuard.git
cd LuckyGuard
.\scripts\build.cmd
.\scripts\test.cmd
```

A locally built binary will not necessarily have the same hash as the official signed artifact because Authenticode signing, build environment details and timestamps affect final bytes.

## False positives

Endpoint-security software performs operations that heuristic engines intentionally monitor. LuckyGuard reads process, persistence, service, executable and network metadata and can install a Windows Service. That can attract scrutiny even when the behavior is defensive.

LuckyGuard does not rely on "0 detections" marketing. When reviewing a detection:

1. verify the downloaded SHA-256 against the official release;
2. verify the Authenticode signer;
3. open the VirusTotal report for that exact SHA-256;
4. note which engine and detection family fired;
5. compare the behavior with the open source implementation;
6. report suspected false positives with the exact release/hash.

The maintainer should submit confirmed false positives to the affected vendor. Microsoft provides a file submission flow that accepts files believed to be incorrectly identified as malware.

## What would invalidate trust

Do not run a binary as an official LuckyGuard release if any of the following is true:

- it was downloaded from an unofficial mirror;
- its SHA-256 differs from `SHA256SUMS.txt`;
- the stable installer is unsigned or Authenticode is invalid;
- its publisher differs from the release's documented publisher;
- the release metadata and GitHub asset digest disagree;
- a third party modified/repacked the installer after publication.

## Vendor false-positive submission

For Microsoft Defender, the official Microsoft Security Intelligence file submission portal is:

`https://www.microsoft.com/wdsi/filesubmission`

Submit only the final official signed artifact and keep the generated submission/reference ID with the release-maintainer notes.
