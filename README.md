# n8n-nodes-encrypted-zip

Extract password-protected ZIP archives inside n8n. The password stays in an n8n credential, and decryption runs in memory.

The package provides one node, **Encrypted ZIP**, with one operation, **Extract**. It reads a ZIP archive from a binary field and outputs every file in it as a separate item with binary data. Supported encryption:

- WinZip AES-128, AES-192 and AES-256, shown by 7-Zip as `AES-256`
- PKWARE strong encryption with a password and AES-128, AES-192 or AES-256, shown by 7-Zip as `pkAES-256` and `StrongCrypto`. Such entries must use Store or Deflate compression.
- Legacy ZipCrypto

`.7z` archives are not supported, and the node does not create archives.

> [!WARNING]
> This is an unverified community package for self-hosted n8n. It is not available on n8n Cloud. n8n 3.0 changes `N8N_UNVERIFIED_PACKAGES_ENABLED` from `true` to `false`. Set it to `true` before upgrading if this package must keep loading, or use the pinned-checksum environment-managed installation described below.

## Installation

Package name:

```text
n8n-nodes-encrypted-zip
```

### Settings

An Owner or Admin can install the package from the n8n editor:

1. Open **Settings**.
2. Select **Community Nodes**.
3. Select **Install**.
4. Enter `n8n-nodes-encrypted-zip`.
5. Review and accept the warning for unverified community code.
6. Select **Install**.

The node appears as **Encrypted ZIP** after installation.

### Manual container installation

Use this path for queue-mode deployments, private registries, or installations where the Community Nodes settings page is unavailable.

Open a shell in the running n8n container:

```sh
docker exec -it <n8n-container> sh
```

Install the package under the n8n user folder:

```sh
mkdir -p ~/.n8n/nodes
cd ~/.n8n/nodes
npm install n8n-nodes-encrypted-zip
```

Restart every n8n process that loads community nodes. In queue mode, install the package in the shared image or persistent user folder used by both the main and worker processes.

### Environment-managed installation

n8n 2.21.0 and later can reconcile community packages from environment variables. Pin both the package version and registry integrity value:

```sh
npm view n8n-nodes-encrypted-zip version
npm view n8n-nodes-encrypted-zip dist.integrity
```

Configure the instance with those values:

```sh
N8N_COMMUNITY_PACKAGES_MANAGED_BY_ENV=true
N8N_COMMUNITY_PACKAGES='[{"name":"n8n-nodes-encrypted-zip","version":"<version>","checksum":"<sha512-integrity>"}]'
```

Enabling environment-managed packages uninstalls community packages that are not listed in `N8N_COMMUNITY_PACKAGES`. Add every package the instance must keep, including `n8n-nodes-openpgp` if it is installed, before restarting.

## Credential setup

Create a **ZIP Password** credential for each archive password.

| Field | Value |
|---|---|
| Password | The password the archive was encrypted with |

n8n stores the password encrypted, and it never appears in workflow parameters, version history or exports. The same field opens WinZip AES, PKWARE strong encryption and ZipCrypto entries.

The credential has no **Test** button: a ZIP password can only be checked against an archive. The first execution reports a wrong password clearly.

## Usage

Typical workflow:

```text
SFTP (Download)  ->  Encrypted ZIP (Extract)  ->  ...
```

| Control | Purpose |
|---|---|
| Credential to connect with | The **ZIP Password** credential. Required |
| Input Data Field Name | Binary field holding the archive, default `data` |
| Output Data Field Name | Binary field each extracted file is written to, default `data` |
| Options → Expected Entry Name | Require exactly one file with exactly this name |

### Output

Each file entry becomes one output item, paired with the input item that held the archive. Folder entries are skipped.

```json
{
  "entryName": "reports/daily.txt",
  "uncompressedSize": 48213,
  "lastModified": "2026-11-12T08:30:00.000Z"
}
```

| Field | Meaning |
|---|---|
| `entryName` | The entry's full path inside the archive |
| `uncompressedSize` | Size of the extracted data in bytes |
| `lastModified` | The entry's modified time as ISO 8601, or `null` when the archive stores none |

The binary file name is the entry name without its folder path. ZIP files store most modified times without a time zone. The node reads them in the n8n process's time zone; an archive with an extended timestamp field gives UTC.

The node writes classic per-item binary fields, so it works in workflows with the `binaryMode: separate` setting. The smoke test runs with that setting.

### Expected Entry Name

Leave the option empty to output every file in the archive. When set, the archive must contain exactly one file entry, and its entry name must match exactly, including any folder path and letter case. The node checks this before decrypting anything.

### Errors

Every error names the input item. None includes the password.

| Failure | Message starts with |
|---|---|
| Wrong password | `The password in the 'ZIP Password' credential does not open this archive` |
| Unsupported encryption, such as PKWARE strong encryption with 3DES or certificates | `The archive uses an encryption method this node cannot decrypt` |
| Failed CRC-32 or AES authentication check | `An entry failed its integrity check` |
| Damaged or non-ZIP input | `The input is not a readable ZIP archive` |
| `.7z` input | `The input is a 7z archive, which this node does not read` |
| No file entries | `The archive contains no files` |
| Expected Entry Name set, more than one file | `The archive must contain exactly one file` |
| Expected Entry Name set, different name | `The archive's only file is not the expected entry` |

An archive with no file entries always fails, so an empty delivery cannot pass silently as zero items.

ZipCrypto checks only one byte of the password, so roughly one wrong password in 256 passes that check. The CRC-32 check then fails, and the error says the password may be wrong.

PKWARE strong encryption has no authentication code: the node checks the password against the archive's password verification data, then checks the decrypted entry against its CRC-32.

The node follows n8n's **On Error** setting. With Continue selected, a failing input item produces an error item and later items continue.

## Security and verification status

- The password comes only from the **ZIP Password** credential. The node has no password parameter.
- The node decrypts in memory and never writes plain text to disk itself. After extraction, n8n stores the output binary data according to the instance's binary data mode. In `filesystem` mode, n8n keeps execution binary data under its storage path until execution data is pruned. Choose the binary data mode and execution-data retention with that in mind.
- No command runs, so the password never appears in the host's process list.

This package is unverified because it ships `@zip.js/zip.js` as a runtime dependency. The n8n scanner reports:

```text
@n8n/community-nodes/no-runtime-dependencies
```

The dependency is deliberate and pinned. Releases are published from GitHub Actions through npm Trusted Publishers with provenance and no long-lived npm token.

## Known limitations

- The package is for self-hosted n8n. n8n Cloud cannot install it.
- The node buffers the whole archive and each extracted file in memory.
- Extract only: the node does not create or modify archives.
- `.7z` and split archives are not supported.
- PKWARE strong encryption is supported only with a password and AES. 3DES, RC2, RC4, certificate recipients and an encrypted central directory are not supported, and strong-encrypted entries compressed with Deflate64 are not read.

## Development

Requirements:

- Node.js 22.22.0 or later
- npm
- Docker, for the smoke test

```sh
npm ci
npm run lint:ci
npm run build
npm test
npm run smoke
```

Unit tests generate their archives with synthetic content, and no fixture holds real data. Archives with PKWARE strong encryption come from `test/helpers/strongArchive.ts`, written from the ZIP specification because zip.js cannot write them; 7-Zip 26.01 extracts its output. The smoke test installs the packed package into a real n8n container. It extracts freshly generated AES-256, PKWARE strong encryption AES-256 and ZipCrypto archives and compares the extracted bytes with the originals. It also checks that a wrong password fails without either password appearing in n8n's output.

Start an n8n development instance:

```sh
npm run dev
```

## Support

Report reproducible defects through [GitHub Issues](https://github.com/calvertjadon/n8n-nodes-encrypted-zip/issues). Include the n8n version, package version, the tool that created the archive, and the complete error message. Never attach passwords or real archives.

## License

[MIT](LICENSE)
