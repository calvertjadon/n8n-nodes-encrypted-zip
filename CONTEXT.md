# n8n-nodes-encrypted-zip

Domain language for the Encrypted ZIP community node for n8n: opening password-protected ZIP archives inside a workflow without exposing the password or writing decrypted data to disk.

## Language

### Archives

**Archive**:
A ZIP file received as n8n binary data. `.7z` files are not archives in this sense.
_Avoid_: zip, bundle, package

**Entry**:
One record inside an archive. A **file entry** holds data; a **folder entry** only names a path and is never output or counted.
_Avoid_: member (a member is a credit union customer), item (an n8n item)

**Entry name**:
The entry's full path inside the archive, as stored, e.g. `reports/daily.txt`. Compared exactly and case-sensitively.
_Avoid_: file name (the output binary's file name drops the folder path)

**Expected entry name**:
The option that pins an archive to exactly one file entry with exactly that entry name. Anything else fails the item.

### Encryption

**WinZip AES**:
AES-128, AES-192 or AES-256 entry encryption with an HMAC authentication code, as written by WinZip and 7-Zip (`AES-256` in 7-Zip's listing).
_Avoid_: AE-x

**PKWARE strong encryption**:
PKWARE's own AES entry encryption from the ZIP specification's Strong Encryption Specification, shown by 7-Zip as `pkAES-256` and `StrongCrypto`. It has no authentication code. Supported with a password and AES only; its 3DES, RC2 and RC4 algorithms, certificate recipients and central directory encryption are not.
_Avoid_: SES, pkAES (as a term), strong AES

**ZipCrypto**:
The legacy PKWARE stream cipher. Weak, and supported only so existing archives stay readable.
_Avoid_: traditional encryption, PKZIP encryption

**Integrity check**:
The CRC-32 checksum or the AES authentication code an entry's data is verified against after decryption.

### Secrets

**ZIP Password credential**:
The n8n credential (`zipPasswordApi`) that holds an archive's password. The only source of the password: the node has no password parameter.
_Avoid_: archive key, passphrase
