import { createDecipheriv, createHash } from 'node:crypto';
import { Uint8ArrayWriter, type FileEntry } from '@zip.js/zip.js';
import { classifyZipError, extractError, type ExtractError } from './errors';

/**
 * PKWARE strong encryption (APPNOTE section 7), the password-based AES subset
 * that 7-Zip also reads. The entry's data starts with a decryption header; the
 * compressed data follows, AES-CBC encrypted with PKCS#7 padding. Certificate
 * recipients and the other algorithms of the specification are rejected.
 */

/** General purpose bit 6: the entry uses strong encryption. */
const STRONG_ENCRYPTION_FLAG = 0x40;

const AES_BLOCK_SIZE = 16;

/** Key length in bytes per AES algorithm ID. */
const AES_KEY_LENGTHS: Record<number, number> = { 0x660e: 16, 0x660f: 24, 0x6610: 32 };

/** The specification's other algorithm IDs, named in the unsupported-encryption error. */
const OTHER_ALGORITHMS: Record<number, string> = {
	0x6601: 'DES',
	0x6602: 'RC2',
	0x6603: '3DES-168',
	0x6609: '3DES-112',
	0x6702: 'RC2',
	0x6720: 'Blowfish',
	0x6721: 'Twofish',
	0x6801: 'RC4',
};

const FLAG_PASSWORD = 0x0001;
const FLAG_CERTIFICATES = 0x0002;
/** The random data is encrypted with 3DES whatever the file algorithm. */
const FLAG_3DES_RANDOM_DATA = 0x4000;

const COMPRESSION_STORE = 0;
const COMPRESSION_DEFLATE = 8;

export function isStrongEncrypted(entry: FileEntry): boolean {
	return entry.encrypted && ((entry.rawBitFlag ?? 0) & STRONG_ENCRYPTION_FLAG) !== 0;
}

/** Decrypts, decompresses and verifies one strong-encrypted entry. */
export async function readStrongEntry(entry: FileEntry, password: string): Promise<Uint8Array> {
	const suffix = ` (entry "${entry.filename}")`;
	if (
		entry.compressionMethod !== COMPRESSION_STORE &&
		entry.compressionMethod !== COMPRESSION_DEFLATE
	) {
		throw extractError('unsupportedCompression', {
			detail: 'Entries with PKWARE strong encryption are read with Store and Deflate only.',
			suffix,
		});
	}
	let stored: Uint8Array;
	try {
		// The entry's bytes as stored: decryption header, then ciphertext.
		stored = await entry.getData(new Uint8ArrayWriter(), { passThrough: true });
	} catch (error) {
		throw classifyZipError(error, password, entry);
	}
	const compressed = decrypt(stored, entry, password, suffix);
	const content =
		entry.compressionMethod === COMPRESSION_DEFLATE
			? await inflate(compressed, entry.uncompressedSize, suffix)
			: compressed;
	if (content.byteLength !== entry.uncompressedSize || crc32(content) !== entry.crc32) {
		throw extractError('integrityCheckFailed', { suffix });
	}
	return content;
}

/** Reads the decryption header, checks the password and returns the compressed data. */
function decrypt(stored: Uint8Array, entry: FileEntry, password: string, suffix: string): Buffer {
	const data = Buffer.from(stored.buffer, stored.byteOffset, stored.byteLength);
	const malformed = (): ExtractError =>
		extractError('corruptArchive', {
			detail: `The PKWARE strong encryption header of entry "${entry.filename}" is damaged.`,
		});
	const unsupported = (reason: string): ExtractError =>
		extractError('unsupportedEncryption', { suffix, detail: `This entry ${reason}.` });

	if (data.length < 2) throw malformed();
	const ivSize = data.readUInt16LE(0);
	let iv: Buffer;
	/** The IV bytes the file key is derived from. */
	let keyIv: Buffer;
	if (ivSize === 0) {
		// No stored IV: the CRC-32 and the 64-bit uncompressed size stand in for it.
		iv = Buffer.alloc(AES_BLOCK_SIZE);
		iv.writeUInt32LE(entry.crc32 ?? 0, 0);
		iv.writeBigUInt64LE(BigInt(entry.uncompressedSize), 4);
		keyIv = iv.subarray(0, 12);
	} else if (ivSize === AES_BLOCK_SIZE) {
		iv = data.subarray(2, 2 + ivSize);
		keyIv = iv;
	} else {
		throw unsupported(`stores a ${ivSize}-byte initialization vector, which AES does not use`);
	}

	let offset = 2 + ivSize;
	if (data.length < offset + 4) throw malformed();
	const headerSize = data.readUInt32LE(offset);
	offset += 4;
	const headerEnd = offset + headerSize;
	// Format, algorithm, bit length, flags and random data size, then the
	// reserved field and the validation data size around the random data.
	if (headerSize < 16 || data.length < headerEnd) throw malformed();
	const format = data.readUInt16LE(offset);
	const algorithm = data.readUInt16LE(offset + 2);
	const bitLength = data.readUInt16LE(offset + 4);
	const flags = data.readUInt16LE(offset + 6);
	const randomSize = data.readUInt16LE(offset + 8);
	offset += 10;

	if (format !== 3) {
		throw unsupported(`uses version ${format} of the PKWARE strong encryption header`);
	}
	const keyLength = AES_KEY_LENGTHS[algorithm];
	if (keyLength === undefined) {
		const name = OTHER_ALGORITHMS[algorithm] ?? `algorithm 0x${algorithm.toString(16)}`;
		throw unsupported(`uses PKWARE strong encryption with ${name}`);
	}
	if (bitLength !== keyLength * 8) throw malformed();
	if ((flags & FLAG_CERTIFICATES) !== 0 || (flags & FLAG_PASSWORD) === 0) {
		throw unsupported('is encrypted for certificates, not with a password');
	}
	if ((flags & FLAG_3DES_RANDOM_DATA) !== 0) {
		throw unsupported('protects its key with 3DES');
	}
	if (randomSize < AES_BLOCK_SIZE || randomSize % AES_BLOCK_SIZE !== 0) throw malformed();
	if (headerEnd < offset + randomSize + 6) throw malformed();
	const encryptedRandom = data.subarray(offset, offset + randomSize);
	offset += randomSize;
	if (data.readUInt32LE(offset) !== 0) {
		// The recipient count: a password-only entry has none.
		throw unsupported('is encrypted for certificates, not with a password');
	}
	offset += 4;
	const validationSize = data.readUInt16LE(offset);
	offset += 2;
	if (
		validationSize < AES_BLOCK_SIZE ||
		validationSize % AES_BLOCK_SIZE !== 0 ||
		offset + validationSize !== headerEnd
	) {
		throw malformed();
	}
	const encryptedValidation = data.subarray(offset, headerEnd);
	const ciphertext = data.subarray(headerEnd);

	const cipher = `aes-${keyLength * 8}-cbc`;
	const masterKey = deriveKey(createHash('sha1').update(password, 'utf8').digest(), keyLength);
	// Every length the format stores is block-aligned, so no automatic padding.
	const random = createDecipheriv(cipher, masterKey, iv)
		.setAutoPadding(false)
		.update(encryptedRandom);
	// A full block of PKCS#7 padding ends the random data; any other value
	// means the password-derived key is wrong.
	const randomEnd = random.length - AES_BLOCK_SIZE;
	if (!random.subarray(randomEnd).every((byte) => byte === AES_BLOCK_SIZE)) {
		throw extractError('wrongPassword');
	}

	const fileKey = deriveKey(
		createHash('sha1').update(keyIv).update(random.subarray(0, randomEnd)).digest(),
		keyLength,
	);
	// The validation data and the file data form one CBC stream under the file
	// key, as 7-Zip reads it.
	const fileDecipher = createDecipheriv(cipher, fileKey, iv).setAutoPadding(false);
	const validation = fileDecipher.update(encryptedValidation);
	const checkOffset = validation.length - 4;
	if (crc32(validation.subarray(0, checkOffset)) !== validation.readUInt32LE(checkOffset)) {
		throw extractError('wrongPassword');
	}

	if (ciphertext.length === 0 || ciphertext.length % AES_BLOCK_SIZE !== 0) {
		throw extractError('integrityCheckFailed', { suffix });
	}
	const padded = fileDecipher.update(ciphertext);
	fileDecipher.final();
	const padding = padded[padded.length - 1];
	const contentEnd = padded.length - padding;
	if (
		padding < 1 ||
		padding > AES_BLOCK_SIZE ||
		!padded.subarray(contentEnd).every((byte) => byte === padding)
	) {
		throw extractError('integrityCheckFailed', { suffix });
	}
	return padded.subarray(0, contentEnd);
}

/** The key derivation of Windows `CryptDeriveKey` for SHA-1 and AES. */
function deriveKey(digest: Buffer, length: number): Buffer {
	const half = (pad: number): Buffer => {
		const block = Buffer.alloc(64, pad);
		for (let index = 0; index < digest.length; index++) {
			block[index] ^= digest[index];
		}
		return createHash('sha1').update(block).digest();
	};
	return Buffer.concat([half(0x36), half(0x5c)]).subarray(0, length);
}

/** Inflates raw Deflate data, failing once the output would exceed the declared size. */
async function inflate(compressed: Uint8Array, size: number, suffix: string): Promise<Uint8Array> {
	const inflater = new DecompressionStream('deflate-raw');
	const writer = inflater.writable.getWriter();
	// A failed write also errors the readable side, where it is reported.
	writer
		.write(compressed)
		.then(() => writer.close())
		.catch(() => undefined);
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		for await (const chunk of inflater.readable) {
			length += chunk.byteLength;
			if (length > size) {
				break;
			}
			chunks.push(chunk);
		}
	} catch {
		throw extractError('integrityCheckFailed', { suffix });
	}
	if (length !== size) {
		throw extractError('integrityCheckFailed', { suffix });
	}
	return Buffer.concat(chunks, length);
}

let crcTable: Uint32Array | undefined;

/** The standard ZIP CRC-32. */
export function crc32(bytes: Uint8Array): number {
	if (crcTable === undefined) {
		crcTable = new Uint32Array(256);
		for (let byte = 0; byte < 256; byte++) {
			let value = byte;
			for (let bit = 0; bit < 8; bit++) {
				value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
			}
			crcTable[byte] = value;
		}
	}
	let crc = 0xffffffff;
	for (const byte of bytes) {
		crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
	}
	return (crc ^ 0xffffffff) >>> 0;
}
