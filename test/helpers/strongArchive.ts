import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { Uint8ArrayReader, Uint8ArrayWriter, ZipReader, ZipWriter } from '@zip.js/zip.js';

/**
 * Writes single-entry archives with PKWARE strong encryption (APPNOTE section
 * 7), which zip.js cannot write. Written from the specification and checked
 * against 7-Zip, which extracts these archives; it shares no code with the
 * node's decoder. Self-contained so the smoke lane can run it with Node's
 * type stripping.
 */

export interface StrongArchiveOptions {
	keyBits?: 128 | 192 | 256;
	compression?: 'store' | 'deflate';
	/** `false` stores no IV, so the CRC-32 and size stand in for it. Defaults to `true`. */
	storedIv?: boolean;
	/** Overrides the algorithm ID written in the decryption header; the data stays AES. */
	algorithmId?: number;
	/** Overrides the decryption header flags (default `0x0001`, password). */
	flags?: number;
}

const AES_ALGORITHM_IDS = { 128: 0x660e, 192: 0x660f, 256: 0x6610 } as const;

export async function makeStrongArchive(
	name: string,
	content: Uint8Array,
	password: string,
	{
		keyBits = 256,
		compression = 'deflate',
		storedIv = true,
		algorithmId = AES_ALGORITHM_IDS[keyBits],
		flags = 0x0001,
	}: StrongArchiveOptions = {},
): Promise<Uint8Array> {
	const { data: compressed, crc32 } = await compress(content, compression === 'deflate');
	const keyLength = keyBits / 8;
	const cipher = `aes-${keyBits}-cbc`;

	let iv: Buffer;
	let keyIv: Buffer;
	if (storedIv) {
		iv = randomBytes(16);
		keyIv = iv;
	} else {
		iv = Buffer.alloc(16);
		iv.writeUInt32LE(crc32, 0);
		iv.writeBigUInt64LE(BigInt(content.length), 4);
		keyIv = iv.subarray(0, 12);
	}

	// Encrypted random data: random bytes plus a full PKCS#7 block, under the password key.
	const random = randomBytes(64);
	const masterKey = deriveKey(createHash('sha1').update(password, 'utf8').digest(), keyLength);
	const encryptedRandom = createCipheriv(cipher, masterKey, iv)
		.setAutoPadding(false)
		.update(Buffer.concat([random, Buffer.alloc(16, 16)]));

	// Password validation data, then the file data, as one CBC stream under the file key.
	const fileKey = deriveKey(createHash('sha1').update(keyIv).update(random).digest(), keyLength);
	const validationData = randomBytes(12);
	const validation = Buffer.alloc(16);
	validationData.copy(validation);
	validation.writeUInt32LE((await compress(validationData, false)).crc32, 12);
	const fileCipher = createCipheriv(cipher, fileKey, iv);
	const encryptedValidation = fileCipher.update(validation);
	const encryptedData = Buffer.concat([fileCipher.update(compressed), fileCipher.final()]);

	const header = Buffer.alloc(16);
	header.writeUInt16LE(3, 0); // format
	header.writeUInt16LE(algorithmId, 2);
	header.writeUInt16LE(keyBits, 4);
	header.writeUInt16LE(flags, 6);
	header.writeUInt16LE(encryptedRandom.length, 8);
	const recipients = Buffer.alloc(6);
	recipients.writeUInt16LE(encryptedValidation.length, 4);
	const remainder = Buffer.concat([
		header.subarray(0, 10),
		encryptedRandom,
		recipients,
		encryptedValidation,
	]);
	const ivField = Buffer.alloc(2);
	ivField.writeUInt16LE(storedIv ? iv.length : 0);
	const remainderSize = Buffer.alloc(4);
	remainderSize.writeUInt32LE(remainder.length);
	const entryData = Buffer.concat([
		ivField,
		storedIv ? iv : Buffer.alloc(0),
		remainderSize,
		remainder,
		encryptedData,
	]);

	const strongExtra = Buffer.alloc(16);
	strongExtra.writeUInt16LE(0x0017, 0);
	strongExtra.writeUInt16LE(12, 2);
	strongExtra.writeUInt16LE(2, 4); // format
	strongExtra.writeUInt16LE(algorithmId, 6);
	strongExtra.writeUInt16LE(keyBits, 8);
	strongExtra.writeUInt16LE(flags, 10);

	return writeZip({
		name: Buffer.from(name, 'utf8'),
		method: compression === 'deflate' ? 8 : 0,
		crc32,
		compressedSize: entryData.length,
		uncompressedSize: content.length,
		centralExtra: strongExtra,
		data: entryData,
	});
}

/** The key derivation of Windows `CryptDeriveKey` for SHA-1, as the specification requires. */
function deriveKey(digest: Buffer, length: number): Buffer {
	const derive = (pad: number) => {
		const block = Buffer.alloc(64, pad);
		digest.forEach((byte, index) => (block[index] ^= byte));
		return createHash('sha1').update(block).digest();
	};
	return Buffer.concat([derive(0x36), derive(0x5c)]).subarray(0, length);
}

/** Raw Deflate or stored bytes and their CRC-32, taken from a zip.js archive. */
async function compress(
	content: Uint8Array,
	deflate: boolean,
): Promise<{ data: Uint8Array; crc32: number }> {
	const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
	await writer.add('content', new Uint8ArrayReader(content), { level: deflate ? 6 : 0 });
	const reader = new ZipReader(new Uint8ArrayReader(await writer.close()), {
		useWebWorkers: false,
	});
	const [entry] = await reader.getEntries();
	if (entry.directory || entry.crc32 === undefined) {
		throw new Error('zip.js wrote no file entry');
	}
	const data = await entry.getData(new Uint8ArrayWriter(), { passThrough: true });
	await reader.close();
	return { data, crc32: entry.crc32 };
}

interface ZipEntryRecord {
	name: Buffer;
	method: number;
	crc32: number;
	compressedSize: number;
	uncompressedSize: number;
	centralExtra: Buffer;
	data: Buffer;
}

/** One local header, the entry data, one central directory record and the end record. */
function writeZip(entry: ZipEntryRecord): Uint8Array {
	// 2026-11-12 08:30:00 as a DOS date and time.
	const time = (8 << 11) | (30 << 5);
	const date = ((2026 - 1980) << 9) | (11 << 5) | 12;
	const versionNeeded = 51;
	const bitFlag = 0x0041; // encrypted, strong encryption

	const local = Buffer.alloc(30);
	local.writeUInt32LE(0x04034b50, 0);
	local.writeUInt16LE(versionNeeded, 4);
	local.writeUInt16LE(bitFlag, 6);
	local.writeUInt16LE(entry.method, 8);
	local.writeUInt16LE(time, 10);
	local.writeUInt16LE(date, 12);
	local.writeUInt32LE(entry.crc32, 14);
	local.writeUInt32LE(entry.compressedSize, 18);
	local.writeUInt32LE(entry.uncompressedSize, 22);
	local.writeUInt16LE(entry.name.length, 26);

	const central = Buffer.alloc(46);
	central.writeUInt32LE(0x02014b50, 0);
	central.writeUInt16LE(versionNeeded, 4); // version made by, MS-DOS
	central.writeUInt16LE(versionNeeded, 6);
	central.writeUInt16LE(bitFlag, 8);
	central.writeUInt16LE(entry.method, 10);
	central.writeUInt16LE(time, 12);
	central.writeUInt16LE(date, 14);
	central.writeUInt32LE(entry.crc32, 16);
	central.writeUInt32LE(entry.compressedSize, 20);
	central.writeUInt32LE(entry.uncompressedSize, 24);
	central.writeUInt16LE(entry.name.length, 28);
	central.writeUInt16LE(entry.centralExtra.length, 30);
	// Local header offset 0.

	const localPart = Buffer.concat([local, entry.name, entry.data]);
	const centralPart = Buffer.concat([central, entry.name, entry.centralExtra]);
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(1, 8);
	end.writeUInt16LE(1, 10);
	end.writeUInt32LE(centralPart.length, 12);
	end.writeUInt32LE(localPart.length, 16);
	return Buffer.concat([localPart, centralPart, end]);
}
