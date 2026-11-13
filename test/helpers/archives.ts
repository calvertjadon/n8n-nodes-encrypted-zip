import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from '@zip.js/zip.js';

/**
 * Builds synthetic ZIP archives inside the tests, so no committed fixture can
 * hold real member data.
 */

export type Encryption = 'aes128' | 'aes192' | 'aes256' | 'zipCrypto';

/** A file entry with content, or a folder entry, which only names a path. */
export type ArchiveEntry = {
	name: string;
	/** Defaults to {@link FIXED_DATE}. */
	lastModified?: Date;
} & ({ data: Uint8Array | string } | { directory: true });

export const PASSWORD = 'correct horse battery staple';

/** A fixed timestamp with even seconds, which DOS dates can represent exactly. */
export const FIXED_DATE = new Date('2026-11-12T08:30:00.000Z');

const ENCRYPTION_OPTIONS: Record<
	Encryption,
	{ zipCrypto?: boolean; encryptionStrength?: 1 | 2 | 3 }
> = {
	aes128: { encryptionStrength: 1 },
	aes192: { encryptionStrength: 2 },
	aes256: { encryptionStrength: 3 },
	zipCrypto: { zipCrypto: true },
};

export async function makeArchive(
	entries: ArchiveEntry[],
	encryption: Encryption = 'aes256',
	password = PASSWORD,
): Promise<Uint8Array> {
	const writer = new ZipWriter(new Uint8ArrayWriter(), {
		password,
		useWebWorkers: false,
		...ENCRYPTION_OPTIONS[encryption],
	});
	for (const entry of entries) {
		const options = { lastModDate: entry.lastModified ?? FIXED_DATE };
		if ('directory' in entry) {
			await writer.add(entry.name, undefined, { ...options, directory: true });
			continue;
		}
		const bytes =
			typeof entry.data === 'string' ? new TextEncoder().encode(entry.data) : entry.data;
		await writer.add(entry.name, new Uint8ArrayReader(bytes), options);
	}
	return writer.close();
}

/** Deterministic bytes covering every byte value, so binary content is exercised. */
export function syntheticBytes(length: number, seed = 1): Uint8Array {
	const bytes = new Uint8Array(length);
	let state = seed;
	for (let index = 0; index < length; index++) {
		state = (state * 1103515245 + 12345) >>> 0;
		bytes[index] = state >>> 24;
	}
	return bytes;
}
