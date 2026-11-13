import { describe, expect, it } from 'vitest';
import { PASSWORD, syntheticBytes } from './helpers/archives';
import { binaryBytes, caughtError, execute, type HarnessOptions } from './helpers/context';
import { makeStrongArchive, type StrongArchiveOptions } from './helpers/strongArchive';

const CONTENT = syntheticBytes(70_000);
const WRONG_PASSWORD = 'wrong-password-do-not-leak';

function extractInput(archive: Uint8Array, password = PASSWORD): HarnessOptions {
	return {
		parameters: { operation: 'extract', options: { expectedEntryName: 'statement.dat' } },
		binary: { 0: { data: { data: archive, fileName: 'statements.zip' } } },
		credential: { password },
	};
}

function strongArchive(options: StrongArchiveOptions = {}): Promise<Uint8Array> {
	return makeStrongArchive('statement.dat', CONTENT, PASSWORD, options);
}

describe('PKWARE strong encryption', () => {
	it.each<StrongArchiveOptions>([
		{ keyBits: 256, compression: 'deflate' },
		{ keyBits: 192, compression: 'deflate' },
		{ keyBits: 128, compression: 'deflate' },
		{ keyBits: 256, compression: 'store' },
		{ keyBits: 256, compression: 'deflate', storedIv: false },
		{ keyBits: 128, compression: 'store', storedIv: false },
	])('recovers the exact bytes of an entry encrypted with %o', async (options) => {
		const items = await execute(extractInput(await strongArchive(options)));

		expect(items).toHaveLength(1);
		expect(binaryBytes(items[0]).equals(Buffer.from(CONTENT))).toBe(true);
		expect(items[0].json).toMatchObject({
			entryName: 'statement.dat',
			uncompressedSize: CONTENT.length,
		});
	});

	it('fails on a wrong password without revealing either password', async () => {
		const error = await caughtError(extractInput(await strongArchive(), WRONG_PASSWORD));

		expect(error.message).toContain(
			"The password in the 'ZIP Password' credential does not open this archive",
		);
		const surfaces = JSON.stringify([error.message, error.description]);
		expect(surfaces).not.toContain(WRONG_PASSWORD);
		expect(surfaces).not.toContain(PASSWORD);
	});

	it.each([
		['in the middle of the data', (length: number) => Math.floor(length / 2)],
		// The last data byte is padding: the central directory record (46 bytes,
		// the 13-byte name and the 16-byte strong encryption extra field) and the
		// 22-byte end record follow it.
		['in the padding', (length: number) => length - 97 - 1],
	])('fails the integrity check when one byte %s is corrupt', async (_case, offsetOf) => {
		const archive = Uint8Array.from(await strongArchive({ compression: 'store' }));
		archive[offsetOf(archive.length)] ^= 0xff;

		const error = await caughtError(extractInput(archive));

		expect(error.message).toContain('An entry failed its integrity check');
		expect(error.message).toContain('(entry "statement.dat")');
	});

	it('names an algorithm other than AES as unsupported', async () => {
		const error = await caughtError(extractInput(await strongArchive({ algorithmId: 0x6603 })));

		expect(error.message).toContain(
			'The archive uses an encryption method this node cannot decrypt',
		);
		expect(error.description).toContain('3DES-168');
	});

	it('rejects an entry encrypted for certificates', async () => {
		const error = await caughtError(extractInput(await strongArchive({ flags: 0x0003 })));

		expect(error.message).toContain('encryption method this node cannot decrypt');
		expect(error.description).toContain('certificates');
	});
});
