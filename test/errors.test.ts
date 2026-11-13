import { NodeOperationError } from 'n8n-workflow';
import { describe, expect, it } from 'vitest';
import { PASSWORD, makeArchive, syntheticBytes, type Encryption } from './helpers/archives';
import { caughtError, execute, type HarnessOptions } from './helpers/context';

const CONTENT = syntheticBytes(70_000);
const WRONG_PASSWORD = 'wrong-password-do-not-leak';

function extractInput(archive: Uint8Array, extra: Partial<HarnessOptions> = {}): HarnessOptions {
	return {
		parameters: { operation: 'extract' },
		binary: { 0: { data: { data: archive, fileName: 'statements.zip' } } },
		credential: { password: PASSWORD },
		...extra,
	};
}

/** Neither the credential's password nor the archive's may appear anywhere in the error. */
function expectNoPasswordIn(error: NodeOperationError, ...passwords: string[]) {
	const surfaces = JSON.stringify({
		message: error.message,
		description: error.description,
		cause: String(error.cause ?? ''),
		context: error.context,
	});
	for (const password of passwords) {
		expect(surfaces).not.toContain(password);
	}
}

function flipByte(archive: Uint8Array, offset: number): Uint8Array {
	const copy = Uint8Array.from(archive);
	copy[offset] ^= 0xff;
	return copy;
}

describe.each<Encryption>(['aes256', 'zipCrypto'])('%s archive', (encryption) => {
	it('fails on a wrong password without revealing either password', async () => {
		const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }], encryption);

		const error = await caughtError(
			extractInput(archive, { credential: { password: WRONG_PASSWORD } }),
		);

		expect(error).toBeInstanceOf(NodeOperationError);
		expect(error.message).toMatch(/password/i);
		expect(error.message).toContain("'ZIP Password'");
		expect(error.message).toContain('[Item 0]');
		expectNoPasswordIn(error, WRONG_PASSWORD, PASSWORD);
	});

	it('fails the integrity check when one byte of the entry data is corrupt', async () => {
		const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }], encryption);

		const error = await caughtError(
			extractInput(flipByte(archive, Math.floor(archive.length / 2))),
		);

		expect(error.message).toMatch(/integrity check/i);
		expect(error.message).toContain('statement.dat');
		expectNoPasswordIn(error, PASSWORD);
	});
});

describe('ZipCrypto wrong password that passes the one-byte password check', () => {
	it('names the password as a possible cause in the message itself', async () => {
		const archive = await makeArchive(
			[{ name: 'statement.dat', data: syntheticBytes(1_000) }],
			'zipCrypto',
		);
		// About 1 in 256 wrong passwords passes ZipCrypto's check byte; find one.
		let error: NodeOperationError | undefined;
		for (let attempt = 0; attempt < 5_000 && !error; attempt++) {
			const candidate = await caughtError(
				extractInput(archive, { credential: { password: `${WRONG_PASSWORD}-${attempt}` } }),
			);
			if (!candidate.message.includes('does not open this archive')) {
				error = candidate;
			}
		}

		expect(error?.message).toMatch(/password is wrong/i);
		expect(error?.message).toContain('statement.dat');
	});
});

describe('unreadable archives', () => {
	/** Rewrites the AES strength in every WinZip AES extra field (0x9901) to an undefined value. */
	function withUnknownAesStrength(archive: Uint8Array): Uint8Array {
		const copy = Uint8Array.from(archive);
		for (let offset = 0; offset + 8 < copy.length; offset++) {
			const isAesField =
				copy[offset] === 0x01 &&
				copy[offset + 1] === 0x99 &&
				copy[offset + 6] === 0x41 && // 'A'
				copy[offset + 7] === 0x45; // 'E'
			if (isAesField) {
				copy[offset + 8] = 4;
			}
		}
		return copy;
	}

	it('fails clearly on an encryption method it does not support', async () => {
		const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }]);

		const error = await caughtError(extractInput(withUnknownAesStrength(archive)));

		expect(error.message).toContain('encryption method this node cannot decrypt');
		expect(error.description).toContain('ZipCrypto');
		expectNoPasswordIn(error, PASSWORD);
	});

	it('fails clearly on a truncated archive', async () => {
		const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }]);

		const error = await caughtError(extractInput(archive.subarray(0, archive.length - 40)));

		expect(error.message).toContain('not a readable ZIP archive');
		expect(error.description).toContain('The ZIP reader reported:');
		expectNoPasswordIn(error, PASSWORD);
	});

	it('names 7z input instead of calling it a corrupt ZIP', async () => {
		const sevenZipHeader = Uint8Array.from([
			0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x00, 0x00,
		]);

		const error = await caughtError(extractInput(sevenZipHeader));

		expect(error.message).toContain('7z archive');
	});

	it("does not repeat a library message that contains the credential's password", async () => {
		const notAZip = new TextEncoder().encode('plain text, not an archive');

		const error = await caughtError(extractInput(notAZip, { credential: { password: 'not' } }));

		expect(error.message).toContain('not a readable ZIP archive');
		expect(error.description).not.toContain('The ZIP reader reported:');
	});
});

describe('continue on fail', () => {
	it('turns a failing item into an error item and keeps extracting later items', async () => {
		const good = await makeArchive([{ name: 'statement.dat', data: CONTENT }]);
		const bad = await makeArchive(
			[{ name: 'statement.dat', data: CONTENT }],
			'aes256',
			WRONG_PASSWORD,
		);

		const items = await execute({
			parameters: { operation: 'extract' },
			items: [{ json: {} }, { json: {} }],
			binary: { 0: { data: { data: bad } }, 1: { data: { data: good } } },
			credential: { password: PASSWORD },
			continueOnFail: true,
		});

		expect(items).toHaveLength(2);
		expect(items[0]).toMatchObject({ pairedItem: { item: 0 } });
		expect(String(items[0].json.error)).toMatch(/password/i);
		expect(items[1].binary?.data).toBeDefined();
		expect(items[1].pairedItem).toEqual({ item: 1 });
	});
});
