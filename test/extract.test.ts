import { describe, expect, it } from 'vitest';
import {
	PASSWORD,
	makeArchive,
	syntheticBytes,
	type ArchiveEntry,
	type Encryption,
} from './helpers/archives';
import { binaryBytes, caughtError, execute } from './helpers/context';
import { EncryptedZip } from '../nodes/EncryptedZip/EncryptedZip.node';

const CONTENT = syntheticBytes(70_000);

function archiveInput(archive: Uint8Array, fieldName = 'data') {
	return { 0: { [fieldName]: { data: archive, fileName: 'statements.zip' } } };
}

describe('Extract', () => {
	it.each<Encryption>(['aes256', 'aes192', 'aes128', 'zipCrypto'])(
		'recovers the exact bytes of a %s entry with the correct password',
		async (encryption) => {
			const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }], encryption);

			const items = await execute({
				parameters: { operation: 'extract' },
				binary: archiveInput(archive),
				credential: { password: PASSWORD },
			});

			expect(items).toHaveLength(1);
			expect(binaryBytes(items[0]).equals(Buffer.from(CONTENT))).toBe(true);
			expect(items[0].pairedItem).toEqual({ item: 0 });
		},
	);
});

describe('entry selection', () => {
	const FIRST = syntheticBytes(5_000, 7);
	const SECOND = syntheticBytes(3_000, 11);

	function extractWith(archive: Uint8Array, expectedEntryName?: string) {
		return {
			parameters: {
				operation: 'extract',
				options: expectedEntryName === undefined ? {} : { expectedEntryName },
			},
			binary: archiveInput(archive),
			credential: { password: PASSWORD },
		};
	}

	it('outputs every file entry as its own item when no entry name is expected', async () => {
		const archive = await makeArchive([
			{ name: 'reports/', directory: true },
			{ name: 'reports/first.dat', data: FIRST },
			{ name: 'second.dat', data: SECOND },
		]);

		const items = await execute(extractWith(archive));

		expect(items).toHaveLength(2);
		expect(binaryBytes(items[0]).equals(Buffer.from(FIRST))).toBe(true);
		expect(binaryBytes(items[1]).equals(Buffer.from(SECOND))).toBe(true);
		expect(items.map((item) => item.pairedItem)).toEqual([{ item: 0 }, { item: 0 }]);
	});

	it('extracts the single entry that matches the expected name, ignoring folder entries', async () => {
		const archive = await makeArchive([
			{ name: 'reports/', directory: true },
			{ name: 'reports/first.dat', data: FIRST },
		]);

		const items = await execute(extractWith(archive, 'reports/first.dat'));

		expect(items).toHaveLength(1);
		expect(binaryBytes(items[0]).equals(Buffer.from(FIRST))).toBe(true);
	});

	it('fails when an entry name is expected but the archive holds two files', async () => {
		const archive = await makeArchive([
			{ name: 'first.dat', data: FIRST },
			{ name: 'second.dat', data: SECOND },
		]);

		const error = await caughtError(extractWith(archive, 'first.dat'));

		expect(error.message).toContain('exactly one file');
		expect(error.message).toContain('"first.dat"');
		expect(error.message).toContain('2 files');
	});

	it('fails when the only file does not have the expected name', async () => {
		const archive = await makeArchive([{ name: 'First.dat', data: FIRST }]);

		const error = await caughtError(extractWith(archive, 'first.dat'));

		expect(error.message).toContain('expected "first.dat"');
		expect(error.message).toContain('found "First.dat"');
	});

	it.each<[string, string | undefined, ArchiveEntry[]]>([
		['no entry name is expected', undefined, []],
		['an entry name is expected', 'first.dat', []],
		['the archive holds only a folder', undefined, [{ name: 'empty-folder/', directory: true }]],
	])('fails on an archive with no files when %s', async (_case, expectedEntryName, entries) => {
		const archive = await makeArchive(entries);

		const error = await caughtError(extractWith(archive, expectedEntryName));

		expect(error.message).toContain('The archive contains no files');
	});
});

describe('output', () => {
	it('reports name, uncompressed size and modified time for each entry', async () => {
		const archive = await makeArchive([
			{
				name: 'reports/daily.dat',
				data: syntheticBytes(4_321),
				lastModified: new Date('2026-11-12T08:30:00.000Z'),
			},
		]);

		const [item] = await execute({
			parameters: { operation: 'extract' },
			binary: archiveInput(archive),
			credential: { password: PASSWORD },
		});

		expect(item.json).toEqual({
			entryName: 'reports/daily.dat',
			uncompressedSize: 4_321,
			lastModified: '2026-11-12T08:30:00.000Z',
		});
		// The binary file is named like the extracted file, without the folder path.
		expect(item.binary?.data.fileName).toBe('daily.dat');
	});

	it('reads and writes the configured binary fields', async () => {
		const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }]);

		const [item] = await execute({
			parameters: {
				operation: 'extract',
				binaryPropertyName: 'archive',
				outputBinaryFieldName: 'statement',
			},
			binary: archiveInput(archive, 'archive'),
			credential: { password: PASSWORD },
		});

		expect(Object.keys(item.binary ?? {})).toEqual(['statement']);
		expect(binaryBytes(item, 'statement').equals(Buffer.from(CONTENT))).toBe(true);
	});
});

describe('password source', () => {
	it('requires the ZIP Password credential and offers no password parameter', () => {
		const { credentials, properties } = new EncryptedZip().description;
		const allProperties = properties.flatMap((property) => [
			property,
			...((property.options ?? []) as Array<{ name: string; typeOptions?: unknown }>),
		]);

		expect(credentials).toEqual([
			expect.objectContaining({ name: 'zipPasswordApi', required: true }),
		]);
		expect(allProperties.some((property) => /password/i.test(property.name))).toBe(false);
		expect(
			allProperties.some(
				(property) => (property.typeOptions as { password?: boolean } | undefined)?.password,
			),
		).toBe(false);
	});

	it('fails before reading the archive when the credential holds no password', async () => {
		const archive = await makeArchive([{ name: 'statement.dat', data: CONTENT }]);

		const error = await caughtError({
			parameters: { operation: 'extract' },
			binary: archiveInput(archive),
			credential: { password: '' },
		});

		expect(error.message).toContain("The 'ZIP Password' credential has no password");
	});
});
