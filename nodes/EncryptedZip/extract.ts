import {
	Uint8ArrayReader,
	Uint8ArrayWriter,
	ZipReader,
	type Entry,
	type FileEntry,
} from '@zip.js/zip.js';
import type { IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { classifyZipError, extractError } from './errors';
import { isStrongEncrypted, readStrongEntry } from './strongEncryption';

/** The signature every .7z file starts with. */
const SEVEN_ZIP_SIGNATURE = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);

/** Extracts every file entry of the archive in the item's binary field. */
export async function extract(
	ctx: IExecuteFunctions,
	itemIndex: number,
	password: string | undefined,
): Promise<INodeExecutionData[]> {
	if (!password) {
		throw extractError('missingPassword');
	}
	const inputField = ctx.getNodeParameter('binaryPropertyName', itemIndex, 'data') as string;
	const outputField = ctx.getNodeParameter('outputBinaryFieldName', itemIndex, 'data') as string;
	ctx.helpers.assertBinaryData(itemIndex, inputField);
	const archive = await ctx.helpers.getBinaryDataBuffer(itemIndex, inputField);
	if (archive.subarray(0, SEVEN_ZIP_SIGNATURE.length).equals(SEVEN_ZIP_SIGNATURE)) {
		throw extractError('sevenZipArchive');
	}

	const reader = new ZipReader(new Uint8ArrayReader(archive), {
		password,
		useWebWorkers: false,
		checkCrc32: true,
	});
	try {
		let entries: FileEntry[];
		try {
			entries = (await reader.getEntries()).filter(
				(entry: Entry): entry is FileEntry => !entry.directory,
			);
		} catch (error) {
			throw classifyZipError(error, password);
		}
		const { expectedEntryName = '' } = ctx.getNodeParameter('options', itemIndex, {}) as {
			expectedEntryName?: string;
		};
		const items: INodeExecutionData[] = [];
		for (const entry of selectEntries(entries, expectedEntryName)) {
			let bytes: Uint8Array;
			if (isStrongEncrypted(entry)) {
				bytes = await readStrongEntry(entry, password);
			} else {
				try {
					bytes = await entry.getData(new Uint8ArrayWriter());
				} catch (error) {
					throw classifyZipError(error, password, entry);
				}
			}
			// Named without its folder path; some Windows tools separate folders with `\`.
			const fileName = entry.filename.split(/[\\/]/).pop() || entry.filename;
			const binaryData = await ctx.helpers.prepareBinaryData(
				// A view over the extracted bytes, not a copy of them.
				Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength),
				fileName,
			);
			// A DOS timestamp has no time zone and is read in the n8n process's local
			// time; an extended timestamp field, when present, is UTC.
			const modified = entry.lastModDate;
			items.push({
				json: {
					entryName: entry.filename,
					uncompressedSize: bytes.byteLength,
					lastModified:
						modified && !Number.isNaN(modified.getTime()) ? modified.toISOString() : null,
				},
				binary: { [outputField]: binaryData },
				pairedItem: { item: itemIndex },
			});
		}
		return items;
	} finally {
		await reader.close();
	}
}

/**
 * Every file entry, or exactly the expected one. Folder entries never count:
 * they hold no data. The checks run before anything is decrypted.
 */
function selectEntries(entries: FileEntry[], expectedName: string): FileEntry[] {
	if (entries.length === 0) {
		throw extractError('emptyArchive');
	}
	if (!expectedName) {
		return entries;
	}
	if (entries.length !== 1) {
		throw extractError('entryCountMismatch', {
			suffix: `, "${expectedName}", but it contains ${entries.length} files`,
		});
	}
	if (entries[0].filename !== expectedName) {
		throw extractError('entryNameMismatch', {
			suffix: `: expected "${expectedName}", found "${entries[0].filename}"`,
		});
	}
	return entries;
}
