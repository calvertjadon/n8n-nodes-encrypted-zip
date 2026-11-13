import {
	ERR_INVALID_AUTHENTICATION_CODE,
	ERR_INVALID_COMPRESSED_DATA,
	ERR_INVALID_CRC32,
	ERR_INVALID_PASSWORD,
	ERR_INVALID_UNCOMPRESSED_SIZE,
	ERR_UNSUPPORTED_COMPRESSION,
	ERR_UNSUPPORTED_ENCRYPTION,
	type FileEntry,
} from '@zip.js/zip.js';
import { NodeOperationError, type IExecuteFunctions } from 'n8n-workflow';

/**
 * Canonical error copy. `message` says what is wrong; `description` says how to
 * unblock. No copy ever includes the password, and library messages are only
 * passed through when they do not contain it either.
 */
const ERROR_COPY = {
	missingPassword: {
		message: "The 'ZIP Password' credential has no password",
		description:
			"Enter the archive's password in the 'ZIP Password' credential selected on this node.",
	},
	wrongPassword: {
		message: "The password in the 'ZIP Password' credential does not open this archive",
		description:
			"Check the password stored in the 'ZIP Password' credential against the one the archive was encrypted with.",
	},
	unsupportedEncryption: {
		message: 'The archive uses an encryption method this node cannot decrypt',
		description:
			'Supported methods are WinZip AES-128, AES-192 and AES-256, and legacy ZipCrypto. PKWARE strong encryption is not supported.',
	},
	unsupportedCompression: {
		message: 'The archive uses a compression method this node cannot read',
		description: 'Supported methods are Store, Deflate and Deflate64.',
	},
	integrityCheckFailed: {
		message: 'An entry failed its integrity check: the archive is damaged or was altered',
		description:
			"The decrypted data does not match the archive's CRC-32 checksum or AES authentication code. Fetch the archive again from its source.",
	},
	zipCryptoCheckFailed: {
		message:
			'An entry failed its integrity check: the password is wrong, or the archive is damaged',
		description:
			"ZipCrypto checks only one byte of the password, so about 1 in 256 wrong passwords gets this far. Check the password in the 'ZIP Password' credential, then fetch the archive again from its source.",
	},
	corruptArchive: {
		message: 'The input is not a readable ZIP archive',
		description:
			'Check that the input data field holds the whole ZIP file, not a partial or altered copy.',
	},
	sevenZipArchive: {
		message: 'The input is a 7z archive, which this node does not read',
		description: 'Ask the sender for a ZIP archive. This node reads ZIP files only.',
	},
	emptyArchive: {
		message: 'The archive contains no files',
		description: 'Check that the sender produced the archive with its files in it.',
	},
	entryCountMismatch: {
		message: 'The archive must contain exactly one file',
		description:
			"'Expected Entry Name' is set, so the archive must hold that file and nothing else. Clear the option to output every file.",
	},
	entryNameMismatch: {
		message: "The archive's only file is not the expected entry",
		description:
			"Check 'Expected Entry Name' against the entry name in the archive, including any folder path. The comparison is exact and case-sensitive.",
	},
} as const;

type ErrorKind = keyof typeof ERROR_COPY;

/** An error the node reports itself, before `execute()` stamps the item index on it. */
export class ExtractError extends Error {
	constructor(
		message: string,
		readonly description: string,
	) {
		super(message);
	}
}

/**
 * Builds the pinned copy for `kind`. `suffix` adds specifics to the message;
 * `detail` adds the underlying reason to the description.
 */
export function extractError(
	kind: ErrorKind,
	{ suffix = '', detail }: { suffix?: string; detail?: string } = {},
): ExtractError {
	const { message, description } = ERROR_COPY[kind];
	return new ExtractError(message + suffix, detail ? `${description} ${detail}` : description);
}

/** zip.js failures raised while an entry's decrypted data is verified or decompressed. */
const INTEGRITY_FAILURES = new Set([
	ERR_INVALID_CRC32,
	ERR_INVALID_AUTHENTICATION_CODE,
	ERR_INVALID_COMPRESSED_DATA,
	ERR_INVALID_UNCOMPRESSED_SIZE,
]);

/**
 * Maps a zip.js failure to the node's error copy. `entry` is set when the
 * failure happened while reading that entry's data.
 */
export function classifyZipError(
	error: unknown,
	password: string,
	entry?: Pick<FileEntry, 'filename' | 'zipCrypto'>,
): ExtractError {
	const reason = error instanceof Error ? error.message : String(error);
	const suffix = entry === undefined ? '' : ` (entry "${entry.filename}")`;
	if (reason === ERR_INVALID_PASSWORD) {
		return extractError('wrongPassword');
	}
	if (reason === ERR_UNSUPPORTED_ENCRYPTION) {
		return extractError('unsupportedEncryption', { suffix });
	}
	if (reason === ERR_UNSUPPORTED_COMPRESSION) {
		return extractError('unsupportedCompression', { suffix });
	}
	if (entry !== undefined && INTEGRITY_FAILURES.has(reason)) {
		return extractError(entry.zipCrypto ? 'zipCryptoCheckFailed' : 'integrityCheckFailed', {
			suffix,
		});
	}
	// Library messages are fixed strings, but an unexpected error could carry
	// arbitrary text; it is shown only when the password cannot be in it.
	const safeReason = reason && !reason.includes(password) ? reason : undefined;
	return extractError('corruptArchive', {
		detail: safeReason && `The ZIP reader reported: ${safeReason}.`,
	});
}

/** Wraps any failure in the `NodeOperationError` n8n shows, naming the item it came from. */
export function toNodeError(
	ctx: IExecuteFunctions,
	error: unknown,
	itemIndex: number,
): NodeOperationError {
	const message = `${error instanceof Error ? error.message : String(error)} [Item ${itemIndex}]`;
	const description =
		error instanceof ExtractError || error instanceof NodeOperationError
			? (error.description ?? undefined)
			: undefined;
	return new NodeOperationError(ctx.getNode(), message, { itemIndex, description });
}
