// Writes the smoke lane's inputs: random synthetic content and the encrypted
// archives holding it. Nothing here is real member data, and nothing is committed.
//
// Usage: node test/smoke/make-archives.mjs <output-dir> <password>

import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from '@zip.js/zip.js';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [outputDir, password] = process.argv.slice(2);
if (!outputDir || !password) {
	console.error('usage: make-archives.mjs <output-dir> <password>');
	process.exit(2);
}

const content = randomBytes(256 * 1024);

async function archive(options) {
	const writer = new ZipWriter(new Uint8ArrayWriter(), {
		password,
		useWebWorkers: false,
		...options,
	});
	await writer.add('synthetic.bin', new Uint8ArrayReader(content));
	return writer.close();
}

mkdirSync(outputDir, { recursive: true });
writeFileSync(join(outputDir, 'synthetic.bin'), content);
writeFileSync(join(outputDir, 'aes256.zip'), await archive({ encryptionStrength: 3 }));
writeFileSync(join(outputDir, 'zipcrypto.zip'), await archive({ zipCrypto: true }));
