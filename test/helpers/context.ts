import { NodeOperationError, type IExecuteFunctions, type INodeExecutionData } from 'n8n-workflow';
import { EncryptedZip } from '../../nodes/EncryptedZip/EncryptedZip.node';

/**
 * Hand-rolled `IExecuteFunctions` double. The node is instantiated directly and
 * the decryption stays real; only n8n's execution context is faked.
 */

export interface BinaryFixture {
	data: Uint8Array;
	fileName?: string;
	mimeType?: string;
}

export interface HarnessOptions {
	/** Node parameters, as the n8n editor would have stored them. */
	parameters?: Record<string, unknown>;
	/** Input items; one empty item by default. */
	items?: INodeExecutionData[];
	/** Binary fields per item index: `binary[itemIndex][fieldName]`. */
	binary?: Record<number, Record<string, BinaryFixture>>;
	/** The ZIP Password credential's data. */
	credential: { password?: string };
	continueOnFail?: boolean;
}

export function createContext(options: HarnessOptions): IExecuteFunctions {
	const parameters = options.parameters ?? {};
	const items = options.items ?? [{ json: {} }];
	const binary = options.binary ?? {};
	const node = {
		id: 'test-node',
		name: 'Encrypted ZIP',
		type: 'n8n-nodes-encrypted-zip.encryptedZip',
		typeVersion: 1,
		position: [0, 0] as [number, number],
		parameters,
	};
	const binaryFixture = (itemIndex: number, fieldName: string): BinaryFixture => {
		const fixture = binary[itemIndex]?.[fieldName];
		if (!fixture) {
			throw new NodeOperationError(node, `No binary data property "${fieldName}" exists on item!`, {
				itemIndex,
			});
		}
		return fixture;
	};

	const context = {
		getNode: () => node,
		getInputData: () => items,
		getNodeParameter: (name: string, _itemIndex: number, fallback?: unknown) =>
			name in parameters ? parameters[name] : fallback,
		getCredentials: async () => options.credential,
		continueOnFail: () => options.continueOnFail ?? false,
		helpers: {
			assertBinaryData: (itemIndex: number, fieldName: string) => {
				const fixture = binaryFixture(itemIndex, fieldName);
				// Mirrors n8n's non-memory binary modes, where `data` holds the mode
				// marker instead of the bytes: reading it directly yields garbage.
				return {
					data: 'filesystem:test',
					fileName: fixture.fileName,
					mimeType: fixture.mimeType ?? 'application/zip',
				};
			},
			getBinaryDataBuffer: async (itemIndex: number, fieldName: string) =>
				Buffer.from(binaryFixture(itemIndex, fieldName).data),
			prepareBinaryData: async (data: Buffer, fileName?: string, mimeType?: string) => ({
				data: data.toString('base64'),
				fileName,
				mimeType: mimeType ?? 'application/octet-stream',
				fileSize: String(data.length),
			}),
		},
	};

	return context as unknown as IExecuteFunctions;
}

/** Runs the node's `execute()` once and returns the items of the single output branch. */
export async function execute(options: HarnessOptions): Promise<INodeExecutionData[]> {
	const node = new EncryptedZip();
	const [items] = await node.execute.call(createContext(options));
	return items;
}

/** Runs the node expecting it to fail, and returns the error it threw. */
export async function caughtError(options: HarnessOptions): Promise<NodeOperationError> {
	try {
		await execute(options);
	} catch (error) {
		return error as NodeOperationError;
	}
	throw new Error('Expected the node to fail, but it returned items');
}

/** The bytes the node wrote into an output item's binary field. */
export function binaryBytes(item: INodeExecutionData, fieldName = 'data'): Buffer {
	const binaryData = item.binary?.[fieldName];
	if (!binaryData || typeof binaryData.data !== 'string') {
		throw new Error(`Output item has no binary field "${fieldName}"`);
	}
	return Buffer.from(binaryData.data, 'base64');
}
