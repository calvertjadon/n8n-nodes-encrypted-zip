import {
	NodeConnectionTypes,
	type IExecuteFunctions,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
} from 'n8n-workflow';
import { toNodeError } from './errors';
import { extract } from './extract';

// eslint-disable-next-line @n8n/community-nodes/node-usable-as-tool -- binary in, binary out: AI agent tools cannot pass or receive binary data, so the node is not offered as a tool (.agents/nodes.md).
export class EncryptedZip implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Encrypted ZIP',
		name: 'encryptedZip',
		icon: {
			light: 'file:encryptedZip.svg',
			dark: 'file:encryptedZip.dark.svg',
		},
		group: ['transform'],
		version: 1,
		subtitle: '={{ $parameter["operation"] }}',
		description: 'Extract password-protected ZIP archives in memory',
		documentationUrl: 'https://github.com/calvertjadon/n8n-nodes-encrypted-zip#usage',
		defaults: {
			name: 'Encrypted ZIP',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'zipPasswordApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				default: 'extract',
				options: [
					{
						name: 'Extract',
						value: 'extract',
						action: 'Extract an encrypted ZIP archive',
						description: 'Decrypt every file in the archive and output each as binary data',
					},
				],
			},
			{
				displayName: 'Input Data Field Name',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				required: true,
				placeholder: 'e.g. data',
				hint: 'The name of the data field holding the ZIP archive',
				displayOptions: { show: { operation: ['extract'] } },
			},
			{
				displayName: 'Output Data Field Name',
				name: 'outputBinaryFieldName',
				type: 'string',
				default: 'data',
				required: true,
				placeholder: 'e.g. data',
				hint: 'The name of the data field each extracted file is written to',
				displayOptions: { show: { operation: ['extract'] } },
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add option',
				default: {},
				displayOptions: { show: { operation: ['extract'] } },
				options: [
					{
						displayName: 'Expected Entry Name',
						name: 'expectedEntryName',
						type: 'string',
						default: '',
						placeholder: 'e.g. statements/daily.txt',
						description:
							'The archive must contain exactly one file, with exactly this name including any folder path, or the node fails. Leave empty to output every file in the archive.',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnItems: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const { password } = await this.getCredentials<{ password?: string }>(
					'zipPasswordApi',
					itemIndex,
				);
				returnItems.push(...(await extract(this, itemIndex, password)));
			} catch (error) {
				const failure = toNodeError(this, error, itemIndex);
				if (this.continueOnFail()) {
					returnItems.push({ json: { error: failure.message }, pairedItem: { item: itemIndex } });
					continue;
				}
				throw failure;
			}
		}

		return [returnItems];
	}
}
