import type { ICredentialType, INodeProperties } from 'n8n-workflow';

// eslint-disable-next-line @n8n/community-nodes/credential-test-required -- a ZIP password can only be checked against an archive, which a credential test does not have; a test that accepted any non-empty value would report success it cannot know.
export class ZipPasswordApi implements ICredentialType {
	name = 'zipPasswordApi';

	// eslint-disable-next-line n8n-nodes-base/cred-class-field-display-name-missing-api -- there is no API: the credential holds an archive password, and 'ZIP Password' is the name users look for.
	displayName = 'ZIP Password';

	documentationUrl = 'https://github.com/calvertjadon/n8n-nodes-encrypted-zip#credential-setup';

	icon = {
		light: 'file:zipPasswordApi.svg',
		dark: 'file:zipPasswordApi.dark.svg',
	} as const;

	properties: INodeProperties[] = [
		{
			displayName: 'Password',
			name: 'password',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description:
				'The password the ZIP archive was encrypted with. It is used for WinZip AES, PKWARE strong encryption and legacy ZipCrypto entries.',
		},
	];
}
