
export interface Identity {
    name: string;
    description: string;
    identityKey: string;
    rootPath: string;
    rootAddress: string;
    previousPath: string;
    currentPath: string;
    lastIdPath: string;
    idSeed: string;
    identityAttributes: any;
}

export type PathPrefix = `/${number}/${number}/${number}` | `/${number}'/${number}'/${number}'`

export interface Attestation {
    type: string;
    hash: string;
    sequence: string;
    signingProtocol: string;
    signingAddress: string;
    signature: string;
    data?: string;
    verified?: boolean;
}
