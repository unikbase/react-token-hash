export declare const randomSalt: () => string;
export declare const toUint8Array: (input: string) => Uint8Array;
export declare const uint8ArrayToString: (uint8Buffer: Uint8Array) => string;
export declare const multihashesSha1: (input: string) => string;
export declare const decodeMultihash: (hexString: string) => {
    raw: string;
    code: import("multihashes/dist/src/constants").HashCode;
    name: import("multihashes/dist/src/constants").HashName;
    length: number;
    digest: Uint8Array;
};
export declare const generateSalts: (tokenDetails: any) => {
    name: any;
    prefix: string;
}[];
export declare const generateJsonHash: (token: any) => string | null;
export declare const generateZipHash: (token: any) => string;
export declare const generateVerifiablePresentation: (token: any, sharedProps: Array<string>, chainId: string, walletAddress: string, sign: (data: any) => string) => Promise<{
    proof: {
        type: string;
        created: string;
        proofPurpose: string;
        verificationMethod: string;
        signature: string;
    };
    tokenId: any;
    credentialId: string;
    selectiveObjectData: any;
} | null>;
