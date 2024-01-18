import { SHA1, SHA512 } from 'crypto-js';
import { canonicalize } from 'json-canonicalize';
import { encode, decode, toHexString, fromHexString } from 'multihashes';
import { toChecksumAddress } from 'ethereum-checksum-address';
const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const alpha2 = 'abcdefghijklmnopqrstuvwxyz';
const digits = '0123456789';
const specials = '!#$%&';
export const randomSalt = () => {
    return Array(10).fill(0).map((e, index) => {
        let source = alpha;
        const re = index % 4;
        switch (re) {
            case 1:
                source = digits;
                break;
            case 2:
                source = specials;
                break;
            case 3:
                source = alpha2;
                break;
        }
        const random = Math.floor(Math.random() * source.length);
        return source[random];
    }).join('');
};
export const toUint8Array = (input) => {
    return Uint8Array.from(input.split('').map(x => x.charCodeAt(0)));
};
export const uint8ArrayToString = (uint8Buffer) => {
    return String.fromCharCode.apply(null, uint8Buffer);
};
export const multihashesSha1 = (input) => {
    const digest = SHA1(input).toString();
    const buffer = fromHexString(digest);
    const output = encode(buffer, 'sha1');
    return toHexString(output);
};
export const decodeMultihash = (hexString) => {
    const buffer = fromHexString(hexString);
    const output = decode(buffer);
    return { ...output, raw: uint8ArrayToString(output.digest) };
};
export const generateSalts = (tokenDetails) => {
    const keys = Object.keys(tokenDetails).sort();
    return keys.map((name) => ({
        name,
        prefix: randomSalt(),
    }));
};
const generateValuesArray = (tokenDetail) => {
    const omitKeys = [];
    const sortedKeys = Object.keys(tokenDetail)
        .sort()
        .filter((key) => !omitKeys.includes(key));
    const valuesArray = [];
    for (const key of sortedKeys) {
        if (typeof tokenDetail[key] !== 'undefined') {
            const field = {
                name: key,
                value: tokenDetail[key].toString(),
            };
            valuesArray.push(field);
        }
    }
    return valuesArray;
};
const generateHashedValuesArray = (token, valuesArray) => {
    if (token.salts && Array.isArray(token.salts)) {
        const tokenKeys = Object.keys(token.token);
        const keysInToken = tokenKeys.sort().join('');
        const keysInSalts = token.salts.map((e) => e.name)
            .filter((e) => tokenKeys.includes(e))
            .sort().join('');
        if (keysInSalts != keysInToken) {
            return null; // invalid salts or keys are not the same
        }
    }
    // generate salt for every property
    const salts = token.salts ? token.salts : generateSalts(token.token);
    token.salts = salts;
    const hashedValuesArray = valuesArray.map((field) => {
        const saltMap = salts.find((e) => e.name == field.name);
        const salt = saltMap === null || saltMap === void 0 ? void 0 : saltMap.prefix;
        return ({
            name: field.name,
            valueHash: multihashesSha1(salt + '_' + field.value),
        });
    });
    return hashedValuesArray;
};
export const generateJsonHash = (token) => {
    // create a json array value serialize in UTF-8
    const valuesArray = generateValuesArray(token.token);
    // hash the values using multihashes sha1
    const hashedValuesArray = generateHashedValuesArray(token, valuesArray);
    if (!hashedValuesArray) {
        return null;
    }
    // return its sha512
    const hash = SHA512(canonicalize(hashedValuesArray)).toString();
    return hash;
};
export const generateZipHash = (token) => {
    const jsonHash = generateJsonHash(token);
    const documentIdHashes = token.documents
        .map((doc) => {
        return multihashesSha1(doc.uuid);
    })
        .sort();
    const zip = {
        jsonHash,
        documentIdHashes,
    };
    const zipHash = SHA512(canonicalize(zip)).toString();
    return zipHash;
};
const selectiveObjectData = (_token, sharedProps) => {
    if (!_token || !_token.token || !_token.documents)
        return null;
    const { token, documents } = _token;
    const salts = _token.salts ? _token.salts : generateSalts(token);
    const data = { documents: {} };
    const valuesArray = generateValuesArray(token);
    valuesArray.forEach((field) => {
        const name = field.name;
        const shared = sharedProps.includes(`token.${name}`);
        const saltMap = salts.find((e) => e.name == name);
        const hashPrefix = saltMap === null || saltMap === void 0 ? void 0 : saltMap.prefix;
        if (shared) {
            data[name] = {
                value: field.value,
                hashPrefix
            };
        }
        else {
            data[name] = {
                hash: multihashesSha1(hashPrefix + '_' + field.value)
            };
        }
    });
    documents.forEach((doc) => {
        const shared = sharedProps.includes(`documents.${doc.path}.${doc.uuid}`);
        if (shared) {
            data.documents[doc.uuid] = [
                'creationDate',
                'filename',
                'fileUrl',
                'hash',
                'lastUpdate',
                'mimeType',
                'name',
                'path',
                'size'
            ].reduce((prev, key) => {
                prev[key] = key == 'hash'
                    ? doc[key] || doc['uuid']
                    : `${doc[key]}`;
                return prev;
            }, {});
        }
        else {
            data.documents[doc.uuid] = {
                hash: doc.hash || doc.uuid
            };
        }
    });
    return data;
};
export const generateVerifiablePresentation = async (latestVerifiableCredential, token, sharedProps, chainId, walletAddress, sign) => {
    var _a;
    if (!token || !token.token || !token.documents)
        return null;
    const presentation = {
        credentialId: (_a = latestVerifiableCredential === null || latestVerifiableCredential === void 0 ? void 0 : latestVerifiableCredential.id) === null || _a === void 0 ? void 0 : _a.split('/').pop(),
        tokenId: token.token.uuid,
        selectiveObjectData: selectiveObjectData(token, sharedProps),
    };
    const address = toChecksumAddress(walletAddress);
    const vp = {
        '@context': ['https://www.w3.org/ns/credentials/v2', 'https://unikbase.com/DigitalPassport/v1'],
        type: 'VerifiablePresentation',
        verifiableCredential: [latestVerifiableCredential],
        holder: `did:ethr:${address}`,
        selectiveObjectData: presentation.selectiveObjectData,
    };
    const signature = await sign(canonicalize(vp));
    const proof = {
        type: 'EcdsaSecp256k1Signature2019',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `did:ethr:${chainId}:${address}`,
        signature
    };
    return { ...presentation, proof };
};
//# sourceMappingURL=hash.js.map