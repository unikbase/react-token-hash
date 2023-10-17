import { SHA512 } from 'crypto-js';
import 'json-canonicalize/src/global';
import { encode, decode, toHexString, fromHexString } from 'multihashes';
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
    const buffer = toUint8Array(input);
    const output = encode(buffer, 'sha1');
    return toHexString(output);
};
export const decodeMultihash = (hexString) => {
    const buffer = fromHexString(hexString);
    const output = decode(buffer);
    return { ...output, raw: uint8ArrayToString(output.digest) };
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
const generateHashedValuesArray = (valuesArray) => {
    // generate salt for every property
    const salts = valuesArray.map((field) => ({
        name: field.name,
        prefix: randomSalt(),
    }));
    const hashedValuesArray = valuesArray.map((field, index) => {
        const salt = salts[index].prefix;
        return ({
            name: field.name,
            valueHash: multihashesSha1(salt + '_' + field.value),
        });
    });
    return { hashedValuesArray, salts };
};
export const generateJsonHash = (token) => {
    // create a json array value serialize in UTF-8
    const valuesArray = generateValuesArray(token.token);
    // hash the values using multihashes sha1
    const { hashedValuesArray, salts } = generateHashedValuesArray(valuesArray);
    // return its sha512
    const hash = SHA512(JSON.canonicalize(hashedValuesArray)).toString();
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
    const zipHash = SHA512(JSON.canonicalize(zip)).toString();
    return zipHash;
};
//# sourceMappingURL=hash.js.map