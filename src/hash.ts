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
      case 1: source = digits; break;
      case 2: source = specials; break;
      case 3: source = alpha2; break;
    }
    const random = Math.floor(Math.random() * source.length);
    return source[random];
  }).join('');
}

export const toUint8Array = (input: string) => {
  return Uint8Array.from(input.split('').map(x => x.charCodeAt(0)))
}

export const uint8ArrayToString = (uint8Buffer: Uint8Array) => {
  return String.fromCharCode.apply(null, uint8Buffer as any);
}

export const multihashesSha1 = (input: string) => {
  const buffer = toUint8Array(input);
  const output = encode(buffer, 'sha1');
  return toHexString(output);
}

export const decodeMultihash = (hexString: string) => {
  const buffer = fromHexString(hexString);
  const output = decode(buffer);
  return { ...output, raw: uint8ArrayToString(output.digest) };
}

export const generateSalts = (tokenDetails: any) => {
  const keys = Object.keys(tokenDetails).sort();

  keys.map((name: any) => ({
    name,
    prefix: randomSalt(),
  }));
}

const generateValuesArray = (tokenDetail: any) => {
  const omitKeys: string[] = [];
  const sortedKeys = Object.keys(tokenDetail)
    .sort()
    .filter((key) => !omitKeys.includes(key));
  const valuesArray: any = [];
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

const generateHashedValuesArray = (token: any, valuesArray: any) => {
  if (token.salts && Array.isArray(token.salts)) {
    const keysInToken = Object.keys(token.token).sort().join('');
    const keysInSalts = token.salts.map((e: any) => e.name).sort().join('');
    if (keysInSalts != keysInToken) {
      return null; // invalid salts or keys are not the same
    }
  }

  // generate salt for every property
  const salts = token.salts ? token.salts : generateSalts(token.token);

  token.salts = salts;

  const hashedValuesArray = valuesArray.map((field: any) => {
    const saltMap = salts.find((e: any) => e.name == field.name);
    const salt = saltMap?.prefix;
    return ({
      name: field.name,
      valueHash: multihashesSha1(salt + '_' + field.value),
    })
  });
  return hashedValuesArray;
};

export const generateJsonHash = (token: any) => {
  // create a json array value serialize in UTF-8
  const valuesArray = generateValuesArray(token.token);

  // hash the values using multihashes sha1
  const hashedValuesArray = generateHashedValuesArray(token, valuesArray);

  if (!hashedValuesArray) {
    return null;
  }

  // return its sha512
  const hash = SHA512(JSON.canonicalize(hashedValuesArray)).toString();
  return hash;
};

export const generateZipHash = (token: any) => {
  const jsonHash = generateJsonHash(token);
  const documentIdHashes = token.documents
    .map((doc: any) => {
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
