import { SHA512 } from 'crypto-js';
import { canonicalize } from 'json-canonicalize';
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

  return keys.map((name: any) => ({
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
  const hash = SHA512(canonicalize(hashedValuesArray)).toString();
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
  const zipHash = SHA512(canonicalize(zip)).toString();
  return zipHash;
};

const selectiveObjectData = (_token: any, sharedProps: Array<string>) => {

  if (!_token || !_token.token || !_token.documents) return null;

  const { token, documents } = _token;
  const salts = _token.salts ? _token.salts : generateSalts(token);

  const data: any = {documents:{}};
  const valuesArray = generateValuesArray(token);

  valuesArray.forEach((field: any) => {
    const name = field.name;
    const shared = sharedProps.includes(`token.${name}`);

    const saltMap = salts.find((e: any) => e.name == name);
    const hashPrefix = saltMap?.prefix;

    if (shared) {
      data[name] = {
        value: field.value,
        hashPrefix
      }
    } else {
      data[name] = {
        hash: multihashesSha1(hashPrefix + '_' + field.value)
      }
    }
  });

  documents.forEach((doc: any) => {
    const shared = sharedProps.includes(`documents.${doc.path}.${doc.uuid}`)

    if (shared) {
      data.documents[doc.uuid] = {
        value: doc.fileUrl,
        hash: doc.hash || doc.uuid
      }
    } else {
      data.documents[doc.uuid] = {
        hash: doc.hash || doc.uuid
      }
    }
  });

  return data;
}

export const generateVerifiablePresentation = async (
  credentialId: string,
  token: any,
  sharedProps: Array<string>,
  chainId: string,
  walletAddress: string,
  sign: (data: any) => Promise<string>) => {

  if (!token || !token.token || !token.documents) return null;


  const presentation = {
    credentialId,
    tokenId: token.token.uuid,
    selectiveObjectData: selectiveObjectData(token, sharedProps),
  }

  const signature = await sign(canonicalize(presentation));

  const proof = {
    type: 'EcdsaSecp256k1Signature2019',
    created: new Date().toISOString(),
    proofPurpose: 'assertionMethod',
    verificationMethod: `did:ethr:${chainId}:${walletAddress}`,
    signature
  }

  return { ...presentation, proof }
}