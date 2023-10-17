import { MD5, SHA512 } from 'crypto-js';
import 'json-canonicalize/src/global';

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

const generateHashedValuesArray = (uuid: string, valuesArray: any) => {
  const hashedValuesArray = valuesArray.map((field: any) => ({
    name: field.name,
    valueHash: MD5(uuid + '_' + field.value).toString(),
  }));
  return hashedValuesArray;
};

export const generateJsonHash = (token: any) => {
  // create a json array value serialize in UTF-8
  const valuesArray = generateValuesArray(token.token);

  // hash the values using MD5
  const hashedValuesArray = generateHashedValuesArray(token.token.uuid, valuesArray);

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
