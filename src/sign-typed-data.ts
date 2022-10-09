import { ecsign, arrToBufArr, publicToAddress } from '@ethereumjs/util';
import { encode, encodePacked } from '@metamask/abi-utils';
import {
  getArrayType,
  getByteLength,
  getLength,
  isArrayType,
} from '@metamask/abi-utils/dist/parsers';
import { padStart } from '@metamask/abi-utils/dist/utils';
import {
  add0x,
  assert,
  bigIntToBytes,
  bytesToHex,
  concatBytes,
  hexToBytes,
  isStrictHexString,
  numberToBytes,
  stringToBytes,
  isHexString,
} from '@metamask/utils';
import { keccak256 } from 'ethereum-cryptography/keccak';

import {
  concatSig,
  isNullish,
  legacyToBuffer,
  recoverPublicKey,
} from './utils';

/**
 * This is the message format used for `V1` of `signTypedData`.
 */
export type TypedDataV1 = TypedDataV1Field[];

/**
 * This represents a single field in a `V1` `signTypedData` message.
 *
 * @property name - The name of the field.
 * @property type - The type of a field (must be a supported Solidity type).
 * @property value - The value of the field.
 */
export type TypedDataV1Field = {
  name: string;
  type: string;
  value: any;
};

/**
 * Represents the version of `signTypedData` being used.
 *
 * V1 is based upon [an early version of
 * EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
 * that lacked some later security improvements, and should generally be neglected in favor of
 * later versions.
 *
 * V3 is based on EIP-712, except that arrays and recursive data structures are not supported.
 *
 * V4 is based on EIP-712, and includes full support of arrays and recursive data structures.
 */
export enum SignTypedDataVersion {
  V1 = 'V1',
  V3 = 'V3',
  V4 = 'V4',
}

export type MessageTypeProperty = {
  name: string;
  type: string;
};

export type MessageTypes = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  EIP712Domain: MessageTypeProperty[];
  [additionalProperties: string]: MessageTypeProperty[];
};

/**
 * This is the message format used for `signTypeData`, for all versions
 * except `V1`.
 *
 * @template T - The custom types used by this message.
 * @property types - The custom types used by this message.
 * @property primaryType - The type of the message.
 * @property domain - Signing domain metadata. The signing domain is the intended context for the
 * signature (e.g. the dapp, protocol, etc. that it's intended for). This data is used to
 * construct the domain seperator of the message.
 * @property domain.name - The name of the signing domain.
 * @property domain.version - The current major version of the signing domain.
 * @property domain.chainId - The chain ID of the signing domain.
 * @property domain.verifyingContract - The address of the contract that can verify the signature.
 * @property domain.salt - A disambiguating salt for the protocol.
 * @property message - The message to be signed.
 */
export type TypedMessage<T extends MessageTypes> = {
  types: T;
  primaryType: keyof T;
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
    salt?: ArrayBuffer;
  };
  message: Record<string, unknown>;
};

export const TYPED_MESSAGE_SCHEMA = {
  type: 'object',
  properties: {
    types: {
      type: 'object',
      additionalProperties: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            type: { type: 'string' },
          },
          required: ['name', 'type'],
        },
      },
    },
    primaryType: { type: 'string' },
    domain: { type: 'object' },
    message: { type: 'object' },
  },
  required: ['types', 'primaryType', 'domain', 'message'],
};

/**
 * Validate that the given value is a valid version string.
 *
 * @param version - The version value to validate.
 * @param allowedVersions - A list of allowed versions. If omitted, all versions are assumed to be
 * allowed.
 */
function validateVersion(
  version: SignTypedDataVersion,
  allowedVersions?: SignTypedDataVersion[],
) {
  if (!Object.keys(SignTypedDataVersion).includes(version)) {
    throw new Error(`Invalid version: '${version}'`);
  } else if (allowedVersions && !allowedVersions.includes(version)) {
    throw new Error(
      `SignTypedDataVersion not allowed: '${version}'. Allowed versions are: ${allowedVersions.join(
        ', ',
      )}`,
    );
  }
}

/**
 * Parse a string, number, or bigint value into a `Uint8Array`.
 *
 * @param type - The type of the value.
 * @param value - The value to parse.
 * @returns The parsed value.
 */
function parseNumber(type: string, value: string | number | bigint) {
  assert(
    value !== null,
    `Unable to encode value: Invalid number. Expected a valid number value, but received "${value}".`,
  );

  const bigIntValue = BigInt(value);

  const length = getLength(type);
  const maxValue = BigInt(2) ** BigInt(length) - BigInt(1);

  // Note that this is not accurate, since the actual maximum value for unsigned
  // integers is `2 ^ (length - 1) - 1`, but this is required for backwards
  // compatibility with the old implementation.
  assert(
    bigIntValue >= -maxValue && bigIntValue <= maxValue,
    `Unable to encode value: Number "${value}" is out of range for type "${type}".`,
  );

  return bigIntValue;
}

/**
 * Parse an address string to a `Uint8Array`. The behaviour of this is quite
 * strange, in that it does not parse the address as hexadecimal string, nor as
 * UTF-8. It does some weird stuff with the string and char codes, and then
 * returns the result as a `Uint8Array`.
 *
 * This is based on the old `ethereumjs-abi` implementation, which essentially
 * calls `new BN(address, 10)` on the address string. This is not a valid
 * implementation of address parsing, but it is what we have to work with.
 *
 * @param address - The address to parse.
 * @returns The parsed address.
 */
function reallyStrangeAddressToBytes(address: string): Uint8Array {
  let r = BigInt(0);
  let b = BigInt(0);

  for (let i = 0; i < address.length; i++) {
    const c = BigInt(address.charCodeAt(i) - 48);
    r *= BigInt(10);

    // 'a'
    if (c >= 49) {
      b = c - BigInt(49) + BigInt(0xa);

      // 'A'
    } else if (c >= 17) {
      b = c - BigInt(17) + BigInt(0xa);

      // '0' - '9'
    } else {
      b = c;
    }

    r += b;
  }

  return padStart(bigIntToBytes(r), 20);
}

/**
 * Encode a single field.
 *
 * @param types - All type definitions.
 * @param name - The name of the field to encode.
 * @param type - The type of the field being encoded.
 * @param value - The value to encode.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns Encoded representation of the field.
 */
function encodeField(
  types: Record<string, MessageTypeProperty[]>,
  name: string,
  type: string,
  // TODO: constrain type on `value`
  value: any,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): [type: string, value: Uint8Array | string] {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  if (types[type] !== undefined) {
    return [
      'bytes32',
      // TODO: return Buffer, remove string from return type
      version === SignTypedDataVersion.V4 && value == null // eslint-disable-line no-eq-null
        ? '0x0000000000000000000000000000000000000000000000000000000000000000'
        : arrToBufArr(keccak256(encodeData(type, value, types, version))),
    ];
  }

  // `function` is supported in `@metamask/abi-utils`, but not allowed by
  // EIP-712, so we throw an error here.
  if (type === 'function') {
    throw new Error('Unsupported or invalid type: function');
  }

  if (value === undefined) {
    throw new Error(`missing value for field ${name} of type ${type}`);
  }

  if (type === 'address') {
    if (typeof value === 'number') {
      return ['address', padStart(numberToBytes(value), 20)];
    } else if (isStrictHexString(value)) {
      return ['address', add0x(value)];
    } else if (typeof value === 'string') {
      return ['address', reallyStrangeAddressToBytes(value).subarray(0, 20)];
    }
  }

  if (type === 'bool') {
    if (value) {
      return ['bool', hexToBytes('0x01')];
    }

    return ['bool', hexToBytes('0x00')];
  }

  if (type === 'bytes') {
    if (typeof value === 'number') {
      value = numberToBytes(value);
    } else if (isHexString(value)) {
      const prepend = value.length % 2 ? '0' : '';
      value = hexToBytes(`${prepend}${value}`);
    } else if (typeof value === 'string') {
      value = stringToBytes(value);
    }
    return ['bytes32', arrToBufArr(keccak256(value))];
  }

  if (type.startsWith('bytes') && type !== 'bytes' && !type.includes('[')) {
    if (typeof value === 'number') {
      if (value < 0) {
        return ['bytes32', new Uint8Array(32)];
      }

      return ['bytes32', bigIntToBytes(BigInt(value))];
    } else if (isStrictHexString(value)) {
      return ['bytes32', hexToBytes(value)];
    }

    return ['bytes32', value];
  }

  if (type.startsWith('int') && !type.includes('[')) {
    const bigIntValue = parseNumber(type, value);
    if (bigIntValue >= BigInt(0)) {
      return ['uint256', bigIntToBytes(bigIntValue)];
    }

    return ['int256', bigIntToBytes(bigIntValue)];
  }

  if (type === 'string') {
    if (typeof value === 'number') {
      value = numberToBytes(value);
    } else {
      value = stringToBytes(value ?? '');
    }
    return ['bytes32', arrToBufArr(keccak256(value))];
  }

  if (type.endsWith(']')) {
    if (version === SignTypedDataVersion.V3) {
      throw new Error(
        'Arrays are unimplemented in encodeData; use V4 extension',
      );
    }
    const parsedType = type.slice(0, type.lastIndexOf('['));
    const typeValuePairs = value.map((item) =>
      encodeField(types, name, parsedType, item, version),
    );
    return [
      'bytes32',
      arrToBufArr(
        keccak256(
          encode(
            typeValuePairs.map(([t]) => t),
            typeValuePairs.map(([, v]) => v),
          ),
        ),
      ),
    ];
  }

  return [type, value];
}

/**
 * Encodes an object by encoding and concatenating each of its members.
 *
 * @param primaryType - The root type.
 * @param data - The object to encode.
 * @param types - Type definitions for all types included in the message.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns An encoded representation of an object.
 */
function encodeData(
  primaryType: string,
  data: Record<string, unknown>,
  types: Record<string, MessageTypeProperty[]>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Uint8Array {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const encodedTypes = ['bytes32'];
  const encodedValues: (Uint8Array | string)[] = [hashType(primaryType, types)];

  for (const field of types[primaryType]) {
    if (version === SignTypedDataVersion.V3 && data[field.name] === undefined) {
      continue;
    }
    const [type, value] = encodeField(
      types,
      field.name,
      field.type,
      data[field.name],
      version,
    );
    encodedTypes.push(type);
    encodedValues.push(value);
  }

  return arrToBufArr(encode(encodedTypes, encodedValues));
}

/**
 * Encodes the type of an object by encoding a comma delimited list of its members.
 *
 * @param primaryType - The root type to encode.
 * @param types - Type definitions for all types included in the message.
 * @returns An encoded representation of the primary type.
 */
function encodeType(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
): string {
  let result = '';
  const unsortedDeps = findTypeDependencies(primaryType, types);
  unsortedDeps.delete(primaryType);

  const deps = [primaryType, ...Array.from(unsortedDeps).sort()];
  for (const type of deps) {
    const children = types[type];
    if (!children) {
      throw new Error(`No type definition specified: ${type}`);
    }

    result += `${type}(${types[type]
      .map(({ name, type: t }) => `${t} ${name}`)
      .join(',')})`;
  }

  return result;
}

/**
 * Finds all types within a type definition object.
 *
 * @param primaryType - The root type.
 * @param types - Type definitions for all types included in the message.
 * @param results - The current set of accumulated types.
 * @returns The set of all types found in the type definition.
 */
function findTypeDependencies(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
  results: Set<string> = new Set(),
): Set<string> {
  if (typeof primaryType !== 'string') {
    throw new Error(
      `Invalid findTypeDependencies input ${JSON.stringify(primaryType)}`,
    );
  }
  const match = primaryType.match(/^\w*/u) as RegExpMatchArray;
  [primaryType] = match;
  if (results.has(primaryType) || types[primaryType] === undefined) {
    return results;
  }

  results.add(primaryType);

  for (const field of types[primaryType]) {
    findTypeDependencies(field.type, types, results);
  }
  return results;
}

/**
 * Hashes an object.
 *
 * @param primaryType - The root type.
 * @param data - The object to hash.
 * @param types - Type definitions for all types included in the message.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The hash of the object.
 */
function hashStruct(
  primaryType: string,
  data: Record<string, unknown>,
  types: Record<string, MessageTypeProperty[]>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const encoded = encodeData(primaryType, data, types, version);
  const hashed = keccak256(encoded);
  const buf = arrToBufArr(hashed);
  return buf;
}

/**
 * Hashes the type of an object.
 *
 * @param primaryType - The root type to hash.
 * @param types - Type definitions for all types included in the message.
 * @returns The hash of the object type.
 */
function hashType(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
): Buffer {
  const encodedHashType = stringToBytes(encodeType(primaryType, types));
  return arrToBufArr(keccak256(encodedHashType));
}

/**
 * Removes properties from a message object that are not defined per EIP-712.
 *
 * @param data - The typed message object.
 * @returns The typed message object with only allowed fields.
 */
function sanitizeData<T extends MessageTypes>(
  data: TypedMessage<T>,
): TypedMessage<T> {
  const sanitizedData: Partial<TypedMessage<T>> = {};
  for (const key in TYPED_MESSAGE_SCHEMA.properties) {
    if (data[key]) {
      sanitizedData[key] = data[key];
    }
  }

  if ('types' in sanitizedData) {
    // TODO: Fix types
    sanitizedData.types = { EIP712Domain: [], ...sanitizedData.types } as any;
  }
  return sanitizedData as Required<TypedMessage<T>>;
}

/**
 * Create a EIP-712 Domain Hash.
 * This hash is used at the top of the EIP-712 encoding.
 *
 * @param typedData - The typed message to hash.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The hash of the domain object.
 */
function eip712DomainHash<T extends MessageTypes>(
  typedData: TypedMessage<T>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const sanitizedData = sanitizeData(typedData);
  const { domain } = sanitizedData;
  const domainType = { EIP712Domain: sanitizedData.types.EIP712Domain };
  return hashStruct('EIP712Domain', domain, domainType, version);
}

/**
 * Hash a typed message according to EIP-712. The returned message starts with the EIP-712 prefix,
 * which is "1901", followed by the hash of the domain separator, then the data (if any).
 * The result is hashed again and returned.
 *
 * This function does not sign the message. The resulting hash must still be signed to create an
 * EIP-712 signature.
 *
 * @param typedData - The typed message to hash.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The hash of the typed message.
 */
function eip712Hash<T extends MessageTypes>(
  typedData: TypedMessage<T>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const sanitizedData = sanitizeData(typedData);
  const parts = [hexToBytes('1901')];
  parts.push(eip712DomainHash(typedData, version));

  if (sanitizedData.primaryType !== 'EIP712Domain') {
    parts.push(
      hashStruct(
        // TODO: Validate that this is a string, so this type cast can be removed.
        sanitizedData.primaryType as string,
        sanitizedData.message,
        sanitizedData.types,
        version,
      ),
    );
  }
  return arrToBufArr(keccak256(concatBytes(parts)));
}

/**
 * A collection of utility functions used for signing typed data.
 */
export const TypedDataUtils = {
  encodeData,
  encodeType,
  findTypeDependencies,
  hashStruct,
  hashType,
  sanitizeData,
  eip712Hash,
  eip712DomainHash,
};

/**
 * Generate the "V1" hash for the provided typed message.
 *
 * The hash will be generated in accordance with an earlier version of the EIP-712
 * specification. This hash is used in `signTypedData_v1`.
 *
 * @param typedData - The typed message.
 * @returns The '0x'-prefixed hex encoded hash representing the type of the provided message.
 */
export function typedSignatureHash(typedData: TypedDataV1Field[]): string {
  const hashBuffer = _typedSignatureHash(typedData);
  return bytesToHex(hashBuffer);
}

/**
 * Normalize a value, so that `@metamask/abi-utils` can handle it. This
 * matches the behaviour of the `ethereumjs-abi` library.
 *
 * @param type - The type of the value to normalize.
 * @param value - The value to normalize.
 * @returns The normalized value.
 */
function normalizeValue(type: string, value: unknown): any {
  if (isArrayType(type) && Array.isArray(value)) {
    const [innerType] = getArrayType(type);
    return value.map((item) => normalizeValue(innerType, item));
  }

  if (type === 'address') {
    if (typeof value === 'number') {
      return padStart(numberToBytes(value), 20);
    }

    if (isStrictHexString(value)) {
      return padStart(hexToBytes(value).subarray(0, 20), 20);
    }

    if (value instanceof Uint8Array) {
      return padStart(value.subarray(0, 20), 20);
    }
  }

  if (type === 'bool') {
    return Boolean(value);
  }

  if (type.startsWith('bytes') && type !== 'bytes') {
    const length = getByteLength(type);
    if (typeof value === 'number') {
      if (value < 0) {
        // `solidityPack(['bytesN'], [-1])` returns `0x00..00`.
        return new Uint8Array();
      }

      return numberToBytes(value).subarray(0, length);
    }

    if (isStrictHexString(value)) {
      return hexToBytes(value).subarray(0, length);
    }

    if (value instanceof Uint8Array) {
      return value.subarray(0, length);
    }
  }

  if (type.startsWith('uint')) {
    if (typeof value === 'number') {
      return Math.abs(value);
    }
  }

  if (type.startsWith('int')) {
    if (typeof value === 'number') {
      const length = getLength(type);
      return BigInt.asIntN(length, BigInt(value));
    }
  }

  return value;
}

/**
 * Generate the "V1" hash for the provided typed message.
 *
 * The hash will be generated in accordance with an earlier version of the EIP-712
 * specification. This hash is used in `signTypedData_v1`.
 *
 * @param typedData - The typed message.
 * @returns The hash representing the type of the provided message.
 */
function _typedSignatureHash(typedData: TypedDataV1): Buffer {
  const error = new Error('Expect argument to be non-empty array');
  if (
    typeof typedData !== 'object' ||
    !('length' in typedData) ||
    !typedData.length
  ) {
    throw error;
  }

  const normalizedData = typedData.map(({ name, type, value }) => ({
    name,
    type,
    value: normalizeValue(type, value),
  }));

  const data = normalizedData.map(function (e) {
    if (e.type !== 'bytes') {
      return e.value;
    }

    return legacyToBuffer(e.value);
  });
  const types = normalizedData.map(function (e) {
    if (e.type === 'function') {
      throw new Error('Unsupported or invalid type: function');
    }

    return e.type;
  });
  const schema = typedData.map(function (e) {
    if (!e.name) {
      throw error;
    }
    return `${e.type} ${e.name}`;
  });

  return arrToBufArr(
    keccak256(
      encodePacked(
        ['bytes32', 'bytes32'],
        [
          keccak256(encodePacked(['string[]'], [schema])),
          keccak256(encodePacked(types, data)),
        ],
      ),
    ),
  );
}

/**
 * Sign typed data according to EIP-712. The signing differs based upon the `version`.
 *
 * V1 is based upon [an early version of
 * EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
 * that lacked some later security improvements, and should generally be neglected in favor of
 * later versions.
 *
 * V3 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), except that arrays and
 * recursive data structures are not supported.
 *
 * V4 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), and includes full support of
 * arrays and recursive data structures.
 *
 * @param options - The signing options.
 * @param options.privateKey - The private key to sign with.
 * @param options.data - The typed data to sign.
 * @param options.version - The signing version to use.
 * @returns The '0x'-prefixed hex encoded signature.
 */
export function signTypedData<
  V extends SignTypedDataVersion,
  T extends MessageTypes,
>({
  privateKey,
  data,
  version,
}: {
  privateKey: Buffer;
  data: V extends 'V1' ? TypedDataV1 : TypedMessage<T>;
  version: V;
}): string {
  validateVersion(version);
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(privateKey)) {
    throw new Error('Missing private key parameter');
  }

  const messageHash =
    version === SignTypedDataVersion.V1
      ? _typedSignatureHash(data as TypedDataV1)
      : TypedDataUtils.eip712Hash(data as TypedMessage<T>, version);
  const sig = ecsign(messageHash, privateKey);
  return concatSig(arrToBufArr(bigIntToBytes(sig.v)), sig.r, sig.s);
}

/**
 * Recover the address of the account that created the given EIP-712
 * signature. The version provided must match the version used to
 * create the signature.
 *
 * @param options - The signature recovery options.
 * @param options.data - The typed data that was signed.
 * @param options.signature - The '0x-prefixed hex encoded message signature.
 * @param options.version - The signing version to use.
 * @returns The '0x'-prefixed hex address of the signer.
 */
export function recoverTypedSignature<
  V extends SignTypedDataVersion,
  T extends MessageTypes,
>({
  data,
  signature,
  version,
}: {
  data: V extends 'V1' ? TypedDataV1 : TypedMessage<T>;
  signature: string;
  version: V;
}): string {
  validateVersion(version);
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(signature)) {
    throw new Error('Missing signature parameter');
  }

  const messageHash =
    version === SignTypedDataVersion.V1
      ? _typedSignatureHash(data as TypedDataV1)
      : TypedDataUtils.eip712Hash(data as TypedMessage<T>, version);
  const publicKey = recoverPublicKey(messageHash, signature);
  const sender = publicToAddress(publicKey);
  return bytesToHex(sender);
}
