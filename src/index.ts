import * as ethUtil from 'ethereumjs-util';
import { defaultAbiCoder } from '@ethersproject/abi';
import { keccak256 } from '@ethersproject/solidity';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';
import {
  intToHex,
  isHexString,
  isHexPrefixed,
  stripHexPrefix,
} from 'ethjs-util';
import BN from 'bn.js';

import { padWithZeroes } from './utils';

/**
 * This is the message format used for `V1` of `signTypedData`.
 */
export type TypedDataV1 = EIP712TypedData[];

/**
 * This represents a single field in a `V1` `signTypedData` message.
 *
 * @property name - The name of the field.
 * @property type - The type of a field (must be a supported Solidity type).
 * @property value - The value of the field.
 */
interface EIP712TypedData {
  name: string;
  type: string;
  value: any;
}

export enum Version {
  V1 = 'V1',
  V3 = 'V3',
  V4 = 'V4',
}

export interface EthEncryptedData {
  version: string;
  nonce: string;
  ephemPublicKey: string;
  ciphertext: string;
}

interface MessageTypeProperty {
  name: string;
  type: string;
}

interface MessageTypes {
  EIP712Domain: MessageTypeProperty[];
  [additionalProperties: string]: MessageTypeProperty[];
}

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
export interface TypedMessage<T extends MessageTypes> {
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
}

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
            type: { type: 'string', enum: getSolidityTypes() },
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
 * Get a list of all Solidity types.
 *
 * @returns A list of all Solidity types.
 */
function getSolidityTypes() {
  const types = ['bool', 'address', 'string', 'bytes'];
  const ints = Array.from(new Array(32)).map(
    (_, index) => `int${(index + 1) * 8}`,
  );
  const uints = Array.from(new Array(32)).map(
    (_, index) => `uint${(index + 1) * 8}`,
  );
  const bytes = Array.from(new Array(32)).map(
    (_, index) => `bytes${index + 1}`,
  );

  return [...types, ...ints, ...uints, ...bytes];
}

/**
 * Validate that the given value is a valid version string.
 *
 * @param version - The version value to validate.
 * @param allowedVersions - A list of allowed versions. If omitted, all versions are assumed to be
 * allowed.
 */
function validateVersion(version: Version, allowedVersions?: Version[]) {
  if (!Object.keys(Version).includes(version)) {
    throw new Error(`Invalid version: '${version}'`);
  } else if (allowedVersions && !allowedVersions.includes(version)) {
    throw new Error(
      `Version not allowed: '${version}'. Allowed versions are: ${allowedVersions.join(
        ', ',
      )}`,
    );
  }
}

/*
 * Parse a number in the same manner as `ethereumjs-abi`.
 *
 * @param number - The number to parse.
 * @returns The parsed number.
 */
function legacyParseNumber(num) {
  if (typeof num === 'string') {
    if (isHexPrefixed(num)) {
      return new BN(stripHexPrefix(num), 16);
    }
    return new BN(num, 10);
  } else if (typeof num === 'number') {
    return new BN(num);
  } else if (num.toArray) {
    return num;
  }
  throw new Error(`Argument is not a number: '${num}'`);
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
  value: any,
  version: Version.V3 | Version.V4,
): [type: string, value: any] {
  validateVersion(version, [Version.V3, Version.V4]);

  if (types[type] !== undefined) {
    return [
      'bytes32',
      version === Version.V4 && value == null // eslint-disable-line no-eq-null
        ? '0x0000000000000000000000000000000000000000000000000000000000000000'
        : ethUtil.keccak(encodeData(type, value, types, version)),
    ];
  }

  if (value === undefined) {
    throw new Error(`missing value for field ${name} of type ${type}`);
  }

  if (type === 'bytes') {
    return ['bytes32', ethUtil.keccak(value)];
  }

  if (type === 'string') {
    // convert string to buffer - prevents ethUtil from interpreting strings like '0xabcd' as hex
    if (typeof value === 'string') {
      value = Buffer.from(value, 'utf8');
    }
    return ['bytes32', ethUtil.keccak(value)];
  }

  // `ethers@5` requires that mixed-case addresses are valid EIP-55 address checksums, and that
  // they are specified as strings. `ethereumjs-abi` allowed addresses to be given as numbers as
  // well, and it didn't check for the case when they were given as strings. The `ethereumjs-abi`
  // encoding is preserved here for backwards compatibility.
  // See: https://github.com/ethereumjs/ethereumjs-abi/blob/1cfbb13862f90f0b391d8a699544d5fe4dfb8c7b/lib/index.js#L117
  if (type === 'address') {
    type = 'uint160';
    value = `0x${legacyParseNumber(value).toString('hex')}`;
  }

  if (type.lastIndexOf(']') === type.length - 1) {
    if (version === Version.V3) {
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
      ethUtil.keccak(
        defaultAbiCoder.encode(
          typeValuePairs.map(([t]) => t),
          typeValuePairs.map(([, v]) => v),
        ),
      ),
    ];
  }

  // `ethereumjs-abi` did not correctly check the bounds for fixed-size integer types, but
  // `ethers@5` does. The `ethereumjs-abi` encoding of integer types is preserved here for
  // backwards compatibility.
  // The type is set to `bytes32` to bypass bounds checking in ethers.
  // See: https://github.com/ethereumjs/ethereumjs-abi/blob/1cfbb13862f90f0b391d8a699544d5fe4dfb8c7b/lib/index.js#L189
  if (type.startsWith('int')) {
    const num: BN = legacyParseNumber(value);
    const size =
      type === 'int' ? 256 : parseInt(/^\D+(\d+)$/u.exec(type)[1], 10);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied int exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    const byteEncoding: Buffer = num.toTwos(256).toArrayLike(Buffer, 'be', 32);
    // throw new Error(`size: ${size / 32}, length: ${byteEncoding.byteLength}`);
    return [`bytes32`, byteEncoding];
  }

  // The maximum and minimum safe integers are not supported by `ethers@5`.
  // They are converted to strings here to preserve backwards compatibility.
  // See: https://github.com/ethers-io/ethers.js/issues/1895
  if (type.startsWith('uint') || type.startsWith('bytes')) {
    if (value === Number.MAX_SAFE_INTEGER) {
      value = `0x${Number.MAX_SAFE_INTEGER.toString(16)}`;
    } else if (value === Number.MIN_SAFE_INTEGER) {
      value = `-0x${Number.MAX_SAFE_INTEGER.toString(16)}`;
    }
  }

  if (type.startsWith('bytes')) {
    // `ethers@5` requires that fixed-size byte data match the size of the type, but
    // `ethereumjs-abi` has no such requirement. The encoding from `ethereumjs-abi` is preserved
    // here for backwards compatibility.
    // See: https://github.com/ethereumjs/ethereumjs-abi/blob/1cfbb13862f90f0b391d8a699544d5fe4dfb8c7b/lib/index.js#L161
    return ['bytes32', ethUtil.setLengthRight(value, 32)];
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
  version: Version.V3 | Version.V4,
): Buffer {
  validateVersion(version, [Version.V3, Version.V4]);

  const encodedTypes = ['bytes32'];
  const encodedValues: unknown[] = [hashType(primaryType, types)];

  for (const field of types[primaryType]) {
    if (version === Version.V3 && data[field.name] === undefined) {
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

  return Buffer.from(
    defaultAbiCoder.encode(encodedTypes, encodedValues).slice(2),
    'hex',
  );
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
  [primaryType] = primaryType.match(/^\w*/u);
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
  version: Version.V3 | Version.V4,
): Buffer {
  validateVersion(version, [Version.V3, Version.V4]);

  return ethUtil.keccak(encodeData(primaryType, data, types, version));
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
  return ethUtil.keccak(encodeType(primaryType, types));
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
    sanitizedData.types = { EIP712Domain: [], ...sanitizedData.types };
  }
  return sanitizedData as Required<TypedMessage<T>>;
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
  version: Version.V3 | Version.V4,
): Buffer {
  validateVersion(version, [Version.V3, Version.V4]);

  const sanitizedData = sanitizeData(typedData);
  const parts = [Buffer.from('1901', 'hex')];
  parts.push(
    hashStruct(
      'EIP712Domain',
      sanitizedData.domain,
      sanitizedData.types,
      version,
    ),
  );
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
  return ethUtil.keccak(Buffer.concat(parts));
}

/**
 * A collection of utility functions used for signing typed data
 */
export const TypedDataUtils = {
  encodeData,
  encodeType,
  findTypeDependencies,
  hashStruct,
  hashType,
  sanitizeData,
  eip712Hash,
};

/**
 * Concatenate an extended ECDSA signature into a hex string.
 *
 * @param v - The 'v' portion of the signature.
 * @param r - The 'r' portion of the signature.
 * @param s - The 's' portion of the signature.
 * @returns The concatenated ECDSA signature.
 */
export function concatSig(v: Buffer, r: Buffer, s: Buffer): string {
  const rSig = ethUtil.fromSigned(r);
  const sSig = ethUtil.fromSigned(s);
  const vSig = ethUtil.bufferToInt(v);
  const rStr = padWithZeroes(ethUtil.toUnsigned(rSig).toString('hex'), 64);
  const sStr = padWithZeroes(ethUtil.toUnsigned(sSig).toString('hex'), 64);
  const vStr = stripHexPrefix(intToHex(vSig));
  return ethUtil.addHexPrefix(rStr.concat(sStr, vStr));
}

/**
 * Normalize the input to a 0x-prefixed hex string.
 *
 * @param input - The value to normalize.
 * @returns The normalized 0x-prefixed hex string.
 */
export function normalize(input: number | string): string {
  if (!input) {
    return undefined;
  }

  if (typeof input === 'number') {
    const buffer = ethUtil.toBuffer(input);
    input = ethUtil.bufferToHex(buffer);
  }

  if (typeof input !== 'string') {
    let msg = 'eth-sig-util.normalize() requires hex string or integer input.';
    msg += ` received ${typeof input}: ${input}`;
    throw new Error(msg);
  }

  return ethUtil.addHexPrefix(input.toLowerCase());
}

/**
 * Create an Ethereum-specific signature for a message.
 *
 * This function is equivalent to the `eth_sign` Ethereum JSON-RPC method as specified in EIP-1417,
 * as well as the MetaMask's `personal_sign` method.
 *
 * @param options - The personal sign options.
 * @param options.privateKey - The key to sign with.
 * @param options.data - The data to sign.
 * @returns The signature.
 */
export function personalSign({
  privateKey,
  data,
}: {
  privateKey: Buffer;
  data: unknown;
}): string {
  const message = legacyToBuffer(data);
  const msgHash = ethUtil.hashPersonalMessage(message);
  const sig = ethUtil.ecsign(msgHash, privateKey);
  const serialized = concatSig(ethUtil.toBuffer(sig.v), sig.r, sig.s);
  return serialized;
}

/**
 * Recover the address of the account used to create the given Ethereum signature. The message
 * must have been signed using the `personalSign` function, or an equivalent function.
 *
 * @param options - The signature recovery options.
 * @param options.data - The message that was signed.
 * @param options.signature - The signature for the message.
 * @returns The address of the message signer.
 */
export function recoverPersonalSignature({
  data,
  signature,
}: {
  data: unknown;
  signature: string;
}): string {
  const publicKey = getPublicKeyFor(data, signature);
  const sender = ethUtil.publicToAddress(publicKey);
  const senderHex = ethUtil.bufferToHex(sender);
  return senderHex;
}

/**
 * Recover the public key of the account used to create the given Ethereum signature. The message
 * must have been signed using the `personalSign` function, or an equivalent function.
 *
 * @param options - The public key recovery options.
 * @param options.data - The message that was signed.
 * @param options.signature - The signature for the message.
 * @returns The public key of the message signer.
 */
export function extractPublicKey({
  data,
  signature,
}: {
  data: unknown;
  signature: string;
}): string {
  const publicKey = getPublicKeyFor(data, signature);
  return `0x${publicKey.toString('hex')}`;
}

/**
 * Generate the "V1" hash for the provided typed message.
 *
 * The hash will be generated in accordance with an earlier version of the EIP-712
 * specification. This hash is used in `signTypedData_v1`.
 *
 * @param typedData - The typed message.
 * @returns The type hash for the provided message.
 */
export function typedSignatureHash(typedData: EIP712TypedData[]): string {
  const hashBuffer = _typedSignatureHash(typedData);
  return ethUtil.bufferToHex(hashBuffer);
}

/**
 * Encrypt a message.
 *
 * @param options - The encryption options.
 * @param options.publicKey - The public key of the message recipient.
 * @param options.data - The message data.
 * @param options.version - The type of encryption to use.
 * @returns The encrypted data.
 */
export function encrypt({
  publicKey,
  data,
  version,
}: {
  publicKey: string;
  data: unknown;
  version: string;
}): EthEncryptedData {
  switch (version) {
    case 'x25519-xsalsa20-poly1305': {
      if (typeof data !== 'string') {
        throw new Error('Message data must be given as a string');
      }
      // generate ephemeral keypair
      const ephemeralKeyPair = nacl.box.keyPair();

      // assemble encryption parameters - from string to UInt8
      let pubKeyUInt8Array;
      try {
        pubKeyUInt8Array = naclUtil.decodeBase64(publicKey);
      } catch (err) {
        throw new Error('Bad public key');
      }

      const msgParamsUInt8Array = naclUtil.decodeUTF8(data);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);

      // encrypt
      const encryptedMessage = nacl.box(
        msgParamsUInt8Array,
        nonce,
        pubKeyUInt8Array,
        ephemeralKeyPair.secretKey,
      );

      // handle encrypted data
      const output = {
        version: 'x25519-xsalsa20-poly1305',
        nonce: naclUtil.encodeBase64(nonce),
        ephemPublicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey),
        ciphertext: naclUtil.encodeBase64(encryptedMessage),
      };
      // return encrypted msg data
      return output;
    }

    default:
      throw new Error('Encryption type/version not supported');
  }
}

/**
 * Encrypt a message in a way that obscures the message length.
 *
 * The message is padded to a multiple of 2048 before being encrypted so that the length of the
 * resulting encrypted message can't be used to guess the exact length of the original message.
 *
 * @param options - The encryption options.
 * @param options.publicKey - The public key of the message recipient.
 * @param options.data - The message data.
 * @param options.version - The type of encryption to use.
 * @returns The encrypted data.
 */
export function encryptSafely({
  publicKey,
  data,
  version,
}: {
  publicKey: string;
  data: unknown;
  version: string;
}): EthEncryptedData {
  const DEFAULT_PADDING_LENGTH = 2 ** 11;
  const NACL_EXTRA_BYTES = 16;

  if (!data) {
    throw new Error('Cannot encrypt empty data');
  }

  if (typeof data === 'object' && 'toJSON' in data) {
    // remove toJSON attack vector
    // TODO, check all possible children
    throw new Error(
      'Cannot encrypt with toJSON property.  Please remove toJSON property',
    );
  }

  // add padding
  const dataWithPadding = {
    data,
    padding: '',
  };

  // calculate padding
  const dataLength = Buffer.byteLength(
    JSON.stringify(dataWithPadding),
    'utf-8',
  );
  const modVal = dataLength % DEFAULT_PADDING_LENGTH;
  let padLength = 0;
  // Only pad if necessary
  if (modVal > 0) {
    padLength = DEFAULT_PADDING_LENGTH - modVal - NACL_EXTRA_BYTES; // nacl extra bytes
  }
  dataWithPadding.padding = '0'.repeat(padLength);

  const paddedMessage = JSON.stringify(dataWithPadding);
  return encrypt({ publicKey, data: paddedMessage, version });
}

/**
 * Decrypt a message.
 *
 * @param options - The decryption options.
 * @param options.encryptedData - The encrypted data.
 * @param options.privateKey - The private key to decrypt with.
 * @returns The decrypted message.
 */
export function decrypt({
  encryptedData,
  privateKey,
}: {
  encryptedData: EthEncryptedData;
  privateKey: string;
}): string {
  switch (encryptedData.version) {
    case 'x25519-xsalsa20-poly1305': {
      // string to buffer to UInt8Array
      const recieverPrivateKeyUint8Array = nacl_decodeHex(privateKey);
      const recieverEncryptionPrivateKey = nacl.box.keyPair.fromSecretKey(
        recieverPrivateKeyUint8Array,
      ).secretKey;

      // assemble decryption parameters
      const nonce = naclUtil.decodeBase64(encryptedData.nonce);
      const ciphertext = naclUtil.decodeBase64(encryptedData.ciphertext);
      const ephemPublicKey = naclUtil.decodeBase64(
        encryptedData.ephemPublicKey,
      );

      // decrypt
      const decryptedMessage = nacl.box.open(
        ciphertext,
        nonce,
        ephemPublicKey,
        recieverEncryptionPrivateKey,
      );

      // return decrypted msg data
      let output;
      try {
        output = naclUtil.encodeUTF8(decryptedMessage);
      } catch (err) {
        throw new Error('Decryption failed.');
      }

      if (output) {
        return output;
      }
      throw new Error('Decryption failed.');
    }

    default:
      throw new Error('Encryption type/version not supported.');
  }
}

/**
 * Decrypt a message that has been encrypted using `encryptSafely`.
 *
 * @param options - The decryption options.
 * @param options.encryptedData - The encrypted data.
 * @param options.privateKey - The private key to decrypt with.
 * @returns The decrypted message.
 */
export function decryptSafely({
  encryptedData,
  privateKey,
}: {
  encryptedData: EthEncryptedData;
  privateKey: string;
}): string {
  const dataWithPadding = JSON.parse(decrypt({ encryptedData, privateKey }));
  return dataWithPadding.data;
}

/**
 * Get the encryption public key for the given key.
 *
 * @param privateKey - The private key to generate the encryption public key with.
 * @returns The encryption public key.
 */
export function getEncryptionPublicKey(privateKey: string): string {
  const privateKeyUint8Array = nacl_decodeHex(privateKey);
  const encryptionPublicKey =
    nacl.box.keyPair.fromSecretKey(privateKeyUint8Array).publicKey;
  return naclUtil.encodeBase64(encryptionPublicKey);
}

/**
 * Sign typed data according to EIP-712. The signing differs based upon the `version`.
 *
 * V1 is based upon [an early version of EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
 * that lacked some later security improvements, and should generally be
 * neglected in favor of later versions.
 *
 * V3 is based on EIP-712, except that arrays and recursive data structures
 * are not supported.
 *
 * V4 is based on EIP-712, and includes full support of arrays and recursive
 * data structures.
 *
 * @param options - The signing options.
 * @param options.privateKey - The private key to sign with.
 * @param options.data - The typed data to sign.
 * @param options.version - The signing version to use.
 * @returns The signature.
 */
export function signTypedData<V extends Version, T extends MessageTypes>({
  privateKey,
  data,
  version,
}: {
  privateKey: Buffer;
  data: V extends 'V1' ? TypedDataV1 : TypedMessage<T>;
  version: V;
}): string {
  validateVersion(version);

  const messageHash =
    version === Version.V1
      ? _typedSignatureHash(data as TypedDataV1)
      : TypedDataUtils.eip712Hash(
          data as TypedMessage<T>,
          version as Version.V3 | Version.V4,
        );
  const sig = ethUtil.ecsign(messageHash, privateKey);
  return concatSig(ethUtil.toBuffer(sig.v), sig.r, sig.s);
}

/**
 * Recover the address of the account that created the given EIP-712
 * signature. The version provided must match the version used to
 * create the signature.
 *
 * @param options - The signature recovery options.
 * @param options.data - The data that was signed.
 * @param options.signature - The message signature.
 * @param options.version - The signing version to use.
 * @returns The address of the signer.
 */
export function recoverTypedSignature<
  V extends Version,
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

  const messageHash =
    version === Version.V1
      ? _typedSignatureHash(data as TypedDataV1)
      : TypedDataUtils.eip712Hash(
          data as TypedMessage<T>,
          version as Version.V3 | Version.V4,
        );
  const publicKey = recoverPublicKey(messageHash, signature);
  const sender = ethUtil.publicToAddress(publicKey);
  return ethUtil.bufferToHex(sender);
}

/**
 * Encode a single `signTypedData_v1` field.
 *
 * @param type - The type of the field to encode.
 * @param value - The value of the field to encode.
 * @param inArray - Whether or not the field is within an array.
 * @returns The encoded field.
 */
function encodeSignTypedDataV1Field(type: string, value: any, inArray = false) {
  if (type.endsWith(']')) {
    const subType = type.replace(/\[.*?\]/u, '');
    if (!subType.endsWith(']')) {
      const arraySizeResult = type.match(/(.*)\[(.*?)\]$/u);
      if (
        arraySizeResult &&
        arraySizeResult?.[2] !== '' &&
        value.length > parseInt(arraySizeResult?.[2], 10)
      ) {
        throw new Error(`Elements exceed array size`);
      }
    }
    const arrayValues = value.map(function (v) {
      return encodeSignTypedDataV1Field(subType, v, true);
    });
    return arrayValues;
  }
  // `ethers` allows a wider variety of types for `bytes<size>` and `address` than
  // `ethereumjs-abi` did. The `ethereumjs-abi` validation was preserved for backwards
  // compatibility.
  if (
    (type === 'address' || (type !== 'bytes' && type?.startsWith('bytes'))) &&
    typeof value === 'string' &&
    !isHexString(value)
  ) {
    // Preserve error from https://github.com/ethereumjs/ethereumjs-util/blob/v6.2.1/src/bytes.ts#L79
    throw new Error(
      `Cannot convert string to buffer. toBuffer only supports 0x-prefixed hex strings and this string was given: ${value}`,
    );
  }

  // `ethereumjs-abi` would interpret certain atypical address inputs differently than `ethers`
  // does. The `ethereumjs-abi` input parsing is preserved for backwards compatibility.
  // See: https://github.com/ethereumjs/ethereumjs-abi/blob/v0.6.8/lib/index.js#L478
  if (type === 'address') {
    return ethUtil.setLengthLeft(value, 20);
  }

  // `ethereumjs-abi` would treat negative uint values as positive, whereas `ethers` will not.
  // The `ethereumjs-abi` behavior is preserved for backwards compatibility.
  if (type?.startsWith('uint') && typeof value === 'number' && value < 0) {
    value = -value;
  }

  // `ethereumjs-abi` did not allow `number` values for the `string` type, whereas `ethers` does.
  // An error is thrown in this circumstance to preserve backwards compatibility.
  if (type === 'string' && typeof value === 'number') {
    throw new Error('String values must be passed in as strings or Buffers.');
  }

  if (type === 'bytes') {
    return legacyToBuffer(value);
  } else if (type?.startsWith('bytes')) {
    // `ethers@5` requires that fixed-size byte data match the size of the type, but
    // `ethereumjs-abi` has no such requirement. The encoding from `ethereumjs-abi` is preserved
    // here for backwards compatibility.
    // See: https://github.com/ethereumjs/ethereumjs-abi/blob/1cfbb13862f90f0b391d8a699544d5fe4dfb8c7b/lib/index.js#L485
    const byteSize = Number.parseInt(type.slice(5), 10);
    return ethUtil.setLengthRight(value, byteSize);
  } else if (type.startsWith('int')) {
    const sizeMatch = type.match(/^u?int(\d+)/u);
    const size = sizeMatch ? parseInt(sizeMatch[1], 10) : 256;
    const bitsize = inArray ? 256 : size;
    const num = legacyParseNumber(value);
    return num.toTwos(size).toArrayLike(Buffer, 'be', bitsize / 8);
  } else if (type.startsWith('uint')) {
    const sizeMatch = type.match(/^u?int(\d+)/u);
    const size = sizeMatch ? parseInt(sizeMatch[2], 10) : 256;
    const bitsize = inArray ? 256 : size;
    const num = legacyParseNumber(value);
    return num.toArrayLike(Buffer, 'be', bitsize / 8);
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
 * @returns The type hash for the provided message.
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

  const data = typedData.map(({ type, value }) =>
    encodeSignTypedDataV1Field(type, value),
  );
  const types = typedData.map(function ({ type }) {
    return type;
  });
  const schema = typedData.map(function (e) {
    if (!e.name) {
      throw error;
    }
    return `${e.type} ${e.name}`;
  });

  return Buffer.from(
    keccak256(
      ['bytes32', 'bytes32'],
      [
        keccak256(new Array(typedData.length).fill('string'), schema),
        keccak256(types, data),
      ],
    ).slice(2),
    'hex',
  );
}

/**
 * Recover the public key from the given signature and message hash.
 *
 * @param messageHash - The hash of the signed message.
 * @param signature - The signature.
 * @returns The public key of the signer.
 */
function recoverPublicKey(messageHash: Buffer, signature: string): Buffer {
  const sigParams = ethUtil.fromRpcSig(signature);
  return ethUtil.ecrecover(messageHash, sigParams.v, sigParams.r, sigParams.s);
}

/**
 * Get the public key for the given signature and message.
 *
 * @param message - The message that was signed.
 * @param signature - The signature.
 * @returns The public key of the signer.
 */
function getPublicKeyFor(message: unknown, signature: string): Buffer {
  const messageHash = ethUtil.hashPersonalMessage(legacyToBuffer(message));
  return recoverPublicKey(messageHash, signature);
}

/**
 * Convert a hex string to the UInt8Array format used by nacl.
 *
 * @param msgHex - The string to convert.
 * @returns The converted string.
 */
function nacl_decodeHex(msgHex: string): Uint8Array {
  const msgBase64 = Buffer.from(msgHex, 'hex').toString('base64');
  return naclUtil.decodeBase64(msgBase64);
}

/**
 * Convert a value to a Buffer. This function should be equivalent to the `toBuffer` function in
 * `ethereumjs-util@5.2.1`.
 *
 * @param value - The value to convert to a Buffer.
 * @returns The given value as a Buffer.
 */
function legacyToBuffer(value: unknown) {
  return typeof value === 'string' && !isHexString(value)
    ? Buffer.from(value)
    : ethUtil.toBuffer(value);
}
