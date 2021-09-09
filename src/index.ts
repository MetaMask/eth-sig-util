import * as ethUtil from 'ethereumjs-util';
import * as ethAbi from 'ethereumjs-abi';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';
import { intToHex, isHexString, stripHexPrefix } from 'ethjs-util';

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

export type SignedMsgParams<D> = Required<MsgParams<D>>;

export interface MsgParams<D> {
  data: D;
  sig?: string;
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
 *   signature (e.g. the dapp, protocol, etc. that it's intended for). This data is used to
 *   construct the domain seperator of the message.
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
        ethAbi.rawEncode(
          typeValuePairs.map(([t]) => t),
          typeValuePairs.map(([, v]) => v),
        ),
      ),
    ];
  }

  return [type, value];
}

/**
 * Encodes an object by encoding and concatenating each of its members
 *
 * @param {string} primaryType - Root type
 * @param {Object} data - Object to encode
 * @param {Object} types - Type definitions
 * @param {Version} version - The EIP-712 version the encoding should comply with
 * @returns {Buffer} - Encoded representation of an object
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

  return ethAbi.rawEncode(encodedTypes, encodedValues);
}

/**
 * Encodes the type of an object by encoding a comma delimited list of its members
 *
 * @param {string} primaryType - Root type to encode
 * @param {Object} types - Type definitions
 * @returns {string} - Encoded representation of the type of an object
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
 * Finds all types within a type definition object
 *
 * @param {string} primaryType - Root type
 * @param {Object} types - Type definitions
 * @param {Array} results - current set of accumulated types
 * @returns {Array} - Set of all types found in the type definition
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
 * Hashes an object
 *
 * @param {string} primaryType - Root type
 * @param {Object} data - Object to hash
 * @param {Object} types - Type definitions
 * @returns {Buffer} - Hash of an object
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
 * Hashes the type of an object
 *
 * @param {string} primaryType - Root type to hash
 * @param {Object} types - Type definitions
 * @returns {Buffer} - Hash of an object
 */
function hashType(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
): Buffer {
  return ethUtil.keccak(encodeType(primaryType, types));
}

/**
 * Removes properties from a message object that are not defined per EIP-712
 *
 * @param {Object} data - typed message object
 * @returns {Object} - typed message object with only allowed fields
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
 * @param {Object} typedData - The typed message to hash.
 * @returns {Buffer} - The hash of the typed message.
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
 * Concatenate an extended ECDSA signature into a hex string
 *
 * @param v - The 'v' portion of the signature
 * @param r - The 'r' portion of the signature
 * @param s - The 's' portion of the signature
 * @returns The concatenated ECDSA signature
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
 * @param privateKey - The key to sign with.
 * @param msgParams - The message parameters. Currently includes just the message data.
 * @param msgParams.data - The data to sign.
 */
export function personalSign(
  privateKey: Buffer,
  msgParams: MsgParams<unknown>,
): string {
  const message = legacyToBuffer(msgParams.data);
  const msgHash = ethUtil.hashPersonalMessage(message);
  const sig = ethUtil.ecsign(msgHash, privateKey);
  const serialized = concatSig(ethUtil.toBuffer(sig.v), sig.r, sig.s);
  return serialized;
}

/**
 * Recover the address of the account used to create the given Ethereum signature. The message
 * must have been signed using the `personalSign` function, or an equivalent function.
 *
 * @param msgParams - The message parameters, which includes both the message and the signature.
 * @param msgParams.data - The message that was signed.
 * @param msgParams.sig - The signature for the message.
 * @returns The address of the message signer.
 */
export function recoverPersonalSignature(
  msgParams: SignedMsgParams<unknown>,
): string {
  const publicKey = getPublicKeyFor(msgParams);
  const sender = ethUtil.publicToAddress(publicKey);
  const senderHex = ethUtil.bufferToHex(sender);
  return senderHex;
}

/**
 * Recover the public key of the account used to create the given Ethereum signature. The message
 * must have been signed using the `personalSign` function, or an equivalent function.
 *
 * @param msgParams - The message parameters, which includes both the message and the signature.
 * @param msgParams.data - The message that was signed.
 * @param msgParams.sig - The signature for the message.
 * @returns The public key of the message signer.
 */
export function extractPublicKey(msgParams: SignedMsgParams<unknown>): string {
  const publicKey = getPublicKeyFor(msgParams);
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
 * @param receiverPublicKey - The public key of the message recipient.
 * @param msgParams - The message parameters. Currently includes just the message data.
 * @param version - The type of encryption to use.
 * @returns The encrypted data.
 */
export function encrypt(
  receiverPublicKey: string,
  msgParams: MsgParams<unknown>,
  version: string,
): EthEncryptedData {
  switch (version) {
    case 'x25519-xsalsa20-poly1305': {
      if (typeof msgParams.data !== 'string') {
        throw new Error(
          'Cannot detect secret message, message params should be of the form {data: "secret message"} ',
        );
      }
      // generate ephemeral keypair
      const ephemeralKeyPair = nacl.box.keyPair();

      // assemble encryption parameters - from string to UInt8
      let pubKeyUInt8Array;
      try {
        pubKeyUInt8Array = naclUtil.decodeBase64(receiverPublicKey);
      } catch (err) {
        throw new Error('Bad public key');
      }

      const msgParamsUInt8Array = naclUtil.decodeUTF8(msgParams.data);
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
 * @param receiverPublicKey - The public key of the message recipient.
 * @param msgParams - The message parameters. Currently includes just the message data.
 * @param version - The type of encryption to use.
 * @returns The encrypted data.
 */
export function encryptSafely(
  receiverPublicKey: string,
  msgParams: MsgParams<unknown>,
  version: string,
): EthEncryptedData {
  const DEFAULT_PADDING_LENGTH = 2 ** 11;
  const NACL_EXTRA_BYTES = 16;

  const { data } = msgParams;
  if (!data) {
    throw new Error('Cannot encrypt empty msg.data');
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

  const paddedMsgParams = { data: JSON.stringify(dataWithPadding) };
  return encrypt(receiverPublicKey, paddedMsgParams, version);
}

/**
 * Decrypt a message.
 *
 * @param encryptedData - The encrypted data.
 * @param receiverPrivateKey - The private key to decrypt with.
 * @returns The decrypted message.
 */
export function decrypt(
  encryptedData: EthEncryptedData,
  receiverPrivateKey: string,
): string {
  switch (encryptedData.version) {
    case 'x25519-xsalsa20-poly1305': {
      // string to buffer to UInt8Array
      const recieverPrivateKeyUint8Array = nacl_decodeHex(receiverPrivateKey);
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
 * @param encryptedData - The encrypted data.
 * @param receiverPrivateKey - The private key to decrypt with.
 * @returns The decrypted message.
 */
export function decryptSafely(
  encryptedData: EthEncryptedData,
  receiverPrivateKey: string,
): string {
  const dataWithPadding = JSON.parse(
    decrypt(encryptedData, receiverPrivateKey),
  );
  return dataWithPadding.data;
}

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
 * @param privateKey - The private key to sign with.
 * @param msgParams - Signing parameters.
 * @param msgParams.data - The typed data to sign.
 * @param version - The signing version to use.
 * @returns The signature
 */
export function signTypedData<V extends Version, T extends MessageTypes>(
  privateKey: Buffer,
  msgParams: V extends 'V1'
    ? MsgParams<TypedDataV1>
    : MsgParams<TypedMessage<T>>,
  version: V,
): string {
  validateVersion(version);

  const messageHash =
    version === Version.V1
      ? _typedSignatureHash(msgParams.data as TypedDataV1)
      : TypedDataUtils.eip712Hash(
          msgParams.data as TypedMessage<T>,
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
 * @param msgParams - Signing parameters.
 * @param msgParams.data - The data that was signed.
 * @param version - The signing version to use.
 * @returns The address of the signer.
 */
export function recoverTypedSignature<
  V extends Version,
  T extends MessageTypes,
>(
  msgParams: V extends 'V1'
    ? SignedMsgParams<TypedDataV1>
    : SignedMsgParams<TypedMessage<T>>,
  version: V,
): string {
  validateVersion(version);

  const messageHash =
    version === Version.V1
      ? _typedSignatureHash(msgParams.data as TypedDataV1)
      : TypedDataUtils.eip712Hash(
          msgParams.data as TypedMessage<T>,
          version as Version.V3 | Version.V4,
        );
  const publicKey = recoverPublicKey(messageHash, msgParams.sig);
  const sender = ethUtil.publicToAddress(publicKey);
  return ethUtil.bufferToHex(sender);
}

function _typedSignatureHash(typedData: TypedDataV1): Buffer {
  const error = new Error('Expect argument to be non-empty array');
  if (
    typeof typedData !== 'object' ||
    !('length' in typedData) ||
    !typedData.length
  ) {
    throw error;
  }

  const data = typedData.map(function (e) {
    if (e.type !== 'bytes') {
      return e.value;
    }

    return legacyToBuffer(e.value);
  });
  const types = typedData.map(function (e) {
    return e.type;
  });
  const schema = typedData.map(function (e) {
    if (!e.name) {
      throw error;
    }
    return `${e.type} ${e.name}`;
  });

  return ethAbi.soliditySHA3(
    ['bytes32', 'bytes32'],
    [
      ethAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema),
      ethAbi.soliditySHA3(types, data),
    ],
  );
}

function recoverPublicKey(hash: Buffer, sig: string): Buffer {
  const sigParams = ethUtil.fromRpcSig(sig);
  return ethUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s);
}

function getPublicKeyFor(msgParams: MsgParams<unknown>): Buffer {
  const message = legacyToBuffer(msgParams.data);
  const msgHash = ethUtil.hashPersonalMessage(message);
  return recoverPublicKey(msgHash, msgParams.sig);
}

// converts hex strings to the Uint8Array format used by nacl
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
