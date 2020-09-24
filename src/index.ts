import * as ethUtil from 'ethereumjs-util';
import * as ethAbi from 'ethereumjs-abi';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

export type TypedData = string | EIP712TypedData | EIP712TypedData[];

interface EIP712TypedData {
  name: string;
  type: string;
  value: any;
}

export type Version = 'V1' | 'V2' | 'V3' | 'V4';

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

export interface TypedMessage<T extends MessageTypes> {
  types: T;
  primaryType: keyof T;
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
  };
  message: Record<string, unknown>;
}

const TYPED_MESSAGE_SCHEMA = {
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
 * A collection of utility functions used for signing typed data
 */
const TypedDataUtils = {
  /**
   * Encodes an object by encoding and concatenating each of its members
   *
   * @param {string} primaryType - Root type
   * @param {Object} data - Object to encode
   * @param {Object} types - Type definitions
   * @returns {Buffer} - Encoded representation of an object
   */
  encodeData(
    primaryType: string,
    data: Record<string, unknown>,
    types: Record<string, MessageTypeProperty[]>,
    useV4 = true,
  ): Buffer {
    const encodedTypes = ['bytes32'];
    const encodedValues = [this.hashType(primaryType, types)];

    if (useV4) {
      const encodeField = (name, type, value) => {
        if (types[type] !== undefined) {
          return [
            'bytes32',
            value == null // eslint-disable-line no-eq-null
              ? '0x0000000000000000000000000000000000000000000000000000000000000000'
              : ethUtil.keccak(this.encodeData(type, value, types, useV4)),
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
          const parsedType = type.slice(0, type.lastIndexOf('['));
          const typeValuePairs = value.map((item) =>
            encodeField(name, parsedType, item),
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
      };

      for (const field of types[primaryType]) {
        const [type, value] = encodeField(
          field.name,
          field.type,
          data[field.name],
        );
        encodedTypes.push(type);
        encodedValues.push(value);
      }
    } else {
      for (const field of types[primaryType]) {
        let value = data[field.name];
        if (value !== undefined) {
          if (field.type === 'bytes') {
            encodedTypes.push('bytes32');
            value = ethUtil.keccak(value);
            encodedValues.push(value);
          } else if (field.type === 'string') {
            encodedTypes.push('bytes32');
            // convert string to buffer - prevents ethUtil from interpreting strings like '0xabcd' as hex
            if (typeof value === 'string') {
              value = Buffer.from(value, 'utf8');
            }
            value = ethUtil.keccak(value);
            encodedValues.push(value);
          } else if (types[field.type] !== undefined) {
            encodedTypes.push('bytes32');
            value = ethUtil.keccak(
              this.encodeData(field.type, value, types, useV4),
            );
            encodedValues.push(value);
          } else if (field.type.lastIndexOf(']') === field.type.length - 1) {
            throw new Error(
              'Arrays are unimplemented in encodeData; use V4 extension',
            );
          } else {
            encodedTypes.push(field.type);
            encodedValues.push(value);
          }
        }
      }
    }

    return ethAbi.rawEncode(encodedTypes, encodedValues);
  },

  /**
   * Encodes the type of an object by encoding a comma delimited list of its members
   *
   * @param {string} primaryType - Root type to encode
   * @param {Object} types - Type definitions
   * @returns {string} - Encoded representation of the type of an object
   */
  encodeType(
    primaryType: string,
    types: Record<string, MessageTypeProperty[]>,
  ): string {
    let result = '';
    let deps = this.findTypeDependencies(primaryType, types).filter(
      (dep) => dep !== primaryType,
    );
    deps = [primaryType].concat(deps.sort());
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
  },

  /**
   * Finds all types within a type definition object
   *
   * @param {string} primaryType - Root type
   * @param {Object} types - Type definitions
   * @param {Array} results - current set of accumulated types
   * @returns {Array} - Set of all types found in the type definition
   */
  findTypeDependencies(
    primaryType: string,
    types: Record<string, MessageTypeProperty[]>,
    results: string[] = [],
  ): string[] {
    [primaryType] = primaryType.match(/^\w*/u);
    if (results.includes(primaryType) || types[primaryType] === undefined) {
      return results;
    }
    results.push(primaryType);
    for (const field of types[primaryType]) {
      for (const dep of this.findTypeDependencies(field.type, types, results)) {
        !results.includes(dep) && results.push(dep);
      }
    }
    return results;
  },

  /**
   * Hashes an object
   *
   * @param {string} primaryType - Root type
   * @param {Object} data - Object to hash
   * @param {Object} types - Type definitions
   * @returns {Buffer} - Hash of an object
   */
  hashStruct(
    primaryType: string,
    data: Record<string, unknown>,
    types: Record<string, unknown>,
    useV4 = true,
  ): Buffer {
    return ethUtil.keccak(this.encodeData(primaryType, data, types, useV4));
  },

  /**
   * Hashes the type of an object
   *
   * @param {string} primaryType - Root type to hash
   * @param {Object} types - Type definitions
   * @returns {Buffer} - Hash of an object
   */
  hashType(primaryType: string, types: Record<string, unknown>): Buffer {
    return ethUtil.keccak(this.encodeType(primaryType, types));
  },

  /**
   * Removes properties from a message object that are not defined per EIP-712
   *
   * @param {Object} data - typed message object
   * @returns {Object} - typed message object with only allowed fields
   */
  sanitizeData<T extends MessageTypes>(
    data: TypedData | TypedMessage<T>,
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
  },

  /**
   * Signs a typed message as per EIP-712 and returns its keccak hash
   *
   * @param {Object} typedData - Types message data to hash as per eip-712
   * @returns {Buffer} - keccak hash of the resulting signed message
   */
  eip712Hash<T extends MessageTypes>(
    typedData: Partial<TypedData | TypedMessage<T>>,
    useV4 = true,
  ): Buffer {
    const sanitizedData = this.sanitizeData(typedData);
    const parts = [Buffer.from('1901', 'hex')];
    parts.push(
      this.hashStruct(
        'EIP712Domain',
        sanitizedData.domain,
        sanitizedData.types,
        useV4,
      ),
    );
    if (sanitizedData.primaryType !== 'EIP712Domain') {
      parts.push(
        this.hashStruct(
          sanitizedData.primaryType,
          sanitizedData.message,
          sanitizedData.types,
          useV4,
        ),
      );
    }
    return ethUtil.keccak(Buffer.concat(parts));
  },
};

function concatSig(v: Buffer, r: Buffer, s: Buffer): string {
  const rSig = ethUtil.fromSigned(r);
  const sSig = ethUtil.fromSigned(s);
  const vSig = ethUtil.bufferToInt(v);
  const rStr = padWithZeroes(ethUtil.toUnsigned(rSig).toString('hex'), 64);
  const sStr = padWithZeroes(ethUtil.toUnsigned(sSig).toString('hex'), 64);
  const vStr = ethUtil.stripHexPrefix(ethUtil.intToHex(vSig));
  return ethUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex');
}

function normalize(input: number | string): string {
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

function personalSign<T extends MessageTypes>(
  privateKey: Buffer,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
): string {
  const message = ethUtil.toBuffer(msgParams.data);
  const msgHash = ethUtil.hashPersonalMessage(message);
  const sig = ethUtil.ecsign(msgHash, privateKey);
  const serialized = ethUtil.bufferToHex(concatSig(sig.v, sig.r, sig.s));
  return serialized;
}

function recoverPersonalSignature<T extends MessageTypes>(
  msgParams: SignedMsgParams<TypedData | TypedMessage<T>>,
): string {
  const publicKey = getPublicKeyFor(msgParams);
  const sender = ethUtil.publicToAddress(publicKey);
  const senderHex = ethUtil.bufferToHex(sender);
  return senderHex;
}

function extractPublicKey<T extends MessageTypes>(
  msgParams: SignedMsgParams<TypedData | TypedMessage<T>>,
): string {
  const publicKey = getPublicKeyFor(msgParams);
  return `0x${publicKey.toString('hex')}`;
}

function externalTypedSignatureHash(typedData: EIP712TypedData[]): string {
  const hashBuffer = typedSignatureHash(typedData);
  return ethUtil.bufferToHex(hashBuffer);
}

function signTypedDataLegacy<T extends MessageTypes>(
  privateKey: Buffer,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
): string {
  const msgHash = typedSignatureHash(msgParams.data);
  const sig = ethUtil.ecsign(msgHash, privateKey);
  return ethUtil.bufferToHex(concatSig(sig.v, sig.r, sig.s));
}

function recoverTypedSignatureLegacy<T extends MessageTypes>(
  msgParams: SignedMsgParams<TypedData | TypedMessage<T>>,
): string {
  const msgHash = typedSignatureHash(msgParams.data);
  const publicKey = recoverPublicKey(msgHash, msgParams.sig);
  const sender = ethUtil.publicToAddress(publicKey);
  return ethUtil.bufferToHex(sender);
}

function encrypt<T extends MessageTypes>(
  receiverPublicKey: string,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
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

function encryptSafely<T extends MessageTypes>(
  receiverPublicKey: string,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
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

function decrypt(
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

function decryptSafely(
  encryptedData: EthEncryptedData,
  receiverPrivateKey: string,
): string {
  const dataWithPadding = JSON.parse(
    decrypt(encryptedData, receiverPrivateKey),
  );
  return dataWithPadding.data;
}

function getEncryptionPublicKey(privateKey: string): string {
  const privateKeyUint8Array = nacl_decodeHex(privateKey);
  const encryptionPublicKey =
    nacl.box.keyPair.fromSecretKey(privateKeyUint8Array).publicKey;
  return naclUtil.encodeBase64(encryptionPublicKey);
}

/**
 * A generic entry point for all typed data methods to be passed, includes a version parameter.
 */
function signTypedMessage<T extends MessageTypes>(
  privateKey: Buffer,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
  version: Version = 'V4',
): string {
  switch (version) {
    case 'V1':
      return signTypedDataLegacy(privateKey, msgParams);
    case 'V3':
      return signTypedData(privateKey, msgParams);
    case 'V4':
    default:
      return signTypedData_v4(privateKey, msgParams);
  }
}

function recoverTypedMessage<T extends MessageTypes>(
  msgParams: SignedMsgParams<TypedData | TypedMessage<T>>,
  version: Version = 'V4',
): string {
  switch (version) {
    case 'V1':
      return recoverTypedSignatureLegacy(msgParams);
    case 'V3':
      return recoverTypedSignature(msgParams);
    case 'V4':
    default:
      return recoverTypedSignature_v4(msgParams);
  }
}

function signTypedData<T extends MessageTypes>(
  privateKey: Buffer,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
): string {
  const message = TypedDataUtils.eip712Hash(msgParams.data, false);
  const sig = ethUtil.ecsign(message, privateKey);
  return ethUtil.bufferToHex(concatSig(sig.v, sig.r, sig.s));
}

function signTypedData_v4<T extends MessageTypes>(
  privateKey: Buffer,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
): string {
  const message = TypedDataUtils.eip712Hash(msgParams.data);
  const sig = ethUtil.ecsign(message, privateKey);
  return ethUtil.bufferToHex(concatSig(sig.v, sig.r, sig.s));
}

function recoverTypedSignature<T extends MessageTypes>(
  msgParams: SignedMsgParams<TypedData | TypedMessage<T>>,
): string {
  const message = TypedDataUtils.eip712Hash(msgParams.data, false);
  const publicKey = recoverPublicKey(message, msgParams.sig);
  const sender = ethUtil.publicToAddress(publicKey);
  return ethUtil.bufferToHex(sender);
}

function recoverTypedSignature_v4<T extends MessageTypes>(
  msgParams: SignedMsgParams<TypedData | TypedMessage<T>>,
): string {
  const message = TypedDataUtils.eip712Hash(msgParams.data);
  const publicKey = recoverPublicKey(message, msgParams.sig);
  const sender = ethUtil.publicToAddress(publicKey);
  return ethUtil.bufferToHex(sender);
}

export {
  TYPED_MESSAGE_SCHEMA,
  TypedDataUtils,
  concatSig,
  normalize,
  personalSign,
  recoverPersonalSignature,
  extractPublicKey,
  externalTypedSignatureHash as typedSignatureHash,
  signTypedDataLegacy,
  recoverTypedSignatureLegacy,
  encrypt,
  encryptSafely,
  decrypt,
  decryptSafely,
  getEncryptionPublicKey,
  signTypedMessage,
  recoverTypedMessage,
  signTypedData,
  signTypedData_v4,
  recoverTypedSignature,
  recoverTypedSignature_v4,
};

/**
 * @param typedData - Array of data along with types, as per EIP712.
 * @returns Buffer
 */
function typedSignatureHash<T extends MessageTypes>(
  typedData: TypedData | TypedMessage<T>,
): Buffer {
  const error = new Error('Expect argument to be non-empty array');
  if (
    typeof typedData !== 'object' ||
    !('length' in typedData) ||
    !typedData.length
  ) {
    throw error;
  }

  const data = typedData.map(function (e) {
    return e.type === 'bytes' ? ethUtil.toBuffer(e.value) : e.value;
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
  const signature = ethUtil.toBuffer(sig);
  const sigParams = ethUtil.fromRpcSig(signature);
  return ethUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s);
}

function getPublicKeyFor<T extends MessageTypes>(
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
): Buffer {
  const message = ethUtil.toBuffer(msgParams.data);
  const msgHash = ethUtil.hashPersonalMessage(message);
  return recoverPublicKey(msgHash, msgParams.sig);
}

function padWithZeroes(number: string, length: number): string {
  let myString = `${number}`;
  while (myString.length < length) {
    myString = `0${myString}`;
  }
  return myString;
}

// converts hex strings to the Uint8Array format used by nacl
function nacl_decodeHex(msgHex: string): Uint8Array {
  const msgBase64 = Buffer.from(msgHex, 'hex').toString('base64');
  return naclUtil.decodeBase64(msgBase64);
}
