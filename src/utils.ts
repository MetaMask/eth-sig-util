import {
  addHexPrefix,
  bufferToHex,
  bufferToInt,
  ecrecover,
  fromRpcSig,
  fromSigned,
  toBuffer,
  ToBufferInputTypes,
  toUnsigned,
  setLengthRight,
  setLengthLeft,
  isHexPrefixed,
  zeros,
} from '@ethereumjs/util';
import { intToHex, isHexString, stripHexPrefix } from 'ethjs-util';
import BN from 'bn.js';

/**
 * Pads the front of the given hex string with zeroes until it reaches the
 * target length. If the input string is already longer than or equal to the
 * target length, it is returned unmodified.
 *
 * If the input string is "0x"-prefixed or not a hex string, an error will be
 * thrown.
 *
 * @param hexString - The hexadecimal string to pad with zeroes.
 * @param targetLength - The target length of the hexadecimal string.
 * @returns The input string front-padded with zeroes, or the original string
 * if it was already greater than or equal to to the target length.
 */
export function padWithZeroes(hexString: string, targetLength: number): string {
  if (hexString !== '' && !/^[a-f0-9]+$/iu.test(hexString)) {
    throw new Error(
      `Expected an unprefixed hex string. Received: ${hexString}`,
    );
  }

  if (targetLength < 0) {
    throw new Error(
      `Expected a non-negative integer target length. Received: ${targetLength}`,
    );
  }

  return String.prototype.padStart.call(hexString, targetLength, '0');
}

/**
 * Returns `true` if the given value is nullish.
 *
 * @param value - The value being checked.
 * @returns Whether the value is nullish.
 */
export function isNullish(value) {
  return value === null || value === undefined;
}

/**
 * Convert a value to a Buffer. This function should be equivalent to the `toBuffer` function in
 * `ethereumjs-util@5.2.1`.
 *
 * @param value - The value to convert to a Buffer.
 * @returns The given value as a Buffer.
 */
export function legacyToBuffer(value: ToBufferInputTypes) {
  return typeof value === 'string' && !isHexString(value)
    ? Buffer.from(value)
    : toBuffer(value);
}

/**
 * Concatenate an extended ECDSA signature into a single '0x'-prefixed hex string.
 *
 * @param v - The 'v' portion of the signature.
 * @param r - The 'r' portion of the signature.
 * @param s - The 's' portion of the signature.
 * @returns The concatenated ECDSA signature as a '0x'-prefixed string.
 */
export function concatSig(v: Buffer, r: Buffer, s: Buffer): string {
  const rSig = fromSigned(r);
  const sSig = fromSigned(s);
  const vSig = bufferToInt(v);
  const rStr = padWithZeroes(toUnsigned(rSig).toString('hex'), 64);
  const sStr = padWithZeroes(toUnsigned(sSig).toString('hex'), 64);
  const vStr = stripHexPrefix(intToHex(vSig));
  return addHexPrefix(rStr.concat(sStr, vStr));
}

/**
 * Recover the public key from the given signature and message hash.
 *
 * @param messageHash - The hash of the signed message.
 * @param signature - The signature.
 * @returns The public key of the signer.
 */
export function recoverPublicKey(
  messageHash: Buffer,
  signature: string,
): Buffer {
  const sigParams = fromRpcSig(signature);
  return ecrecover(messageHash, sigParams.v, sigParams.r, sigParams.s);
}

/**
 * Normalize the input to a lower-cased '0x'-prefixed hex string.
 *
 * @param input - The value to normalize.
 * @returns The normalized value.
 */
export function normalize(input: number | string): string {
  if (!input) {
    return undefined;
  }

  if (typeof input === 'number') {
    if (input < 0) {
      return '0x';
    }
    const buffer = toBuffer(input);
    input = bufferToHex(buffer);
  }

  if (typeof input !== 'string') {
    let msg = 'eth-sig-util.normalize() requires hex string or integer input.';
    msg += ` received ${typeof input}: ${input}`;
    throw new Error(msg);
  }

  return addHexPrefix(input.toLowerCase());
}

// /
// / Stolen from ethereumjs-abi:
// /

/**
 * Packs non-standard encoded values packed according to their respective type in types in a buffer.
 *
 * @param types - Array of types of each value to encode.
 * @param values - Array of values to encode.
 * @returns A buffer containing the packed values.
 */
export function solidityPack(types: string[], values: any[]) {
  if (types.length !== values.length) {
    throw new Error('Number of types are not matching the values');
  }

  const ret = [];

  for (let i = 0; i < types.length; i++) {
    const type = elementaryName(types[i]);
    const value = values[i];
    ret.push(solidityHexValue(type, value, null));
  }

  return Buffer.concat(ret);
}

/**
 * Checks if a value is an array (represented as a string).
 *
 * @param type - The value to check whether it is an array.
 * @returns A boolean indicating whether the passed value is an array.
 */
function isArray(type) {
  return type.lastIndexOf(']') === type.length - 1;
}

/**
 * Parse array type for packing solidity values.
 *
 * @param type - A string that may be an array to parse.
 * @returns A parsed value from the array.
 */
function parseTypeArray(type) {
  const tmp = type.match(/(.*)\[(.*?)\]$/u);
  if (tmp) {
    return tmp[2] === '' ? 'dynamic' : parseInt(tmp[2], 10);
  }
  return null;
}

/**
 * Parse N from type<N>.
 *
 * @param type - Value to parse.
 * @returns Parsed value.
 */
function parseTypeN(type) {
  return parseInt(/^\D+(\d+)$/u.exec(type)[1], 10);
}

/**
 * Parse a number for determining a solidity hexvalue.
 *
 * @param arg - Number to parse.
 * @returns Parsed value.
 */
function parseNumber(arg) {
  const type = typeof arg;
  if (type === 'string') {
    if (isHexPrefixed(arg)) {
      return new BN(stripHexPrefix(arg), 16);
    }
    return new BN(arg, 10);
  } else if (type === 'number') {
    return new BN(arg);
  } else if (arg.toArray) {
    // assume this is a BN for the moment, replace with BN.isBN soon
    return arg;
  }
  throw new Error('Argument is not a number');
}

/**
 * Get solidity hex value from type, value and bitsize inputs for packing these values in a buffer.
 *
 * @param type - The type of the value to encode.
 * @param value - The value to encode.
 * @param bitsize - The bitsize of the value to encode.
 * @returns The encoded soldity hex value.
 */
function solidityHexValue(type, value, bitsize) {
  // pass in bitsize = null if use default bitsize
  let size, num;
  if (isArray(type)) {
    const subType = type.replace(/\[.*?\]/u, '');
    if (!isArray(subType)) {
      const arraySize = parseTypeArray(type);
      if (
        arraySize !== 'dynamic' &&
        arraySize !== 0 &&
        value.length > arraySize
      ) {
        throw new Error(`Elements exceed array size: ${arraySize}`);
      }
    }
    const arrayValues = value.map(function (v) {
      return solidityHexValue(subType, v, 256);
    });
    return Buffer.concat(arrayValues);
  } else if (type === 'bytes') {
    return value;
  } else if (type === 'string') {
    return Buffer.from(value, 'utf8');
  } else if (type === 'bool') {
    bitsize = bitsize || 8;
    const padding = Array(bitsize / 4).join('0');
    return Buffer.from(value ? `${padding}1` : `${padding}0`, 'hex');
  } else if (type === 'address') {
    let bytesize = 20;
    if (bitsize) {
      bytesize = bitsize / 8;
    }
    return setLengthLeft(toBuffer(value), bytesize);
  } else if (type.startsWith('bytes')) {
    size = parseTypeN(type);
    if (size < 1 || size > 32) {
      throw new Error(`Invalid bytes<N> width: ${size}`);
    }

    if (typeof value === 'number') {
      value = normalize(value);
    }
    return setLengthRight(toBuffer(value), size);
  } else if (type.startsWith('uint')) {
    size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid uint<N> width: ${size}`);
    }

    num = parseNumber(value);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied uint exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    bitsize = bitsize || size;
    return num.toArrayLike(Buffer, 'be', bitsize / 8);
  } else if (type.startsWith('int')) {
    size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid int<N> width: ${size}`);
    }

    num = parseNumber(value);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied int exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    bitsize = bitsize || size;
    return num.toTwos(size).toArrayLike(Buffer, 'be', bitsize / 8);
  }
  // FIXME: support all other types
  throw new Error(`Unsupported or invalid type: ${type}`);
}

/**
 * Gets the correct solidity type name.
 *
 * @param name - The type name for which we want the corresponding solidity type name.
 * @returns The solidity type name for the input value.
 */
function elementaryName(name) {
  if (name.startsWith('int[')) {
    return `int256${name.slice(3)}`;
  } else if (name === 'int') {
    return 'int256';
  } else if (name.startsWith('uint[')) {
    return `uint256${name.slice(4)}`;
  } else if (name === 'uint') {
    return 'uint256';
  } else if (name.startsWith('fixed[')) {
    return `fixed128x128${name.slice(5)}`;
  } else if (name === 'fixed') {
    return 'fixed128x128';
  } else if (name.startsWith('ufixed[')) {
    return `ufixed128x128${name.slice(6)}`;
  } else if (name === 'ufixed') {
    return 'ufixed128x128';
  }
  return name;
}

/**
 * @param types
 * @param values
 */
export function rawEncode(types, values) {
  const output = [];
  const data = [];

  let headLength = 0;

  types.forEach(function (type) {
    if (isArray(type)) {
      const size: number | 'dynamic' = parseTypeArray(type);

      if (size !== 'dynamic') {
        headLength += 32 * size;
      } else {
        headLength += 32;
      }
    } else {
      headLength += 32;
    }
  });

  for (let i = 0; i < types.length; i++) {
    const type = elementaryName(types[i]);
    const value = values[i];
    const cur = encodeSingle(type, value);

    // Use the head/tail method for storing dynamic data
    if (isDynamic(type)) {
      output.push(encodeSingle('uint256', headLength));
      data.push(cur);
      headLength += cur.length;
    } else {
      output.push(cur);
    }
  }

  return Buffer.concat(output.concat(data));
}

// Encodes a single item (can be dynamic array)
// @returns: Buffer
/**
 * @param type
 * @param arg
 */
function encodeSingle(type, arg) {
  let size, num, ret, i;

  if (type === 'address') {
    return encodeSingle('uint160', parseNumber(arg));
  } else if (type === 'bool') {
    return encodeSingle('uint8', arg ? 1 : 0);
  } else if (type === 'string') {
    return encodeSingle('bytes', Buffer.from(arg, 'utf8'));
  } else if (isArray(type)) {
    // this part handles fixed-length ([2]) and variable length ([]) arrays
    // NOTE: we catch here all calls to arrays, that simplifies the rest
    if (typeof arg.length === 'undefined') {
      throw new Error('Not an array?');
    }
    size = parseTypeArray(type);
    if (size !== 'dynamic' && size !== 0 && arg.length > size) {
      throw new Error(`Elements exceed array size: ${size}`);
    }
    ret = [];
    type = type.slice(0, type.lastIndexOf('['));
    if (typeof arg === 'string') {
      arg = JSON.parse(arg);
    }

    for (i in arg) {
      ret.push(encodeSingle(type, arg[i]));
    }

    if (size === 'dynamic') {
      const length = encodeSingle('uint256', arg.length);
      ret.unshift(length);
    }
    return Buffer.concat(ret);
  } else if (type === 'bytes') {
    arg = Buffer.from(arg);

    ret = Buffer.concat([encodeSingle('uint256', arg.length), arg]);

    if (arg.length % 32 !== 0) {
      ret = Buffer.concat([ret, zeros(32 - (arg.length % 32))]);
    }

    return ret;
  } else if (type.startsWith('bytes')) {
    size = parseTypeN(type);
    if (size < 1 || size > 32) {
      throw new Error(`Invalid bytes<N> width: ${size}`);
    }

    if (typeof arg === 'number') {
      arg = normalize(arg);
    }
    return setLengthRight(toBuffer(arg), 32);
  } else if (type.startsWith('uint')) {
    size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid uint<N> width: ${size}`);
    }

    num = parseNumber(arg);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied uint exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    if (num < 0) {
      throw new Error('Supplied uint is negative');
    }

    return num.toArrayLike(Buffer, 'be', 32);
  } else if (type.startsWith('int')) {
    size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid int<N> width: ${size}`);
    }

    num = parseNumber(arg);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied int exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    return num.toTwos(256).toArrayLike(Buffer, 'be', 32);
  } else if (type.startsWith('ufixed')) {
    size = parseTypeNxM(type);

    num = parseNumber(arg);

    if (num < 0) {
      throw new Error('Supplied ufixed is negative');
    }

    return encodeSingle('uint256', num.mul(new BN(2).pow(new BN(size[1]))));
  } else if (type.startsWith('fixed')) {
    size = parseTypeNxM(type);

    return encodeSingle(
      'int256',
      parseNumber(arg).mul(new BN(2).pow(new BN(size[1]))),
    );
  }

  throw new Error(`Unsupported or invalid type: ${type}`);
}

// Is a type dynamic?
/**
 * @param type
 */
function isDynamic(type) {
  // FIXME: handle all types? I don't think anything is missing now
  return (
    type === 'string' || type === 'bytes' || parseTypeArray(type) === 'dynamic'
  );
}

// Parse N,M from type<N>x<M>
/**
 * @param type
 */
function parseTypeNxM(type) {
  const tmp = /^\D+(\d+)x(\d+)$/.exec(type);
  return [parseInt(tmp[1], 10), parseInt(tmp[2], 10)];
}

/**
 * Node's Buffer.from() method does not seem to buffer numbers correctly out of the box.
 * This helper method formats the number correct for Buffer.from to return correct buffer.
 *
 * @param num - The number to convert to buffer.
 * @returns The number in buffer form.
 */
export function numberToBuffer(num: number) {
  const hexVal = num.toString(16);
  const prepend = hexVal.length % 2 ? '0' : '';
  return Buffer.from(prepend + hexVal, 'hex');
}
