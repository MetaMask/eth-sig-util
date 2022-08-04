/* eslint jsdoc/require-description: 0 */
/* eslint jsdoc/require-returns: 0 */
/* eslint jsdoc/match-description: 0 */
/* eslint jsdoc/require-param-description: 0 */

import {
  toBuffer,
  setLengthRight,
  setLengthLeft,
  isHexPrefixed,
  zeros,
} from '@ethereumjs/util';
import { stripHexPrefix } from 'ethjs-util';
import BN from 'bn.js';
import { normalize } from './utils';

//
// Methods borrowed and somewhat adapted from ethereumjs-abi@0.6.8:
// https://npmfs.com/package/ethereumjs-abi/0.6.8/lib/index.js
//

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
      // eslint-disable-next-line no-negated-condition
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
      if (Object.prototype.hasOwnProperty.call(arg, i)) {
        ret.push(encodeSingle(type, arg[i]));
      }
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
  const tmp = /^\D+(\d+)x(\d+)$/u.exec(type);
  return [parseInt(tmp[1], 10), parseInt(tmp[2], 10)];
}
