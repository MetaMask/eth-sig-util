/* eslint jsdoc/require-description: 0 */
/* eslint jsdoc/require-returns: 0 */
/* eslint jsdoc/match-description: 0 */
/* eslint jsdoc/require-param-description: 0 */

import {
  ToBufferInputTypes,
  toBuffer,
  setLengthRight,
  setLengthLeft,
  isHexPrefixed,
  zeros,
} from '@ethereumjs/util';
import BN from 'bn.js';
import { stripHexPrefix } from 'ethjs-util';

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
export function solidityPack(types: string[], values: any[]): Buffer {
  if (types.length !== values.length) {
    throw new Error('Number of types are not matching the values');
  }

  const ret: Buffer[] = [];

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
function isArray(type: string): boolean {
  return type.endsWith(']');
}

/**
 * Parse array type for packing solidity values.
 *
 * @param type - A string that may be an array to parse.
 * @returns A parsed value from the array.
 */
function parseTypeArray(type: string): 'dynamic' | number | null {
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
function parseTypeN(type: string): number {
  const match = /^\D+(\d+)$/u.exec(type);
  if (match === null) {
    throw new Error(`Invalid parseTypeN input "${type}".`);
  }
  return parseInt(match[1], 10);
}

/**
 * Parse a number for determining a solidity hexvalue.
 *
 * @param arg - Number to parse.
 * @returns Parsed value.
 */
export function parseNumber(arg: string | number | BN): BN {
  const type = typeof arg;
  if (type === 'string') {
    if (isHexPrefixed(arg as string)) {
      return new BN(stripHexPrefix(arg), 16);
    }
    return new BN(arg, 10);
  } else if (type === 'number') {
    return new BN(arg);
  } else if (
    (arg && Object.prototype.hasOwnProperty.call(arg, 'toArray')) ||
    BN.isBN(arg)
  ) {
    return arg as BN;
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
function solidityHexValue(
  type: string,
  value: ToBufferInputTypes,
  bitsize: number | null,
): Buffer {
  // pass in bitsize = null if use default bitsize
  if (isArray(type)) {
    const subType = type.replace(/\[.*?\]/u, '');
    if (!isArray(subType)) {
      const arraySize = parseTypeArray(type);
      if (
        arraySize !== 'dynamic' &&
        arraySize !== 0 &&
        arraySize !== null &&
        (value as any[]).length > arraySize
      ) {
        throw new Error(`Elements exceed array size: ${arraySize}`);
      }
    }
    const arrayValues = (value as number[]).map((v) =>
      solidityHexValue(subType, v, 256),
    );
    return Buffer.concat(arrayValues);
  } else if (type === 'bytes') {
    return value as Buffer;
  } else if (type === 'string') {
    return Buffer.from(value as string, 'utf8');
  } else if (type === 'bool') {
    // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
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
    const size = parseTypeN(type);
    if (size < 1 || size > 32) {
      throw new Error(`Invalid bytes<N> width: ${size}`);
    }

    if (typeof value === 'number') {
      value = normalize(value);
    }
    return setLengthRight(toBuffer(value), size);
  } else if (type.startsWith('uint')) {
    const size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid uint<N> width: ${size}`);
    }

    const num = parseNumber(value as number);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied uint exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
    bitsize = bitsize || size;
    return num.toArrayLike(Buffer, 'be', bitsize / 8);
  } else if (type.startsWith('int')) {
    const size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid int<N> width: ${size}`);
    }

    const num = parseNumber(value as number);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied int exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
    bitsize = bitsize || size;
    return num.toTwos(size).toArrayLike(Buffer, 'be', bitsize / 8);
  }
  // FIXME: support all other types
  throw new Error(`Unsupported or invalid type: ${JSON.stringify(type)}`);
}

/**
 * Gets the correct solidity type name.
 *
 * @param name - The type name for which we want the corresponding solidity type name.
 * @returns The solidity type name for the input value.
 */
function elementaryName(name: string): string {
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
export function rawEncode(
  types: string[],
  values: (BN | Buffer | string | number | string[] | number[])[],
): Buffer {
  const output: Buffer[] = [];
  const data: Buffer[] = [];

  let headLength = 0;

  types.forEach((type) => {
    if (isArray(type)) {
      const size: number | 'dynamic' | null = parseTypeArray(type);
      // eslint-disable-next-line no-negated-condition
      if (size !== 'dynamic' && size !== null) {
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
function encodeSingle(
  type: string,
  arg: BN | Buffer | string | number | string[] | number[],
): Buffer {
  if (type === 'address') {
    return encodeSingle('uint160', parseNumber(arg as string));
  } else if (type === 'bool') {
    return encodeSingle('uint8', arg ? 1 : 0);
  } else if (type === 'string') {
    return encodeSingle('bytes', Buffer.from(arg as string, 'utf8'));
  } else if (isArray(type)) {
    // this part handles fixed-length ([2]) and variable length ([]) arrays
    // NOTE: we catch here all calls to arrays, that simplifies the rest
    if (typeof (arg as any).length === 'undefined') {
      throw new Error('Not an array?');
    }
    const size = parseTypeArray(type);
    if (
      size !== 'dynamic' &&
      size !== 0 &&
      size !== null &&
      (arg as any).length > size
    ) {
      throw new Error(`Elements exceed array size: ${size}`);
    }
    const ret: Buffer[] = [];
    type = type.slice(0, type.lastIndexOf('['));
    if (typeof arg === 'string') {
      arg = JSON.parse(arg);
    }

    // TODO: if this is array, should do for-of
    for (const i in arg as Record<string, any>) {
      if (Object.prototype.hasOwnProperty.call(arg, i)) {
        ret.push(encodeSingle(type, arg[i]));
      }
    }

    if (size === 'dynamic') {
      const length = encodeSingle('uint256', (arg as any).length);
      ret.unshift(length);
    }
    return Buffer.concat(ret);
  } else if (type === 'bytes') {
    arg = Buffer.from(arg as Buffer);

    let ret = Buffer.concat([encodeSingle('uint256', arg.length), arg]);

    if (arg.length % 32 !== 0) {
      ret = Buffer.concat([ret, zeros(32 - (arg.length % 32))]);
    }

    return ret;
  } else if (type.startsWith('bytes')) {
    const size = parseTypeN(type);
    if (size < 1 || size > 32) {
      throw new Error(`Invalid bytes<N> width: ${size}`);
    }

    // TODO: fix types here
    const nArg = typeof arg === 'number' ? normalize(arg) : arg;
    return setLengthRight(toBuffer(nArg as string), 32);
  } else if (type.startsWith('uint')) {
    const size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid uint<N> width: ${size}`);
    }

    const num = parseNumber(arg as string);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied uint exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    if (num.isNeg()) {
      throw new Error('Supplied uint is negative');
    }

    return num.toArrayLike(Buffer, 'be', 32);
  } else if (type.startsWith('int')) {
    const size = parseTypeN(type);
    if (size % 8 || size < 8 || size > 256) {
      throw new Error(`Invalid int<N> width: ${size}`);
    }

    const num = parseNumber(arg as string);
    if (num.bitLength() > size) {
      throw new Error(
        `Supplied int exceeds width: ${size} vs ${num.bitLength()}`,
      );
    }

    return num.toTwos(256).toArrayLike(Buffer, 'be', 32);
  } else if (type.startsWith('ufixed')) {
    const size = parseTypeNxM(type);

    const num = parseNumber(arg as string);

    if (num.isNeg()) {
      throw new Error('Supplied ufixed is negative');
    }

    return encodeSingle('uint256', num.mul(new BN(2).pow(new BN(size[1]))));
  } else if (type.startsWith('fixed')) {
    const size = parseTypeNxM(type);

    return encodeSingle(
      'int256',
      parseNumber(arg as string).mul(new BN(2).pow(new BN(size[1]))),
    );
  }

  throw new Error(`Unsupported or invalid type: ${JSON.stringify(type)}`);
}

// Is a type dynamic?
/**
 * @param type
 */
function isDynamic(type: string): boolean {
  // FIXME: handle all types? I don't think anything is missing now
  return (
    type === 'string' || type === 'bytes' || parseTypeArray(type) === 'dynamic'
  );
}

// Parse N,M from type<N>x<M>
/**
 * @param type
 */
function parseTypeNxM(type: string): [number, number] {
  const match = /^\D+(\d+)x(\d+)$/u.exec(type);
  if (match === null || match.length < 1) {
    throw new Error(`Invalid parseTypeNxM input "${type}".`);
  }
  return [parseInt(match[1], 10), parseInt(match[2], 10)];
}
