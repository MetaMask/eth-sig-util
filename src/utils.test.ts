import { concatSig, padWithZeroes, normalize } from './utils';

describe('padWithZeroes', function () {
  it('pads a string shorter than the target length with zeroes', function () {
    const input = 'abc';
    expect(padWithZeroes(input, 5)).toBe(`00${input}`);
  });

  it('pads an empty string', function () {
    const input = '';
    expect(padWithZeroes(input, 4)).toBe(`0000`);
  });

  it('returns a string equal to the target length without modifying it', function () {
    const input = 'abc';
    expect(padWithZeroes(input, 3)).toStrictEqual(input);
  });

  it('returns a string longer than the target length without modifying it', function () {
    const input = 'abcd';
    expect(padWithZeroes(input, 3)).toStrictEqual(input);
  });

  it('throws an error if passed an invalid hex string', function () {
    const inputs = ['0xabc', 'xyz', '-'];
    for (const input of inputs) {
      expect(() => padWithZeroes(input, 3)).toThrow(
        new Error(`Expected an unprefixed hex string. Received: ${input}`),
      );
    }
  });

  it('throws an error if passed a negative number', function () {
    expect(() => padWithZeroes('abc', -1)).toThrow(
      new Error('Expected a non-negative integer target length. Received: -1'),
    );
  });
});

describe('concatSig', function () {
  it('should concatenate an extended ECDSA signature', function () {
    expect(
      concatSig(
        Buffer.from('1', 'hex'),
        Buffer.from('1', 'hex'),
        Buffer.from('1', 'hex'),
      ),
    ).toMatchInlineSnapshot(
      `"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"`,
    );
  });

  it('should concatenate an all-zero extended ECDSA signature', function () {
    expect(
      concatSig(
        Buffer.from('0', 'hex'),
        Buffer.from('0', 'hex'),
        Buffer.from('0', 'hex'),
      ),
    ).toMatchInlineSnapshot(
      `"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"`,
    );
  });

  it('should return a hex-prefixed string', function () {
    const signature = concatSig(
      Buffer.from('1', 'hex'),
      Buffer.from('1', 'hex'),
      Buffer.from('1', 'hex'),
    );

    expect(typeof signature).toBe('string');
    expect(signature.slice(0, 2)).toBe('0x');
  });

  it('should encode an impossibly large extended ECDSA signature', function () {
    const largeNumber = Number.MAX_SAFE_INTEGER.toString(16);
    expect(
      concatSig(
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
      ),
    ).toMatchInlineSnapshot(
      `"0x000000000000000000000000000000000000000000000000001fffffffffffff000000000000000000000000000000000000000000000000001fffffffffffff1fffffffffffff"`,
    );
  });

  it('should throw if a portion of the signature is larger than the maximum safe integer', function () {
    const largeNumber = '20000000000000'; // This is Number.MAX_SAFE_INTEGER + 1, in hex
    expect(() =>
      concatSig(
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
      ),
    ).toThrow('Number exceeds 53 bits');
  });
});

describe('normalize', function () {
  it('should normalize an address to lower case', function () {
    const initial = '0xA06599BD35921CfB5B71B4BE3869740385b0B306';
    const result = normalize(initial);
    expect(result).toBe(initial.toLowerCase());
  });

  it('should normalize address without a 0x prefix', function () {
    const initial = 'A06599BD35921CfB5B71B4BE3869740385b0B306';
    const result = normalize(initial);
    expect(result).toBe(`0x${initial.toLowerCase()}`);
  });

  it('should normalize 0 to a byte-pair hex string', function () {
    const initial = 0;
    const result = normalize(initial);
    expect(result).toBe('0x00');
  });

  it('should normalize an integer to a byte-pair hex string', function () {
    const initial = 1;
    const result = normalize(initial);
    expect(result).toBe('0x01');
  });

  // TODO: Add validation to disallow negative integers.
  it('should normalize a negative integer to 0x', function () {
    const initial = -1;
    const result = normalize(initial);
    expect(result).toBe('0x');
  });

  // TODO: Add validation to disallow null.
  it('should return undefined if given null', function () {
    const initial = null;
    expect(normalize(initial as any)).toBeUndefined();
  });

  // TODO: Add validation to disallow undefined.
  it('should return undefined if given undefined', function () {
    const initial = undefined;
    expect(normalize(initial as any)).toBeUndefined();
  });

  it('should throw if given an object', function () {
    const initial = {};
    expect(() => normalize(initial as any)).toThrow(
      'eth-sig-util.normalize() requires hex string or integer input. received object:',
    );
  });

  it('should throw if given a boolean', function () {
    const initial = true;
    expect(() => normalize(initial as any)).toThrow(
      'eth-sig-util.normalize() requires hex string or integer input. received boolean: true',
    );
  });

  it('should throw if given a bigint', function () {
    const initial = BigInt(Number.MAX_SAFE_INTEGER);
    expect(() => normalize(initial as any)).toThrow(
      'eth-sig-util.normalize() requires hex string or integer input. received bigint: 9007199254740991',
    );
  });

  it('should throw if given a symbol', function () {
    const initial = Symbol('test');
    expect(() => normalize(initial as any)).toThrow(
      'Cannot convert a Symbol value to a string',
    );
  });
});
