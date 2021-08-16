import { padWithZeroes } from './utils';

describe('padWithZeroes', function () {
  it('pads a string shorter than the target length with zeroes', function () {
    const input = 'abc';
    expect(padWithZeroes(input, 5)).toStrictEqual(`00${input}`);
  });

  it('pads an empty string', function () {
    const input = '';
    expect(padWithZeroes(input, 4)).toStrictEqual(`0000`);
  });

  it('returns a string longer than or equal to the target length without modifying it', function () {
    const input = 'abc';
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
});
