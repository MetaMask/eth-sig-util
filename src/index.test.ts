import * as ethUtil from 'ethereumjs-util';
import * as sigUtil from '.';

const privateKey = Buffer.from(
  '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0',
  'hex',
);

const encodeDataExamples = {
  // dynamic types supported by EIP-712:
  bytes: [10, '10', '0x10', Buffer.from('10', 'utf8')],
  string: [
    'Hello!',
    '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    '0xabcd',
    '😁',
    10,
  ],
  // atomic types supported by EIP-712:
  address: [
    '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    '0x0',
    10,
    'bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    Number.MAX_SAFE_INTEGER,
  ],
  bool: [true, false, 'true', 'false', 0, 1, -1, Number.MAX_SAFE_INTEGER],
  bytes1: [
    '0x10',
    10,
    0,
    1,
    -1,
    Number.MAX_SAFE_INTEGER,
    Buffer.from('10', 'utf8'),
  ],
  bytes32: [
    '0x10',
    10,
    0,
    1,
    -1,
    Number.MAX_SAFE_INTEGER,
    Buffer.from('10', 'utf8'),
  ],
  int8: [0, '0', '0x0', 255, -255],
  int256: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER],
  uint8: [0, '0', '0x0', 255],
  uint256: [0, '0', '0x0', Number.MAX_SAFE_INTEGER],
  // atomic types not supported by EIP-712:
  int: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER], // interpreted as `int256` by `ethereumjs-abi`
  uint: [0, '0', '0x0', Number.MAX_SAFE_INTEGER], // interpreted as `uint256` by `ethereumjs-abi`
  // `fixed` and `ufixed` types omitted because their encoding in `ethereumjs-abi` is very broken at the moment.
  // `function` type omitted because it is not supported by `ethereumjs-abi`.
};

const encodeDataErrorExamples = {
  address: [
    {
      input: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB0',
      errorMessage: 'Supplied uint exceeds width: 160 vs 164',
    },
  ],
  int8: [{ input: '256', errorMessage: 'Supplied int exceeds width: 8 vs 9' }],
  uint: [{ input: -1, errorMessage: 'Supplied uint is negative' }],
  uint8: [{ input: -1, errorMessage: 'Supplied uint is negative' }],
  uint256: [{ input: -1, errorMessage: 'Supplied uint is negative' }],
  bytes1: [
    { input: 'a', errorMessage: 'Cannot convert string to buffer' },
    { input: 'test', errorMessage: 'Cannot convert string to buffer' },
  ],
  bytes32: [
    { input: 'a', errorMessage: 'Cannot convert string to buffer' },
    { input: 'test', errorMessage: 'Cannot convert string to buffer' },
  ],
};

// Union of all types from both sets of examples
const allExampleTypes = [
  ...new Set(
    Object.keys(encodeDataExamples).concat(
      Object.keys(encodeDataErrorExamples),
    ),
  ),
];

describe('TypedDataUtils.encodeData', function () {
  // The `TypedDataUtils.encodeData` function accepts most Solidity data types, as well as custom
  // data types defined by the types provided. The supported Solidity data types are divided into
  // two types: atomic and dynamic. Atomic types are of a fixed size (e.g. `int8`), whereas dynamic
  // types can vary in size (e.g. strings, bytes). We also test arrays of each of these types.
  //
  // The tests below test all boundary conditions of each Solidity type. These tests are
  // automatically constructed using the example data above ("encodeDataExamples" and
  // "encodeDataErrorExamples"). The behaviour for `null` and `undefined` inputs does vary between
  // atomic, dynamic, and custom types though, so each of these three categories is tested
  // separately with `null` and `undefined` input. Lastly, there are more tests for various other
  // edge cases.
  //
  // The behavior differs between V3 and V4, so each test has been run for each version. We also
  // have a block of tests to verify that signatures that match between V3 and V4 remain identical,
  // and that signatures that differ between V3 and V4 remain different.
  //
  // To make reading and maintaining these tests easier, the order will be the same throughout all
  // 4 of these test suites. Here is a table showing that order, as well as the compatibility of
  // each input type with V3 and V4 `encodeData`. The table also shows whether the signature is
  // identical between versions in the cases where the input can be encoded in both versions.
  //
  // | Input type                                           | V3 | V4 | Matching Signatures |
  // | ---------------------------------------------------- | -- | -- | ------------------- |
  // | Auto-generated tests from the example data           | Y  | Y  | Y                   |
  // | Arrays using the example data                        | N  | Y  |                     |
  // | Custom type                                          | Y  | Y  | Y                   |
  // | Recursive custom type                                | Y  | Y  | N                   |
  // | Custom type array                                    | N  | Y  |                     |
  // | Custom type with extra properties                    | Y  | Y  | Y                   |
  // | Atomic type with `null` input                        | N  | N  |                     |
  // | Atomic type with `undefined` input                   | Y  | N  |                     |
  // | Dynamic type with `null` input                       | Y  | Y  | Y                   |
  // | Dynamic type with `undefined` input                  | Y  | N  |                     |
  // | Custom type with `null` input                        | N  | Y  |                     |
  // | Custom type with `undefined` input                   | Y  | Y  | N                   |
  // | Functions                                            | N  | N  |                     |
  // | Unrecognized primary type                            | N  | N  |                     |
  // | Unrecognized non-primary type                        | N  | N  |                     |
  // | Extra type specified that isn't used by primary type | Y  | Y  | Y                   |
  //
  // Note that these tests should mirror the `TypedDataUtils.hashStruct` tests. The `hashStruct`
  // function just calls `encodeData` and hashes the result.

  describe('V3', function () {
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should encode "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              _expect(
                sigUtil.TypedDataUtils.encodeData(
                  'Message',
                  message,
                  types,
                  'V3',
                ).toString('hex'),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to encode "${input}" (type "${inputType}")`,
              function () {
                const types = {
                  Message: [{ name: 'data', type }],
                };
                const message = { data: input };

                _expect(() =>
                  sigUtil.TypedDataUtils.encodeData(
                    'Message',
                    message,
                    types,
                    'V3',
                  ).toString('hex'),
                ).toThrow(errorMessage);
              },
            );
          }

          _it(
            `should fail to encode array of all ${type} example data`,
            function () {
              const types = {
                Message: [{ name: 'data', type: `${type}[]` }],
              };
              const message = { data: inputs };
              _expect(() =>
                sigUtil.TypedDataUtils.encodeData(
                  'Message',
                  message,
                  types,
                  'V3',
                ).toString('hex'),
              ).toThrow(
                'Arrays are unimplemented in encodeData; use V4 extension',
              );
            },
          );
        });
      }
    });

    it('should encode data with custom type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data with a recursive data type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to encode a custom type array', function () {
      const types = {
        Message: [{ name: 'data', type: 'string[]' }],
      };
      const message = { data: ['1', '2', '3'] };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('Arrays are unimplemented in encodeData; use V4 extension');
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalSignature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const signatureWithExtraProperties = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        messageWithExtraProperties,
        types,
        'V3',
      ).toString('hex');

      expect(originalSignature).toBe(signatureWithExtraProperties);
    });

    it('should throw an error when an atomic property is set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: null,
      };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should encode data with an atomic property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: undefined,
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data with a dynamic property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data with a dynamic property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: undefined,
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when a custom type property is set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        to: null,
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow(`Cannot read property 'name' of null`);
    });

    it('should encode data with a custom type property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: undefined,
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to encode a function', function () {
      const types = {
        Message: [{ name: 'data', type: 'function' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to encode with a missing primary type definition', function () {
      const types = {};
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('No type definition specified: Message');
    });

    it('should throw an error when trying to encode an unrecognized type', function () {
      const types = {
        Message: [{ name: 'data', type: 'foo' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: foo');
    });

    it('should encode data when given extraneous types', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data when called unbound', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };
      const primaryType = 'Message';
      const { hashStruct } = sigUtil.TypedDataUtils;

      expect(
        hashStruct(primaryType, message, types, 'V3').toString('hex'),
      ).toMatchSnapshot();
    });
  });

  describe('V4', function () {
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should encode "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              _expect(
                sigUtil.TypedDataUtils.encodeData(
                  'Message',
                  message,
                  types,
                  'V4',
                ).toString('hex'),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to encode "${input}" (type "${inputType}")`,
              function () {
                const types = {
                  Message: [{ name: 'data', type }],
                };
                const message = { data: input };

                _expect(() =>
                  sigUtil.TypedDataUtils.encodeData(
                    'Message',
                    message,
                    types,
                    'V4',
                  ).toString('hex'),
                ).toThrow(errorMessage);
              },
            );
          }

          _it(`should encode array of all ${type} example data`, function () {
            const types = {
              Message: [{ name: 'data', type: `${type}[]` }],
            };
            const message = { data: inputs };
            _expect(
              sigUtil.TypedDataUtils.encodeData(
                'Message',
                message,
                types,
                'V4',
              ).toString('hex'),
            ).toMatchSnapshot();
          });
        });
      }
    });

    it('should encode data with custom type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data with a recursive data type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data with a custom data type array', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address[]' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person[]' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: [
            '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            '0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          ],
        },
        to: [
          {
            name: 'Bob',
            wallet: ['0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'],
          },
        ],
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalSignature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const signatureWithExtraProperties = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        messageWithExtraProperties,
        types,
        'V4',
      ).toString('hex');

      expect(originalSignature).toBe(signatureWithExtraProperties);
    });

    it('should throw an error when an atomic property is set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: null,
      };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should throw an error when an atomic property is set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: undefined,
      };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('missing value for field length of type int32');
    });

    it('should encode data with a dynamic property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when a dynamic property is set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: undefined,
      };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('missing value for field contents of type string');
    });

    it('should encode data with a custom type property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        to: null,
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data with a custom type property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: undefined,
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to encode a function', function () {
      const types = {
        Message: [{ name: 'data', type: 'function' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to encode with a missing primary type definition', function () {
      const types = {};
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('No type definition specified: Message');
    });

    it('should throw an error when trying to encode an unrecognized type', function () {
      const types = {
        Message: [{ name: 'data', type: 'foo' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: foo');
    });

    it('should encode data when given extraneous types', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };

      expect(
        sigUtil.TypedDataUtils.encodeData(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should encode data when called unbound', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };
      const primaryType = 'Message';
      const { encodeData } = sigUtil.TypedDataUtils;

      expect(
        encodeData(primaryType, message, types, 'V4').toString('hex'),
      ).toMatchSnapshot();
    });
  });

  // This test suite covers all cases where data should be encoded identically
  // on V3 and V4
  describe('V3/V4 identical encodings', function () {
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should encode "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              const v3Signature = sigUtil.TypedDataUtils.encodeData(
                'Message',
                message,
                types,
                'V3',
              ).toString('hex');
              const v4Signature = sigUtil.TypedDataUtils.encodeData(
                'Message',
                message,
                types,
                'V4',
              ).toString('hex');

              _expect(v3Signature).toBe(v4Signature);
            });
          }
        });
      }
    });

    it('should encode data with custom type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const v3Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).toBe(v4Signature);
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalV3Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const originalV4Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const v3signatureWithExtraProperties = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        messageWithExtraProperties,
        types,
        'V3',
      ).toString('hex');
      const v4signatureWithExtraProperties = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        messageWithExtraProperties,
        types,
        'V4',
      ).toString('hex');

      expect(originalV3Signature).toBe(originalV4Signature);
      expect(v3signatureWithExtraProperties).toBe(
        v4signatureWithExtraProperties,
      );
    });

    it('should encode data with a dynamic property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      const v3Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).toBe(v4Signature);
    });

    it('should encode data when given extraneous types', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };

      const v3Signature = sigUtil.TypedDataUtils.encodeData(
        'Message',
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.encodeData(
        'Message',
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).toBe(v4Signature);
    });
  });

  // This test suite covers all cases where data should be encoded differently
  // on V3 and V4
  describe('V3/V4 encoding differences', () => {
    // Recursive data structures are encoded differently because V4 encodes
    // missing custom typed properties as 0 byte32 rather than omitting it,
    // and all recursive data structures must include a missing custom typed
    // property (the recursive one), or they'd be infinitely large or cyclic.
    // And cyclic data structures are not supported.
    it('should encode data with recursive data differently', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      const v3Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).not.toBe(v4Signature);
    });

    // Missing custom type properties are omitted in V3, but encoded as 0 (bytes32) in V4
    it('should encode missing custom type properties differently', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      const v3Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.encodeData(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).not.toBe(v4Signature);
    });
  });
});

describe('TypedDataUtils.hashStruct', function () {
  // These tests mirror the `TypedDataUtils.encodeData` tests. The same inputs are expected.
  // See the `encodeData` test comments for more information about these test cases.
  describe('V3', function () {
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should hash "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              _expect(
                sigUtil.TypedDataUtils.hashStruct(
                  'Message',
                  message,
                  types,
                  'V3',
                ).toString('hex'),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to hash "${input}" (type "${inputType}")`,
              function () {
                const types = {
                  Message: [{ name: 'data', type }],
                };
                const message = { data: input };

                _expect(() =>
                  sigUtil.TypedDataUtils.hashStruct(
                    'Message',
                    message,
                    types,
                    'V3',
                  ).toString('hex'),
                ).toThrow(errorMessage);
              },
            );
          }

          _it(
            `should fail to hash array of all ${type} example data`,
            function () {
              const types = {
                Message: [{ name: 'data', type: `${type}[]` }],
              };
              const message = { data: inputs };
              _expect(() =>
                sigUtil.TypedDataUtils.hashStruct(
                  'Message',
                  message,
                  types,
                  'V3',
                ).toString('hex'),
              ).toThrow(
                'Arrays are unimplemented in encodeData; use V4 extension',
              );
            },
          );
        });
      }
    });

    it('should hash data with custom type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data with a recursive data type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to hash a custom type array', function () {
      const types = {
        Message: [{ name: 'data', type: 'string[]' }],
      };
      const message = { data: ['1', '2', '3'] };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('Arrays are unimplemented in encodeData; use V4 extension');
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalSignature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const signatureWithExtraProperties = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        messageWithExtraProperties,
        types,
        'V3',
      ).toString('hex');

      expect(originalSignature).toBe(signatureWithExtraProperties);
    });

    it('should throw an error when an atomic property is set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: null,
      };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should hash data with an atomic property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: undefined,
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data with a dynamic property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data with a dynamic property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: undefined,
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when a custom type property is set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        to: null,
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow(`Cannot read property 'name' of null`);
    });

    it('should hash data with a custom type property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: undefined,
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to hash a function', function () {
      const types = {
        Message: [{ name: 'data', type: 'function' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to hash with a missing primary type definition', function () {
      const types = {};
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('No type definition specified: Message');
    });

    it('should throw an error when trying to hash an unrecognized type', function () {
      const types = {
        Message: [{ name: 'data', type: 'foo' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: foo');
    });

    it('should hash data when given extraneous types', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V3',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data when called unbound', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };
      const primaryType = 'Message';
      const { hashStruct } = sigUtil.TypedDataUtils;

      expect(
        hashStruct(primaryType, message, types, 'V3').toString('hex'),
      ).toMatchSnapshot();
    });
  });

  describe('V4', function () {
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should hash "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              _expect(
                sigUtil.TypedDataUtils.hashStruct(
                  'Message',
                  message,
                  types,
                  'V4',
                ).toString('hex'),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to hash "${input}" (type "${inputType}")`,
              function () {
                const types = {
                  Message: [{ name: 'data', type }],
                };
                const message = { data: input };

                _expect(() =>
                  sigUtil.TypedDataUtils.hashStruct(
                    'Message',
                    message,
                    types,
                    'V4',
                  ).toString('hex'),
                ).toThrow(errorMessage);
              },
            );
          }

          _it(`should hash array of all ${type} example data`, function () {
            const types = {
              Message: [{ name: 'data', type: `${type}[]` }],
            };
            const message = { data: inputs };
            _expect(
              sigUtil.TypedDataUtils.hashStruct(
                'Message',
                message,
                types,
                'V4',
              ).toString('hex'),
            ).toMatchSnapshot();
          });
        });
      }
    });

    it('should hash data with custom type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data with a recursive data type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data with a custom data type array', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address[]' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person[]' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: [
            '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            '0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          ],
        },
        to: [
          {
            name: 'Bob',
            wallet: ['0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'],
          },
        ],
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalSignature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const signatureWithExtraProperties = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        messageWithExtraProperties,
        types,
        'V4',
      ).toString('hex');

      expect(originalSignature).toBe(signatureWithExtraProperties);
    });

    it('should throw an error when an atomic property is set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: null,
      };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should throw an error when an atomic property is set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: undefined,
      };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('missing value for field length of type int32');
    });

    it('should hash data with a dynamic property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when a dynamic property is set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: undefined,
      };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('missing value for field contents of type string');
    });

    it('should hash data with a custom type property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        to: null,
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data with a custom type property set to undefined', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: undefined,
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          primaryType,
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to hash a function', function () {
      const types = {
        Message: [{ name: 'data', type: 'function' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to hash with a missing primary type definition', function () {
      const types = {};
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('No type definition specified: Message');
    });

    it('should throw an error when trying to hash an unrecognized type', function () {
      const types = {
        Message: [{ name: 'data', type: 'foo' }],
      };
      const message = { data: 'test' };

      expect(() =>
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toThrow('Unsupported or invalid type: foo');
    });

    it('should hash data when given extraneous types', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };

      expect(
        sigUtil.TypedDataUtils.hashStruct(
          'Message',
          message,
          types,
          'V4',
        ).toString('hex'),
      ).toMatchSnapshot();
    });

    it('should hash data when called unbound', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };
      const primaryType = 'Message';
      const { hashStruct } = sigUtil.TypedDataUtils;

      expect(
        hashStruct(primaryType, message, types, 'V4').toString('hex'),
      ).toMatchSnapshot();
    });
  });

  // This test suite covers all cases where data should be encoded identically
  // on V3 and V4
  describe('V3/V4 identical encodings', function () {
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should hash "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              const v3Signature = sigUtil.TypedDataUtils.hashStruct(
                'Message',
                message,
                types,
                'V3',
              ).toString('hex');
              const v4Signature = sigUtil.TypedDataUtils.hashStruct(
                'Message',
                message,
                types,
                'V4',
              ).toString('hex');

              _expect(v3Signature).toBe(v4Signature);
            });
          }
        });
      }
    });

    it('should hash data with custom type', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const v3Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).toBe(v4Signature);
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalV3Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const originalV4Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const v3signatureWithExtraProperties = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        messageWithExtraProperties,
        types,
        'V3',
      ).toString('hex');
      const v4signatureWithExtraProperties = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        messageWithExtraProperties,
        types,
        'V4',
      ).toString('hex');

      expect(originalV3Signature).toBe(originalV4Signature);
      expect(v3signatureWithExtraProperties).toBe(
        v4signatureWithExtraProperties,
      );
    });

    it('should hash data with a dynamic property set to null', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      const v3Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).toBe(v4Signature);
    });

    it('should hash data when given extraneous types', function () {
      const types = {
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };

      const v3Signature = sigUtil.TypedDataUtils.hashStruct(
        'Message',
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.hashStruct(
        'Message',
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).toBe(v4Signature);
    });
  });

  // This test suite covers all cases where data should be encoded differently
  // on V3 and V4
  describe('V3/V4 encoding differences', () => {
    // Recursive data structures are encoded differently because V4 encodes
    // missing custom typed properties as 0 byte32 rather than omitting it,
    // and all recursive data structures must include a missing custom typed
    // property (the recursive one), or they'd be infinitely large or cyclic.
    // And cyclic data structures are not supported.
    it('should hash data with recursive data differently', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      const v3Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).not.toBe(v4Signature);
    });

    // Missing custom type properties are omitted in V3, but encoded as 0 (bytes32) in V4
    it('should hash missing custom type properties differently', function () {
      const types = {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      const v3Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V3',
      ).toString('hex');
      const v4Signature = sigUtil.TypedDataUtils.hashStruct(
        primaryType,
        message,
        types,
        'V4',
      ).toString('hex');

      expect(v3Signature).not.toBe(v4Signature);
    });
  });
});

describe('TypedDataUtils.encodeType', () => {
  // Note that these tests should mirror the `TypedDataUtils.hashType` tests. The `hashType`
  // function just calls `encodeType` and hashes the result.
  it('should encode simple type', () => {
    const types = {
      Person: [{ name: 'name', type: 'string' }],
    };
    const primaryType = 'Person';

    expect(
      sigUtil.TypedDataUtils.encodeType(primaryType, types),
    ).toMatchInlineSnapshot(`"Person(string name)"`);
  });

  it('should encode complex type', () => {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person[]' },
        { name: 'contents', type: 'string' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.encodeType(primaryType, types),
    ).toMatchInlineSnapshot(
      `"Mail(Person from,Person[] to,string contents)Person(string name,address wallet)"`,
    );
  });

  it('should encode recursive type', () => {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
        { name: 'replyTo', type: 'Mail' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.encodeType(primaryType, types),
    ).toMatchInlineSnapshot(
      `"Mail(Person from,Person to,string contents,Mail replyTo)Person(string name,address wallet)"`,
    );
  });

  it('should encode unrecognized non-primary types', () => {
    const types = {
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.encodeType(primaryType, types),
    ).toMatchInlineSnapshot(`"Mail(Person from,Person to,string contents)"`);
  });

  it('should throw if primary type is missing', () => {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
    };
    const primaryType = 'Mail';

    expect(() => sigUtil.TypedDataUtils.encodeType(primaryType, types)).toThrow(
      'No type definition specified: Mail',
    );
  });

  it('should encode type when called unbound', function () {
    const types = {
      Message: [{ name: 'data', type: 'string' }],
    };
    const primaryType = 'Message';
    const { encodeType } = sigUtil.TypedDataUtils;

    expect(encodeType(primaryType, types)).toMatchInlineSnapshot(
      `"Message(string data)"`,
    );
  });
});

describe('TypedDataUtils.hashType', () => {
  // These tests mirror the `TypedDataUtils.encodeType` tests. The same inputs are expected.
  it('should hash simple type', () => {
    const types = {
      Person: [{ name: 'name', type: 'string' }],
    };
    const primaryType = 'Person';

    expect(
      sigUtil.TypedDataUtils.hashType(primaryType, types).toString('hex'),
    ).toMatchInlineSnapshot(
      `"fcbb73369ebb221abfdc626fdec0be9ca48ad89ef757b9a76eb7b31ddd261338"`,
    );
  });

  it('should hash complex type', () => {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person[]' },
        { name: 'contents', type: 'string' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.hashType(primaryType, types).toString('hex'),
    ).toMatchInlineSnapshot(
      `"dd57d9596af52b430ced3d5b52d4e3d5dccfdf3e0572db1dcf526baad311fbd1"`,
    );
  });

  it('should hash recursive type', () => {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
        { name: 'replyTo', type: 'Mail' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.hashType(primaryType, types).toString('hex'),
    ).toMatchInlineSnapshot(
      `"66658e9662034bcd21df657297dab8ba47f0ae05dd8aa253cc935d9aacfd9d10"`,
    );
  });

  it('should hash unrecognized non-primary types', () => {
    const types = {
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.hashType(primaryType, types).toString('hex'),
    ).toMatchInlineSnapshot(
      `"c0aee50a43b64ca632347f993c5a39cbddcae6ae329a7a111357622dc88dc1fb"`,
    );
  });

  it('should throw if primary type is missing', () => {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
    };
    const primaryType = 'Mail';

    expect(() =>
      sigUtil.TypedDataUtils.hashType(primaryType, types).toString('hex'),
    ).toThrow('No type definition specified: Mail');
  });

  it('should hash type when called unbound', function () {
    const types = {
      Message: [{ name: 'data', type: 'string' }],
    };
    const primaryType = 'Message';
    const { hashType } = sigUtil.TypedDataUtils;

    expect(hashType(primaryType, types).toString('hex')).toMatchInlineSnapshot(
      `"cddf41b07426e1a761f3da57e35474ae3deaa5b596306531f651c6dc1321e4fd"`,
    );
  });
});

describe('TypedDataUtils.findTypeDependencies', () => {
  it('should return type dependencies of a simple type', function () {
    const types = {
      Person: [{ name: 'name', type: 'string' }],
    };
    const primaryType = 'Person';

    expect(
      sigUtil.TypedDataUtils.findTypeDependencies(primaryType, types),
    ).toStrictEqual(new Set(['Person']));
  });

  it('should return type dependencies of an array type', function () {
    const types = {
      Person: [{ name: 'name', type: 'string' }],
    };
    const primaryType = 'Person[]';

    expect(
      sigUtil.TypedDataUtils.findTypeDependencies(primaryType, types),
    ).toStrictEqual(new Set(['Person']));
  });

  it('should return type dependencies of a complex type', function () {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person[]' },
        { name: 'contents', type: 'string' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.findTypeDependencies(primaryType, types),
    ).toStrictEqual(new Set(['Mail', 'Person']));
  });

  it('should return type dependencies of a recursive type', function () {
    const types = {
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person[]' },
        { name: 'contents', type: 'string' },
        { name: 'replyTo', type: 'Mail' },
      ],
    };
    const primaryType = 'Mail';

    expect(
      sigUtil.TypedDataUtils.findTypeDependencies(primaryType, types),
    ).toStrictEqual(new Set(['Mail', 'Person']));
  });

  it('should return empty set if primary type is missing', function () {
    const primaryType = 'Person';

    expect(
      sigUtil.TypedDataUtils.findTypeDependencies(primaryType, {}),
    ).toStrictEqual(new Set());
  });

  it('should return type dependencies when called unbound', function () {
    const types = {
      Person: [{ name: 'name', type: 'string' }],
    };
    const primaryType = 'Person';
    const { findTypeDependencies } = sigUtil.TypedDataUtils;

    expect(findTypeDependencies(primaryType, types)).toStrictEqual(
      new Set(['Person']),
    );
  });
});

describe('TypedDataUtils.sanitizeData', function () {
  it('should return correctly formatted data unchanged', function () {
    const typedMessage = {
      domain: {},
      message: {},
      primaryType: 'Person' as const,
      types: {
        EIP712Domain: [{ name: 'name', type: 'string' }],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
      },
    };

    const sanitizedTypedMessage =
      sigUtil.TypedDataUtils.sanitizeData(typedMessage);

    expect(sanitizedTypedMessage).toStrictEqual(typedMessage);
  });

  it("should add `EIP712Domain` to `types` if it's missing", function () {
    const typedMessage = {
      domain: {},
      message: {},
      primaryType: 'Person' as const,
      types: {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
      },
    };

    const sanitizedTypedMessage = sigUtil.TypedDataUtils.sanitizeData(
      typedMessage as any,
    );

    expect(sanitizedTypedMessage).toStrictEqual({
      ...typedMessage,
      types: { ...typedMessage.types, EIP712Domain: [] },
    });
  });

  it('should sanitize empty object', function () {
    const typedMessage = {};

    const sanitizedTypedMessage = sigUtil.TypedDataUtils.sanitizeData(
      typedMessage as any,
    );

    expect(sanitizedTypedMessage).toStrictEqual({});
  });

  it('should omit unrecognized properties', function () {
    const expectedMessage = {
      domain: {},
      message: {},
      primaryType: 'Person' as const,
      types: {
        EIP712Domain: [{ name: 'name', type: 'string' }],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
      },
    };
    const typedMessage = { ...expectedMessage, extraStuff: 'Extra stuff' };

    const sanitizedTypedMessage =
      sigUtil.TypedDataUtils.sanitizeData(typedMessage);

    expect(sanitizedTypedMessage).toStrictEqual(expectedMessage);
  });

  it('should sanitize data when called unbound', function () {
    const typedMessage = {
      domain: {},
      message: {},
      primaryType: 'Person' as const,
      types: {
        EIP712Domain: [{ name: 'name', type: 'string' }],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
      },
    };
    const { sanitizeData } = sigUtil.TypedDataUtils;

    const sanitizedTypedMessage = sanitizeData(typedMessage);

    expect(sanitizedTypedMessage).toStrictEqual(typedMessage);
  });
});

describe('TypedDataUtils.eip712Hash', function () {
  describe('V3', function () {
    it('should hash a minimal valid typed message', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        // This represents the most basic "typed message" that is valid according to our types.
        // It's not a very useful message (it's totally empty), but it's complete according to the
        // spec.
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V3',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('minimal typed message hash should be identical to minimal valid typed message hash', function () {
      const minimalHash = sigUtil.TypedDataUtils.eip712Hash(
        // This tests that when the mandatory fields `domain`, `message`, and `types.EIP712Domain`
        // are omitted, the result is the same as if they were included but empty.
        {
          types: {},
          primaryType: 'EIP712Domain',
        } as any,
        'V3',
      );
      const minimalValidHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V3',
      );

      expect(minimalHash.toString('hex')).toBe(
        minimalValidHash.toString('hex'),
      );
    });

    it('should ignore extra top-level properties', function () {
      const minimalValidHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V3',
      );
      const extraPropertiesHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
          extra: 'stuff',
          moreExtra: 1,
        } as any,
        'V3',
      );

      expect(minimalValidHash.toString('hex')).toBe(
        extraPropertiesHash.toString('hex'),
      );
    });

    it('should hash a typed message with a domain separator that uses all fields', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {},
        },
        'V3',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should hash a typed message with extra domain seperator fields', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
              {
                name: 'extraField',
                type: 'string',
              },
            ],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
            extraField: 'stuff',
          },
          message: {},
        } as any,
        'V3',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should hash a typed message with only custom domain seperator fields', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'customName',
                type: 'string',
              },
              {
                name: 'customVersion',
                type: 'string',
              },
              {
                name: 'customChainId',
                type: 'uint256',
              },
              {
                name: 'customVerifyingContract',
                type: 'address',
              },
              {
                name: 'customSalt',
                type: 'bytes32',
              },
              {
                name: 'extraField',
                type: 'string',
              },
            ],
          },
          primaryType: 'EIP712Domain',
          domain: {
            customName: 'example.metamask.io',
            customVersion: '1',
            customChainId: 1,
            customVerifyingContract:
              '0x0000000000000000000000000000000000000000',
            customSalt: Buffer.from(new Int32Array([1, 2, 3])),
            extraField: 'stuff',
          },
          message: {},
        } as any,
        'V3',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should hash a typed message with data', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
            Message: [{ name: 'data', type: 'string' }],
          },
          primaryType: 'Message',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {
            data: 'Hello!',
          },
        },
        'V3',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should ignore message if the primary type is EIP712Domain', function () {
      const hashWithMessage = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
            Message: [{ name: 'data', type: 'string' }],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {
            data: 'Hello!',
          },
        },
        'V3',
      );
      const hashWithoutMessage = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
            Message: [{ name: 'data', type: 'string' }],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {},
        },
        'V3',
      );

      expect(hashWithMessage.toString('hex')).toBe(
        hashWithoutMessage.toString('hex'),
      );
    });

    it('should hash a minimal valid typed message when called unbound', function () {
      const { eip712Hash } = sigUtil.TypedDataUtils;

      const hash = eip712Hash(
        // This represents the most basic "typed message" that is valid according to our types.
        // It's not a very useful message (it's totally empty), but it's complete according to the
        // spec.
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V3',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });
  });

  describe('V4', function () {
    it('should hash a minimal valid typed message', function () {
      // This represents the most basic "typed message" that is valid according to our types.
      // It's not a very useful message (it's totally empty), but it's complete according to the
      // spec.
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V4',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('minimal typed message hash should be identical to minimal valid typed message hash', function () {
      // This tests that when the mandatory fields `domain`, `message`, and `types.EIP712Domain`
      // are omitted, the result is the same as if they were included but empty.
      const minimalHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {},
          primaryType: 'EIP712Domain',
        } as any,
        'V4',
      );
      const minimalValidHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V4',
      );

      expect(minimalHash.toString('hex')).toBe(
        minimalValidHash.toString('hex'),
      );
    });

    it('should ignore extra top-level properties', function () {
      const minimalValidHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V4',
      );
      const extraPropertiesHash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
          extra: 'stuff',
          moreExtra: 1,
        } as any,
        'V4',
      );

      expect(minimalValidHash.toString('hex')).toBe(
        extraPropertiesHash.toString('hex'),
      );
    });

    it('should hash a typed message with a domain separator that uses all fields.', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {},
        },
        'V4',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should hash a typed message with extra domain seperator fields', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
              {
                name: 'extraField',
                type: 'string',
              },
            ],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
            extraField: 'stuff',
          },
          message: {},
        } as any,
        'V4',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should hash a typed message with only custom domain seperator fields', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'customName',
                type: 'string',
              },
              {
                name: 'customVersion',
                type: 'string',
              },
              {
                name: 'customChainId',
                type: 'uint256',
              },
              {
                name: 'customVerifyingContract',
                type: 'address',
              },
              {
                name: 'customSalt',
                type: 'bytes32',
              },
              {
                name: 'extraField',
                type: 'string',
              },
            ],
          },
          primaryType: 'EIP712Domain',
          domain: {
            customName: 'example.metamask.io',
            customVersion: '1',
            customChainId: 1,
            customVerifyingContract:
              '0x0000000000000000000000000000000000000000',
            customSalt: Buffer.from(new Int32Array([1, 2, 3])),
            extraField: 'stuff',
          },
          message: {},
        } as any,
        'V4',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should hash a typed message with data', function () {
      const hash = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
            Message: [{ name: 'data', type: 'string' }],
          },
          primaryType: 'Message',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {
            data: 'Hello!',
          },
        },
        'V4',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });

    it('should ignore message if the primary type is EIP712Domain', function () {
      const hashWithMessage = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
            Message: [{ name: 'data', type: 'string' }],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {
            data: 'Hello!',
          },
        },
        'V4',
      );
      const hashWithoutMessage = sigUtil.TypedDataUtils.eip712Hash(
        {
          types: {
            EIP712Domain: [
              {
                name: 'name',
                type: 'string',
              },
              {
                name: 'version',
                type: 'string',
              },
              {
                name: 'chainId',
                type: 'uint256',
              },
              {
                name: 'verifyingContract',
                type: 'address',
              },
              {
                name: 'salt',
                type: 'bytes32',
              },
            ],
            Message: [{ name: 'data', type: 'string' }],
          },
          primaryType: 'EIP712Domain',
          domain: {
            name: 'example.metamask.io',
            version: '1',
            chainId: 1,
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: Buffer.from(new Int32Array([1, 2, 3])),
          },
          message: {},
        },
        'V4',
      );

      expect(hashWithMessage.toString('hex')).toBe(
        hashWithoutMessage.toString('hex'),
      );
    });

    it('should hash a minimal valid typed message when called unbound', function () {
      const { eip712Hash } = sigUtil.TypedDataUtils;

      // This represents the most basic "typed message" that is valid according to our types.
      // It's not a very useful message (it's totally empty), but it's complete according to the
      // spec.
      const hash = eip712Hash(
        {
          types: {
            EIP712Domain: [],
          },
          primaryType: 'EIP712Domain',
          domain: {},
          message: {},
        },
        'V4',
      );

      expect(hash.toString('hex')).toMatchSnapshot();
    });
  });
});

describe('concatSig', function () {
  it('should concatenate an extended ECDSA signature', function () {
    expect(
      sigUtil.concatSig(
        Buffer.from('1', 'hex'),
        Buffer.from('1', 'hex'),
        Buffer.from('1', 'hex'),
      ),
    ).toMatchSnapshot();
  });

  it('should concatenate an all-zero extended ECDSA signature', function () {
    expect(
      sigUtil.concatSig(
        Buffer.from('0', 'hex'),
        Buffer.from('0', 'hex'),
        Buffer.from('0', 'hex'),
      ),
    ).toMatchSnapshot();
  });

  it('should return a hex-prefixed string', function () {
    const signature = sigUtil.concatSig(
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
      sigUtil.concatSig(
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
      ),
    ).toMatchSnapshot();
  });

  it('should throw if a portion of the signature is larger than the maximum safe integer', function () {
    const largeNumber = '20000000000000'; // This is Number.MAX_SAFE_INTEGER + 1, in hex
    expect(() =>
      sigUtil.concatSig(
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
        Buffer.from(largeNumber, 'hex'),
      ),
    ).toThrow('Number can only safely store up to 53 bits');
  });
});

describe('normalize', function () {
  it('should normalize an address to lower case', function () {
    const initial = '0xA06599BD35921CfB5B71B4BE3869740385b0B306';
    const result = sigUtil.normalize(initial);
    expect(result).toBe(initial.toLowerCase());
  });

  it('should normalize address without a 0x prefix', function () {
    const initial = 'A06599BD35921CfB5B71B4BE3869740385b0B306';
    const result = sigUtil.normalize(initial);
    expect(result).toBe(`0x${initial.toLowerCase()}`);
  });

  it('should normalize an integer to a byte-pair hex string', function () {
    const initial = 1;
    const result = sigUtil.normalize(initial);
    expect(result).toBe('0x01');
  });

  // TODO: Add validation to disallow negative integers.
  it('should normalize a negative integer to 0x', function () {
    const initial = -1;
    const result = sigUtil.normalize(initial);
    expect(result).toBe('0x');
  });

  // TODO: Add validation to disallow null.
  it('should return undefined if given null', function () {
    const initial = null;
    expect(sigUtil.normalize(initial as any)).toBeUndefined();
  });

  // TODO: Add validation to disallow undefined.
  it('should return undefined if given undefined', function () {
    const initial = undefined;
    expect(sigUtil.normalize(initial as any)).toBeUndefined();
  });

  it('should throw if given an object', function () {
    const initial = {};
    expect(() => sigUtil.normalize(initial as any)).toThrow(
      'eth-sig-util.normalize() requires hex string or integer input. received object:',
    );
  });

  it('should throw if given a boolean', function () {
    const initial = true;
    expect(() => sigUtil.normalize(initial as any)).toThrow(
      'eth-sig-util.normalize() requires hex string or integer input. received boolean: true',
    );
  });

  it('should throw if given a bigint', function () {
    const initial = BigInt(Number.MAX_SAFE_INTEGER);
    expect(() => sigUtil.normalize(initial as any)).toThrow(
      'eth-sig-util.normalize() requires hex string or integer input. received bigint: 9007199254740991',
    );
  });

  it('should throw if given a symbol', function () {
    const initial = Symbol('test');
    expect(() => sigUtil.normalize(initial as any)).toThrow(
      'Cannot convert a Symbol value to a string',
    );
  });
});

describe('personalSign', function () {
  // This is a signature of the message "Hello, world!" that was created using the private key in
  // the top-level `privateKey` variable.
  const helloWorldSignature =
    '0x90a938f7457df6e8f741264c32697fc52f9a8f867c52dd70713d9d2d472f2e415d9c94148991bbe1f4a1818d1dff09165782749c877f5cf1eff4ef126e55714d1c';
  const helloWorldMessage = 'Hello, world!';

  it('should sign a message', function () {
    expect(sigUtil.personalSign(privateKey, { data: helloWorldMessage })).toBe(
      helloWorldSignature,
    );
  });

  it('should recover the address from a signature', function () {
    const address = ethUtil.addHexPrefix(
      ethUtil.privateToAddress(privateKey).toString('hex'),
    );

    expect(
      sigUtil.recoverPersonalSignature({
        data: helloWorldMessage,
        sig: helloWorldSignature,
      }),
    ).toBe(address);
  });

  it('should recover the public key from a signature', function () {
    const publicKey = ethUtil.addHexPrefix(
      ethUtil.privateToPublic(privateKey).toString('hex'),
    );

    expect(
      sigUtil.extractPublicKey({
        data: helloWorldMessage,
        sig: helloWorldSignature,
      }),
    ).toBe(publicKey);
  });

  it('should sign a message and recover the address of the signer', function () {
    const address = ethUtil.addHexPrefix(
      ethUtil.privateToAddress(privateKey).toString('hex'),
    );
    const signature = sigUtil.personalSign(privateKey, {
      data: helloWorldMessage,
    });

    expect(
      sigUtil.recoverPersonalSignature({
        data: helloWorldMessage,
        sig: signature,
      }),
    ).toBe(address);
  });

  it('should sign a message and recover the public key of the signer', function () {
    const publicKey = ethUtil.addHexPrefix(
      ethUtil.privateToPublic(privateKey).toString('hex'),
    );
    const signature = sigUtil.personalSign(privateKey, {
      data: helloWorldMessage,
    });

    expect(
      sigUtil.extractPublicKey({
        data: helloWorldMessage,
        sig: signature,
      }),
    ).toBe(publicKey);
  });
});

// Comments starting with "V1:" highlight differences relative to V3 and 4.
const signTypedDataV1Examples = {
  // dynamic types supported by EIP-712:
  bytes: [10, '10', '0x10', Buffer.from('10', 'utf8')],
  string: [
    'Hello!',
    '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    '0xabcd',
    '😁',
  ],
  // atomic types supported by EIP-712:
  address: [
    '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    // V1: No apparent maximum address length
    '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbBbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    '0x0',
    10,
    Number.MAX_SAFE_INTEGER,
  ],
  bool: [true, false, 'true', 'false', 0, 1, -1, Number.MAX_SAFE_INTEGER],
  bytes1: [
    '0x10',
    10,
    0,
    1,
    -1,
    Number.MAX_SAFE_INTEGER,
    Buffer.from('10', 'utf8'),
  ],
  bytes32: [
    '0x10',
    10,
    0,
    1,
    -1,
    Number.MAX_SAFE_INTEGER,
    Buffer.from('10', 'utf8'),
  ],
  int8: [0, '0', '0x0', 255, -255],
  int256: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER],
  uint8: [0, '0', '0x0', 255, -255],
  uint256: [
    0,
    '0',
    '0x0',
    Number.MAX_SAFE_INTEGER,
    // V1: Negative unsigned integers
    Number.MIN_SAFE_INTEGER,
  ],
  // atomic types not supported by EIP-712:
  int: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER], // interpreted as `int256` by `ethereumjs-abi`
  uint: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER], // interpreted as `uint256` by `ethereumjs-abi`
  // `fixed` and `ufixed` types omitted because their encoding in `ethereumjs-abi` is very broken at the moment.
  // `function` type omitted because it is not supported by `ethereumjs-abi`.
};

const signTypedDataV1ErrorExamples = {
  string: [
    {
      // V1: Does not accept numbers as strings (arguably correctly).
      input: 10,
      errorMessage:
        'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received type number (10)',
    },
  ],
  address: [
    {
      // V1: Unprefixed addresses are not accepted.
      input: 'bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
      errorMessage:
        'Cannot convert string to buffer. toBuffer only supports 0x-prefixed hex strings and this string was given:',
    },
  ],
  int8: [{ input: '256', errorMessage: 'Supplied int exceeds width: 8 vs 9' }],
  bytes1: [
    { input: 'a', errorMessage: 'Cannot convert string to buffer' },
    { input: 'test', errorMessage: 'Cannot convert string to buffer' },
  ],
  bytes32: [
    { input: 'a', errorMessage: 'Cannot convert string to buffer' },
    { input: 'test', errorMessage: 'Cannot convert string to buffer' },
  ],
};

// Union of all types from both sets of examples
const allSignTypedDataV1ExampleTypes = [
  ...new Set(
    Object.keys(encodeDataExamples).concat(
      Object.keys(encodeDataErrorExamples),
    ),
  ),
];

describe('signTypedData', function () {
  describe('V1', function () {
    it('should throw when given an empty array', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [],
          },
          'V1',
        ),
      ).toThrow('Expect argument to be non-empty array');
    });

    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified
      // variables from the outer scope" which can be dangerous to reference in
      // a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allSignTypedDataV1ExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = signTypedDataV1Examples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should sign "${input}" (type "${inputType}")`, function () {
              _expect(
                sigUtil.signTypedData(
                  privateKey,
                  {
                    data: [{ name: 'data', type, value: input }],
                  },
                  'V1',
                ),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = signTypedDataV1ErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to sign "${input}" (type "${inputType}")`,
              function () {
                _expect(() =>
                  sigUtil.signTypedData(
                    privateKey,
                    {
                      data: [{ name: 'data', type, value: input }],
                    },
                    'V1',
                  ),
                ).toThrow(errorMessage);
              },
            );
          }

          if (type === 'bytes') {
            _it(
              `should fail to sign array of all ${type} example data`,
              function () {
                _expect(() =>
                  sigUtil.signTypedData(
                    privateKey,
                    {
                      data: [
                        { name: 'data', type: `${type}[]`, value: inputs },
                      ],
                    },
                    'V1',
                  ),
                ).toThrow(
                  'The "list[0]" argument must be an instance of Buffer or Uint8Array. Received type number (10)',
                );
              },
            );
          } else {
            _it(`should sign array of all ${type} example data`, function () {
              _expect(
                sigUtil.signTypedData(
                  privateKey,
                  {
                    data: [{ name: 'data', type: `${type}[]`, value: inputs }],
                  },
                  'V1',
                ),
              ).toMatchSnapshot();
            });
          }
        });
      }
    });

    it('should throw an error when an atomic property is set to null', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [{ name: 'data', type: 'int32', value: null }],
          },
          'V1',
        ),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should sign data with an atomic property set to undefined', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [{ name: 'data', type: 'int32', value: undefined }],
          },
          'V1',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a dynamic property set to null', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [{ name: 'data', type: 'string', value: null }],
          },
          'V1',
        ),
      ).toThrow(
        'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received null',
      );
    });

    it('should sign data with a dynamic property set to undefined', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [{ name: 'data', type: 'string', value: undefined }],
          },
          'V1',
        ),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to sign a function', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [
              {
                name: 'data',
                type: 'function',
                value: () => console.log(test),
              },
            ],
          },
          'V1',
        ),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to sign an unrecognized type', function () {
      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: [{ name: 'data', type: 'foo', value: 'test' }],
          },
          'V1',
        ),
      ).toThrow('Unsupported or invalid type: foo');
    });
  });

  describe('V3', function () {
    // This first group of tests mirrors the `TypedDataUtils.eip712Hash` tests, because all of
    // those test cases are relevant here as well.

    it('should sign a minimal valid typed message', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        // This represents the most basic "typed message" that is valid according to our types.
        // It's not a very useful message (it's totally empty), but it's complete according to the
        // spec.
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
          },
        },
        'V3',
      );

      expect(signature).toMatchSnapshot();
    });

    it('minimal typed message signature should be identical to minimal valid typed message signature', function () {
      const minimalSignature = sigUtil.signTypedData(
        privateKey,
        // This tests that when the mandatory fields `domain`, `message`, and `types.EIP712Domain`
        // are omitted, the result is the same as if they were included but empty.
        {
          data: {
            types: {},
            primaryType: 'EIP712Domain',
          },
        } as any,
        'V3',
      );
      const minimalValidSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
          },
        },
        'V3',
      );

      expect(minimalSignature).toBe(minimalValidSignature);
    });

    it('should ignore extra data properties', function () {
      const minimalValidSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
          },
        },
        'V3',
      );
      const extraPropertiesSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
            extra: 'stuff',
            moreExtra: 1,
          },
        } as any,
        'V3',
      );

      expect(minimalValidSignature).toBe(extraPropertiesSignature);
    });

    it('should sign a typed message with a domain separator that uses all fields', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'name',
                  type: 'string',
                },
                {
                  name: 'version',
                  type: 'string',
                },
                {
                  name: 'chainId',
                  type: 'uint256',
                },
                {
                  name: 'verifyingContract',
                  type: 'address',
                },
                {
                  name: 'salt',
                  type: 'bytes32',
                },
              ],
            },
            primaryType: 'EIP712Domain',
            domain: {
              name: 'example.metamask.io',
              version: '1',
              chainId: 1,
              verifyingContract: '0x0000000000000000000000000000000000000000',
              salt: Buffer.from(new Int32Array([1, 2, 3])),
            },
            message: {},
          },
        },
        'V3',
      );

      expect(signature).toMatchSnapshot();
    });

    it('should sign a typed message with extra domain seperator fields', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'name',
                  type: 'string',
                },
                {
                  name: 'version',
                  type: 'string',
                },
                {
                  name: 'chainId',
                  type: 'uint256',
                },
                {
                  name: 'verifyingContract',
                  type: 'address',
                },
                {
                  name: 'salt',
                  type: 'bytes32',
                },
                {
                  name: 'extraField',
                  type: 'string',
                },
              ],
            },
            primaryType: 'EIP712Domain',
            domain: {
              name: 'example.metamask.io',
              version: '1',
              chainId: 1,
              verifyingContract: '0x0000000000000000000000000000000000000000',
              salt: Buffer.from(new Int32Array([1, 2, 3])),
              extraField: 'stuff',
            },
            message: {},
          },
        } as any,
        'V3',
      );

      expect(signature).toMatchSnapshot();
    });

    it('should sign a typed message with only custom domain seperator fields', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'customName',
                  type: 'string',
                },
                {
                  name: 'customVersion',
                  type: 'string',
                },
                {
                  name: 'customChainId',
                  type: 'uint256',
                },
                {
                  name: 'customVerifyingContract',
                  type: 'address',
                },
                {
                  name: 'customSalt',
                  type: 'bytes32',
                },
                {
                  name: 'extraField',
                  type: 'string',
                },
              ],
            },
            primaryType: 'EIP712Domain',
            domain: {
              customName: 'example.metamask.io',
              customVersion: '1',
              customChainId: 1,
              customVerifyingContract:
                '0x0000000000000000000000000000000000000000',
              customSalt: Buffer.from(new Int32Array([1, 2, 3])),
              extraField: 'stuff',
            },
            message: {},
          },
        } as any,
        'V3',
      );

      expect(signature).toMatchSnapshot();
    });

    it('should sign a typed message with data', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'name',
                  type: 'string',
                },
                {
                  name: 'version',
                  type: 'string',
                },
                {
                  name: 'chainId',
                  type: 'uint256',
                },
                {
                  name: 'verifyingContract',
                  type: 'address',
                },
                {
                  name: 'salt',
                  type: 'bytes32',
                },
              ],
              Message: [{ name: 'data', type: 'string' }],
            },
            primaryType: 'Message',
            domain: {
              name: 'example.metamask.io',
              version: '1',
              chainId: 1,
              verifyingContract: '0x0000000000000000000000000000000000000000',
              salt: Buffer.from(new Int32Array([1, 2, 3])),
            },
            message: {
              data: 'Hello!',
            },
          },
        },
        'V3',
      );

      expect(signature).toMatchSnapshot();
    });

    // This second group of tests mirrors the `TypedDataUtils.encodeData` tests, because all of
    // those test cases are relevant here as well.

    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should sign "${input}" (type "${inputType}")`, function () {
              _expect(
                sigUtil.signTypedData(
                  privateKey,
                  {
                    data: {
                      types: {
                        EIP712Domain: [],
                        Message: [{ name: 'data', type }],
                      },
                      primaryType: 'Message',
                      domain: {},
                      message: {
                        data: input,
                      },
                    },
                  },
                  'V3',
                ),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to sign "${input}" (type "${inputType}")`,
              function () {
                _expect(() =>
                  sigUtil.signTypedData(
                    privateKey,
                    {
                      data: {
                        types: {
                          EIP712Domain: [],
                          Message: [{ name: 'data', type }],
                        },
                        primaryType: 'Message',
                        domain: {},
                        message: {
                          data: input,
                        },
                      },
                    },
                    'V3',
                  ),
                ).toThrow(errorMessage);
              },
            );
          }

          _it(
            `should fail to sign array of all ${type} example data`,
            function () {
              _expect(() =>
                sigUtil.signTypedData(
                  privateKey,
                  {
                    data: {
                      types: {
                        EIP712Domain: [],
                        Message: [{ name: 'data', type: `${type}[]` }],
                      },
                      primaryType: 'Message',
                      domain: {},
                      message: {
                        data: inputs,
                      },
                    },
                  },
                  'V3',
                ),
              ).toThrow(
                'Arrays are unimplemented in encodeData; use V4 extension',
              );
            },
          );
        });
      }
    });

    it('should sign data with custom type', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a recursive data type', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to sign a custom type array', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string[]' }],
      };
      const message = { data: ['1', '2', '3'] };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toThrow('Arrays are unimplemented in encodeData; use V4 extension');
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types,
            primaryType,
            domain: {},
            message,
          },
        },
        'V3',
      );
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const signatureWithExtraProperties = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types,
            primaryType,
            domain: {},
            message: messageWithExtraProperties,
          },
        },
        'V3',
      );

      expect(originalSignature).toBe(signatureWithExtraProperties);
    });

    it('should throw an error when an atomic property is set to null', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: null,
      };

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should sign data with an atomic property set to undefined', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: undefined,
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a dynamic property set to null', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a dynamic property set to undefined', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: undefined,
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });

    it('should throw an error when a custom type property is set to null', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        to: null,
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toThrow(`Cannot read property 'name' of null`);
    });

    it('should sign data with a custom type property set to undefined', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: undefined,
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to sign a function', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'function' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to sign with a missing primary type definition', function () {
      const types = {
        EIP712Domain: [],
      };
      const message = { data: 'test' };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            } as any,
          },
          'V3',
        ),
      ).toThrow('No type definition specified: Message');
    });

    it('should throw an error when trying to sign an unrecognized type', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'foo' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toThrow('Unsupported or invalid type: foo');
    });

    it('should sign data when given extraneous types', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };
      const primaryType = 'Message';

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V3',
        ),
      ).toMatchSnapshot();
    });
  });

  describe('V4', function () {
    // This first group of tests mirrors the `TypedDataUtils.eip712Hash` tests, because all of
    // those test cases are relevant here as well.

    it('should sign a minimal valid typed message', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        // This represents the most basic "typed message" that is valid according to our types.
        // It's not a very useful message (it's totally empty), but it's complete according to the
        // spec.
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
          },
        },
        'V4',
      );

      expect(signature).toMatchSnapshot();
    });

    it('minimal typed message signature should be identical to minimal valid typed message signature', function () {
      const minimalSignature = sigUtil.signTypedData(
        privateKey,
        // This tests that when the mandatory fields `domain`, `message`, and `types.EIP712Domain`
        // are omitted, the result is the same as if they were included but empty.
        {
          data: {
            types: {},
            primaryType: 'EIP712Domain',
          },
        } as any,
        'V4',
      );
      const minimalValidSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
          },
        },
        'V4',
      );

      expect(minimalSignature).toBe(minimalValidSignature);
    });

    it('should ignore extra data properties', function () {
      const minimalValidSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
          },
        },
        'V4',
      );
      const extraPropertiesSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [],
            },
            primaryType: 'EIP712Domain',
            domain: {},
            message: {},
            extra: 'stuff',
            moreExtra: 1,
          },
        } as any,
        'V4',
      );

      expect(minimalValidSignature).toBe(extraPropertiesSignature);
    });

    it('should sign a typed message with a domain separator that uses all fields', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'name',
                  type: 'string',
                },
                {
                  name: 'version',
                  type: 'string',
                },
                {
                  name: 'chainId',
                  type: 'uint256',
                },
                {
                  name: 'verifyingContract',
                  type: 'address',
                },
                {
                  name: 'salt',
                  type: 'bytes32',
                },
              ],
            },
            primaryType: 'EIP712Domain',
            domain: {
              name: 'example.metamask.io',
              version: '1',
              chainId: 1,
              verifyingContract: '0x0000000000000000000000000000000000000000',
              salt: Buffer.from(new Int32Array([1, 2, 3])),
            },
            message: {},
          },
        },
        'V4',
      );

      expect(signature).toMatchSnapshot();
    });

    it('should sign a typed message with extra domain seperator fields', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'name',
                  type: 'string',
                },
                {
                  name: 'version',
                  type: 'string',
                },
                {
                  name: 'chainId',
                  type: 'uint256',
                },
                {
                  name: 'verifyingContract',
                  type: 'address',
                },
                {
                  name: 'salt',
                  type: 'bytes32',
                },
                {
                  name: 'extraField',
                  type: 'string',
                },
              ],
            },
            primaryType: 'EIP712Domain',
            domain: {
              name: 'example.metamask.io',
              version: '1',
              chainId: 1,
              verifyingContract: '0x0000000000000000000000000000000000000000',
              salt: Buffer.from(new Int32Array([1, 2, 3])),
              extraField: 'stuff',
            },
            message: {},
          },
        } as any,
        'V4',
      );

      expect(signature).toMatchSnapshot();
    });

    it('should sign a typed message with only custom domain seperator fields', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'customName',
                  type: 'string',
                },
                {
                  name: 'customVersion',
                  type: 'string',
                },
                {
                  name: 'customChainId',
                  type: 'uint256',
                },
                {
                  name: 'customVerifyingContract',
                  type: 'address',
                },
                {
                  name: 'customSalt',
                  type: 'bytes32',
                },
                {
                  name: 'extraField',
                  type: 'string',
                },
              ],
            },
            primaryType: 'EIP712Domain',
            domain: {
              customName: 'example.metamask.io',
              customVersion: '1',
              customChainId: 1,
              customVerifyingContract:
                '0x0000000000000000000000000000000000000000',
              customSalt: Buffer.from(new Int32Array([1, 2, 3])),
              extraField: 'stuff',
            },
            message: {},
          },
        } as any,
        'V4',
      );

      expect(signature).toMatchSnapshot();
    });

    it('should sign a typed message with data', function () {
      const signature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types: {
              EIP712Domain: [
                {
                  name: 'name',
                  type: 'string',
                },
                {
                  name: 'version',
                  type: 'string',
                },
                {
                  name: 'chainId',
                  type: 'uint256',
                },
                {
                  name: 'verifyingContract',
                  type: 'address',
                },
                {
                  name: 'salt',
                  type: 'bytes32',
                },
              ],
              Message: [{ name: 'data', type: 'string' }],
            },
            primaryType: 'Message',
            domain: {
              name: 'example.metamask.io',
              version: '1',
              chainId: 1,
              verifyingContract: '0x0000000000000000000000000000000000000000',
              salt: Buffer.from(new Int32Array([1, 2, 3])),
            },
            message: {
              data: 'Hello!',
            },
          },
        },
        'V4',
      );

      expect(signature).toMatchSnapshot();
    });

    // This second group of tests mirrors the `TypedDataUtils.encodeData` tests, because all of
    // those test cases are relevant here as well.
    describe('example data', function () {
      // Reassigned to silence "no-loop-func" ESLint rule
      // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
      // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
      const _expect = expect;
      const _it = it;

      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(`should sign "${input}" (type "${inputType}")`, function () {
              const types = {
                EIP712Domain: [],
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };
              const primaryType = 'Message';

              _expect(
                sigUtil.signTypedData(
                  privateKey,
                  {
                    data: {
                      types,
                      primaryType,
                      domain: {},
                      message,
                    },
                  },
                  'V4',
                ),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            _it(
              `should fail to sign "${input}" (type "${inputType}")`,
              function () {
                const types = {
                  EIP712Domain: [],
                  Message: [{ name: 'data', type }],
                };
                const message = { data: input };
                const primaryType = 'Message';

                _expect(() =>
                  sigUtil.signTypedData(
                    privateKey,
                    {
                      data: {
                        types,
                        primaryType,
                        domain: {},
                        message,
                      },
                    },
                    'V4',
                  ),
                ).toThrow(errorMessage);
              },
            );
          }

          _it(`should sign array of all ${type} example data`, function () {
            const types = {
              EIP712Domain: [],
              Message: [{ name: 'data', type: `${type}[]` }],
            };
            const message = { data: inputs };
            const primaryType = 'Message';
            _expect(
              sigUtil.signTypedData(
                privateKey,
                {
                  data: {
                    types,
                    primaryType,
                    domain: {},
                    message,
                  },
                },
                'V4',
              ),
            ).toMatchSnapshot();
          });
        });
      }
    });

    it('should sign data with custom type', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a recursive data type', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello!',
        },
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a custom data type array', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address[]' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person[]' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: [
            '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            '0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          ],
        },
        to: [
          {
            name: 'Bob',
            wallet: ['0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'],
          },
        ],
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });

    it('should ignore extra unspecified message properties', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
      };

      const originalSignature = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types,
            primaryType,
            domain: {},
            message,
          },
        },
        'V4',
      );
      const messageWithExtraProperties = { ...message, foo: 'bar' };
      const signatureWithExtraProperties = sigUtil.signTypedData(
        privateKey,
        {
          data: {
            types,
            primaryType,
            domain: {},
            message: messageWithExtraProperties,
          },
        },
        'V4',
      );

      expect(originalSignature).toBe(signatureWithExtraProperties);
    });

    it('should throw an error when an atomic property is set to null', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: null,
      };

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toThrow(`Cannot read property 'toArray' of null`);
    });

    it('should throw an error when an atomic property is set to undefined', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'length', type: 'int32' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello!',
        length: undefined,
      };

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toThrow('missing value for field length of type int32');
    });

    it('should sign data with a dynamic property set to null', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: null,
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });

    it('should throw an error when a dynamic property is set to undefined', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: undefined,
      };

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toThrow('missing value for field contents of type string');
    });

    it('should sign data with a custom type property set to null', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        to: null,
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });

    it('should sign data with a custom type property set to undefined', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      };
      const primaryType = 'Mail';
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: undefined,
        contents: 'Hello, Bob!',
      };

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });

    it('should throw an error when trying to encode a function', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'function' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toThrow('Unsupported or invalid type: function');
    });

    it('should throw an error when trying to sign with a missing primary type definition', function () {
      const types = {
        EIP712Domain: [],
      };
      const message = { data: 'test' };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            } as any,
          },
          'V4',
        ),
      ).toThrow('No type definition specified: Message');
    });

    it('should throw an error when trying to sign an unrecognized type', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'foo' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message';

      expect(() =>
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toThrow('Unsupported or invalid type: foo');
    });

    it('should sign data when given extraneous types', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'Hello!' };
      const primaryType = 'Message';

      expect(
        sigUtil.signTypedData(
          privateKey,
          {
            data: {
              types,
              primaryType,
              domain: {},
              message,
            },
          },
          'V4',
        ),
      ).toMatchSnapshot();
    });
  });
});

describe('recoverTypedSignature', function () {
  describe('V1', function () {
    // This is a signature of the message "[{ name: 'message', type: 'string', value: 'Hi, Alice!' }]"
    // that was created using the private key in the top-level `privateKey` variable.
    const exampleSignature =
      '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b';

    it('should recover the address of the signer', function () {
      const address = ethUtil.addHexPrefix(
        ethUtil.privateToAddress(privateKey).toString('hex'),
      );

      expect(
        sigUtil.recoverTypedSignature(
          {
            data: [{ name: 'message', type: 'string', value: 'Hi, Alice!' }],
            sig: exampleSignature,
          },
          'V1',
        ),
      ).toBe(address);
    });

    it('should sign typed data and recover the address of the signer', function () {
      const address = ethUtil.addHexPrefix(
        ethUtil.privateToAddress(privateKey).toString('hex'),
      );
      const message = [
        { name: 'message', type: 'string', value: 'Hi, Alice!' },
      ];
      const signature = sigUtil.signTypedData(
        privateKey,
        { data: message },
        'V1',
      );

      expect(
        sigUtil.recoverTypedSignature(
          {
            data: message,
            sig: signature,
          },
          'V1',
        ),
      ).toBe(address);
    });
  });

  describe('V3', function () {
    // This is a signature of the message in the test below that was created using the private key
    // in the top-level `privateKey` variable.
    const exampleSignature =
      '0xf6cda8eaf5137e8cc15d48d03a002b0512446e2a7acbc576c01cfbe40ad9345663ccda8884520d98dece9a8bfe38102851bdae7f69b3d8612b9808e6337801601b';

    it('should recover the address of the signer', function () {
      const address = ethUtil.addHexPrefix(
        ethUtil.privateToAddress(privateKey).toString('hex'),
      );
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message' as const;
      const typedMessage = {
        types,
        primaryType,
        domain: {},
        message,
      };

      expect(
        sigUtil.recoverTypedSignature(
          {
            data: typedMessage,
            sig: exampleSignature,
          },
          'V3',
        ),
      ).toBe(address);
    });

    it('should sign typed data and recover the address of the signer', function () {
      const address = ethUtil.addHexPrefix(
        ethUtil.privateToAddress(privateKey).toString('hex'),
      );
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message' as const;
      const typedMessage = {
        types,
        primaryType,
        domain: {},
        message,
      };
      const signature = sigUtil.signTypedData(
        privateKey,
        { data: typedMessage },
        'V3',
      );

      expect(
        sigUtil.recoverTypedSignature(
          {
            data: typedMessage,
            sig: signature,
          },
          'V3',
        ),
      ).toBe(address);
    });
  });

  describe('V4', function () {
    // This is a signature of the message in the test below that was created using the private key
    // in the top-level `privateKey` variable.
    const exampleSignature =
      '0xf6cda8eaf5137e8cc15d48d03a002b0512446e2a7acbc576c01cfbe40ad9345663ccda8884520d98dece9a8bfe38102851bdae7f69b3d8612b9808e6337801601b';

    it('should recover the address of the signer', function () {
      const address = ethUtil.addHexPrefix(
        ethUtil.privateToAddress(privateKey).toString('hex'),
      );
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message' as const;
      const typedMessage = {
        types,
        primaryType,
        domain: {},
        message,
      };

      expect(
        sigUtil.recoverTypedSignature(
          {
            data: typedMessage,
            sig: exampleSignature,
          },
          'V4',
        ),
      ).toBe(address);
    });

    it('should sign typed data and recover the address of the signer', function () {
      const address = ethUtil.addHexPrefix(
        ethUtil.privateToAddress(privateKey).toString('hex'),
      );
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const message = { data: 'test' };
      const primaryType = 'Message' as const;
      const typedMessage = {
        types,
        primaryType,
        domain: {},
        message,
      };
      const signature = sigUtil.signTypedData(
        privateKey,
        { data: typedMessage },
        'V4',
      );

      expect(
        sigUtil.recoverTypedSignature(
          {
            data: typedMessage,
            sig: signature,
          },
          'V4',
        ),
      ).toBe(address);
    });
  });
});

describe('typedSignatureHash', function () {
  // Reassigned to silence "no-loop-func" ESLint rule
  // It was complaining because it saw that `it` and `expect` as "modified variables from the outer scope"
  // which can be dangerous to reference in a loop. But they aren't modified in this case, just invoked.
  const _expect = expect;
  const _it = it;

  for (const type of allSignTypedDataV1ExampleTypes) {
    describe(`type "${type}"`, function () {
      // Test all examples that do not crash
      const inputs = signTypedDataV1Examples[type] || [];
      for (const input of inputs) {
        const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
        _it(`should hash "${input}" (type "${inputType}")`, function () {
          const typedData = [{ type, name: 'message', value: input }];

          _expect(sigUtil.typedSignatureHash(typedData)).toMatchSnapshot();
        });
      }

      const errorInputs = signTypedDataV1ErrorExamples[type] || [];
      for (const { input, errorMessage } of errorInputs) {
        const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
        _it(
          `should fail to hash "${input}" (type "${inputType}")`,
          function () {
            const typedData = [{ type, name: 'message', value: input }];

            _expect(() => sigUtil.typedSignatureHash(typedData)).toThrow(
              errorMessage,
            );
          },
        );
      }
    });
  }

  const invalidTypedMessages = [
    {
      input: [],
      errorMessage: 'Expect argument to be non-empty array',
      label: 'an empty array',
    },
    {
      input: 42,
      errorMessage: 'Expect argument to be non-empty array',
      label: 'a number',
    },
    {
      input: null,
      errorMessage: "Cannot use 'in' operator to search for 'length' in null",
      label: 'null',
    },
    {
      input: undefined,
      errorMessage: 'Expect argument to be non-empty array',
      label: 'undefined',
    },
    {
      input: [
        {
          type: 'jocker',
          name: 'message',
          value: 'Hi, Alice!',
        },
      ],
      errorMessage: 'Unsupported or invalid type: jocker',
      label: 'an unrecognized type',
    },
    {
      input: [
        {
          name: 'message',
          value: 'Hi, Alice!',
        },
      ],
      errorMessage: "Cannot read property 'startsWith' of undefined",
      label: 'no type',
    },
    {
      input: [
        {
          type: 'string',
          value: 'Hi, Alice!',
        },
      ],
      errorMessage: 'Expect argument to be non-empty array',
      label: 'no name',
    },
  ];

  for (const { input, errorMessage, label } of invalidTypedMessages) {
    _it(`should throw when given ${label}`, function () {
      _expect(() => sigUtil.typedSignatureHash(input as any)).toThrow(
        errorMessage,
      );
    });
  }

  it('should hash a message with multiple entries', function () {
    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
      {
        type: 'uint8',
        name: 'value',
        value: 10,
      },
    ];

    expect(sigUtil.typedSignatureHash(typedData)).toMatchInlineSnapshot(
      `"0xf7ad23226db5c1c00ca0ca1468fd49c8f8bbc1489bc1c382de5adc557a69c229"`,
    );
  });
});

// personal_sign was declared without an explicit set of test data
// so I made a script out of geth's internals to create this test data
// https://gist.github.com/kumavis/461d2c0e9a04ea0818e423bb77e3d260

signatureTest({
  testLabel: 'personalSign - kumavis fml manual test I',
  // "hello world"
  message: '0x68656c6c6f20776f726c64',
  signature:
    '0xce909e8ea6851bc36c007a0072d0524b07a3ff8d4e623aca4c71ca8e57250c4d0a3fc38fa8fbaaa81ead4b9f6bd03356b6f8bf18bccad167d78891636e1d69561b',
  addressHex: '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb',
  privateKey: Buffer.from(
    '6969696969696969696969696969696969696969696969696969696969696969',
    'hex',
  ),
});

signatureTest({
  testLabel: 'personalSign - kumavis fml manual test II',
  // some random binary message from parity's test
  message: '0x0cc175b9c0f1b6a831c399e26977266192eb5ffee6ae2fec3ad71c777531578f',
  signature:
    '0x9ff8350cc7354b80740a3580d0e0fd4f1f02062040bc06b893d70906f8728bb5163837fd376bf77ce03b55e9bd092b32af60e86abce48f7b8d3539988ee5a9be1c',
  addressHex: '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb',
  privateKey: Buffer.from(
    '6969696969696969696969696969696969696969696969696969696969696969',
    'hex',
  ),
});

signatureTest({
  testLabel: 'personalSign - kumavis fml manual test III',
  // random binary message data and pk from parity's test
  // https://github.com/ethcore/parity/blob/5369a129ae276d38f3490abb18c5093b338246e0/rpc/src/v1/tests/mocked/eth.rs#L301-L317
  // note: their signature result is incorrect (last byte moved to front) due to a parity bug
  message: '0x0cc175b9c0f1b6a831c399e26977266192eb5ffee6ae2fec3ad71c777531578f',
  signature:
    '0xa2870db1d0c26ef93c7b72d2a0830fa6b841e0593f7186bc6c7cc317af8cf3a42fda03bd589a49949aa05db83300cdb553116274518dbe9d90c65d0213f4af491b',
  addressHex: '0xe0da1edcea030875cd0f199d96eb70f6ab78faf2',
  privateKey: Buffer.from(
    '4545454545454545454545454545454545454545454545454545454545454545',
    'hex',
  ),
});

function signatureTest(opts) {
  it(opts.testLabel, function () {
    const address = opts.addressHex;
    const privKey = opts.privateKey;
    const { message } = opts;
    const msgParams: sigUtil.MsgParams<string> = { data: message };

    const signed = sigUtil.personalSign(privKey, msgParams);
    expect(signed).toBe(opts.signature);

    msgParams.sig = signed;
    const recovered = sigUtil.recoverPersonalSignature(
      msgParams as sigUtil.SignedMsgParams<string>,
    );

    expect(recovered).toBe(address);
  });
}

const bob = {
  ethereumPrivateKey:
    '7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816',
  encryptionPrivateKey: 'flN07C7w2Rdhpucv349qxmVRm/322gojKc8NgEUUuBY=',
  encryptionPublicKey: 'C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=',
};

const secretMessage = { data: 'My name is Satoshi Buterin' };

const encryptedData = {
  version: 'x25519-xsalsa20-poly1305',
  nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
  ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
  ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
};

it("Getting bob's encryptionPublicKey", async function () {
  const result = await sigUtil.getEncryptionPublicKey(bob.ethereumPrivateKey);
  expect(result).toBe(bob.encryptionPublicKey);
});

// encryption test
it("Alice encrypts message with bob's encryptionPublicKey", async function () {
  const result = await sigUtil.encrypt(
    bob.encryptionPublicKey,
    secretMessage,
    'x25519-xsalsa20-poly1305',
  );

  expect(result.ciphertext).toHaveLength(56);
  expect(result.ephemPublicKey).toHaveLength(44);
  expect(result.nonce).toHaveLength(32);
  expect(result.version).toBe('x25519-xsalsa20-poly1305');
});

// safe encryption test
it("Alice encryptsSafely message with bob's encryptionPublicKey", async function () {
  const VERSION = 'x25519-xsalsa20-poly1305';
  const result = await sigUtil.encryptSafely(
    bob.encryptionPublicKey,
    secretMessage,
    VERSION,
  );

  expect(result.ciphertext).toHaveLength(2732);
  expect(result.ephemPublicKey).toHaveLength(44);
  expect(result.nonce).toHaveLength(32);
  expect(result.version).toBe('x25519-xsalsa20-poly1305');
});

// safe decryption test
it('Bob decryptSafely message that Alice encryptSafely for him', async function () {
  const VERSION = 'x25519-xsalsa20-poly1305';
  const result = await sigUtil.encryptSafely(
    bob.encryptionPublicKey,
    secretMessage,
    VERSION,
  );

  const plaintext = sigUtil.decryptSafely(result, bob.ethereumPrivateKey);
  expect(plaintext).toBe(secretMessage.data);
});

// decryption test
it('Bob decrypts message that Alice sent to him', function () {
  const result = sigUtil.decrypt(encryptedData, bob.ethereumPrivateKey);
  expect(result).toBe(secretMessage.data);
});

it('Decryption failed because version is wrong or missing', function () {
  const badVersionData = {
    version: 'x256k1-aes256cbc',
    nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
    ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
    ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
  };

  expect(() => sigUtil.decrypt(badVersionData, bob.ethereumPrivateKey)).toThrow(
    'Encryption type/version not supported.',
  );
});

it('Decryption failed because nonce is wrong or missing', function () {
  // encrypted data
  const badNonceData = {
    version: 'x25519-xsalsa20-poly1305',
    nonce: '',
    ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
    ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
  };

  expect(() => sigUtil.decrypt(badNonceData, bob.ethereumPrivateKey)).toThrow(
    'bad nonce size',
  );
});

it('Decryption failed because ephemPublicKey is wrong or missing', function () {
  // encrypted data
  const badEphemData = {
    version: 'x25519-xsalsa20-poly1305',
    nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
    ephemPublicKey: 'FFFF/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
    ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
  };

  expect(() => sigUtil.decrypt(badEphemData, bob.ethereumPrivateKey)).toThrow(
    'Decryption failed.',
  );
});

it('Decryption failed because cyphertext is wrong or missing', function () {
  // encrypted data
  const badEphemData = {
    version: 'x25519-xsalsa20-poly1305',
    nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
    ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
    ciphertext: 'ffffff/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
  };

  expect(() => sigUtil.decrypt(badEphemData, bob.ethereumPrivateKey)).toThrow(
    'Decryption failed.',
  );
});
