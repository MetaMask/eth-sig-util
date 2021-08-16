import * as ethUtil from 'ethereumjs-util';
import * as sigUtil from '.';

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

describe('TypedDataUtils.encodeType', () => {
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
});

it('normalize address lower cases', function () {
  const initial = '0xA06599BD35921CfB5B71B4BE3869740385b0B306';
  const result = sigUtil.normalize(initial);
  expect(result).toBe(initial.toLowerCase());
});

it('normalize address adds hex prefix', function () {
  const initial = 'A06599BD35921CfB5B71B4BE3869740385b0B306';
  const result = sigUtil.normalize(initial);
  expect(result).toBe(`0x${initial.toLowerCase()}`);
});

it('normalize an integer converts to byte-pair hex', function () {
  const initial = 1;
  const result = sigUtil.normalize(initial);
  expect(result).toBe('0x01');
});

it('normalize an unsupported type throws', function () {
  const initial = {};
  expect(() => sigUtil.normalize(initial as any)).toThrow(
    'eth-sig-util.normalize() requires hex string or integer input. received object:',
  );
});

it('personalSign and recover', function () {
  const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
  const privKeyHex =
    '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';
  const privKey = Buffer.from(privKeyHex, 'hex');
  const message = 'Hello, world!';
  const msgParams: sigUtil.MsgParams<string> = { data: message };

  const signed = sigUtil.personalSign(privKey, msgParams);
  msgParams.sig = signed;
  const recovered = sigUtil.recoverPersonalSignature(
    msgParams as sigUtil.SignedMsgParams<string>,
  );

  expect(recovered).toBe(address);
});

it('personalSign and extractPublicKey', function () {
  const privKeyHex =
    '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';
  const pubKeyHex =
    '0x9e9e45b2ec5f070b4e26f57c7fedf647afa7a03e894789816fbd12fedc5acd79d0dfeea925688e177caccb8f5e09f0c289bbcfc7adb98d76f5f8c5259478903a';

  const privKey = Buffer.from(privKeyHex, 'hex');
  const message = 'Hello, world!';
  const msgParams: sigUtil.MsgParams<string> = { data: message };

  const signed = sigUtil.personalSign(privKey, msgParams);
  msgParams.sig = signed;
  const publicKey = sigUtil.extractPublicKey(
    msgParams as sigUtil.SignedMsgParams<string>,
  );

  expect(publicKey).toBe(pubKeyHex);
});

it('signTypedData and recoverTypedSignature V1 - single message', function () {
  const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
  const privKeyHex =
    '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

  const privKey = Buffer.from(privKeyHex, 'hex');

  const typedData = [
    {
      type: 'string',
      name: 'message',
      value: 'Hi, Alice!',
    },
  ];

  const msgParams = { data: typedData };

  const signature = sigUtil.signTypedData(privKey, msgParams, 'V1');
  const recovered = sigUtil.recoverTypedSignature(
    {
      data: msgParams.data,
      sig: signature,
    },
    'V1',
  );
  expect(signature).toBe(
    '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b',
  );

  expect(address).toBe(recovered);
});

it('signTypedData and recoverTypedSignature V1 - multiple messages', function () {
  const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
  const privKeyHex =
    '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

  const privKey = Buffer.from(privKeyHex, 'hex');

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

  const msgParams = { data: typedData };

  const signature = sigUtil.signTypedData(privKey, msgParams, 'V1');
  const recovered = sigUtil.recoverTypedSignature(
    {
      data: msgParams.data,
      sig: signature,
    },
    'V1',
  );

  expect(address).toBe(recovered);
});

it('typedSignatureHash - single value', function () {
  const typedData = [
    {
      type: 'string',
      name: 'message',
      value: 'Hi, Alice!',
    },
  ];
  const hash = sigUtil.typedSignatureHash(typedData);
  expect(hash).toBe(
    '0x14b9f24872e28cc49e72dc104d7380d8e0ba84a3fe2e712704bcac66a5702bd5',
  );
});

it('typedSignatureHash - multiple values', function () {
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
  const hash = sigUtil.typedSignatureHash(typedData);
  expect(hash).toBe(
    '0xf7ad23226db5c1c00ca0ca1468fd49c8f8bbc1489bc1c382de5adc557a69c229',
  );
});

it('typedSignatureHash - bytes', function () {
  const typedData = [
    {
      type: 'bytes',
      name: 'message',
      value: '0xdeadbeaf',
    },
  ];
  const hash = sigUtil.typedSignatureHash(typedData);
  expect(hash).toBe(
    '0x6c69d03412450b174def7d1e48b3bcbbbd8f51df2e76e2c5b3a5d951125be3a9',
  );
});

typedSignatureHashThrowsTest({
  argument: [],
  errorMessage: 'Expect argument to be non-empty array',
  testLabel: 'empty array',
});

typedSignatureHashThrowsTest({
  argument: 42,
  errorMessage: 'Expect argument to be non-empty array',
  testLabel: 'not array',
});

typedSignatureHashThrowsTest({
  argument: null,
  errorMessage: "Cannot use 'in' operator to search for 'length' in null",
  testLabel: 'null',
});

typedSignatureHashThrowsTest({
  argument: [
    {
      type: 'jocker',
      name: 'message',
      value: 'Hi, Alice!',
    },
  ],
  errorMessage: 'Unsupported or invalid type: jocker',
  testLabel: 'wrong type',
});

typedSignatureHashThrowsTest({
  argument: [
    {
      name: 'message',
      value: 'Hi, Alice!',
    },
  ],
  errorMessage: "Cannot read property 'startsWith' of undefined",
  testLabel: 'no type',
});

typedSignatureHashThrowsTest({
  argument: [
    {
      type: 'string',
      value: 'Hi, Alice!',
    },
  ],
  errorMessage: 'Expect argument to be non-empty array',
  testLabel: 'no name',
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

function typedSignatureHashThrowsTest({ argument, errorMessage, testLabel }) {
  const label = `typedSignatureHash - malformed arguments - ${testLabel}`;
  it(label, function () {
    expect(() => {
      sigUtil.typedSignatureHash(argument);
    }).toThrow(errorMessage);
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

it('signedTypeData', function () {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
      ],
    },
    primaryType: 'Mail' as const,
    domain: {
      name: 'Ether Mail',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: {
      from: {
        name: 'Cow',
        wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
      },
      to: {
        name: 'Bob',
        wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
      },
      contents: 'Hello, Bob!',
    },
  };

  const utils = sigUtil.TypedDataUtils;
  const privateKey = ethUtil.keccak('cow');
  const address = ethUtil.privateToAddress(privateKey);
  const sig = sigUtil.signTypedData(privateKey, { data: typedData }, 'V3');

  expect(ethUtil.bufferToHex(utils.hashType('Mail', typedData.types))).toBe(
    '0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2',
  );
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V3',
      ),
    ),
  ).toBe('0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('EIP712Domain', typedData.domain, typedData.types, 'V3'),
    ),
  ).toBe('0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f');
  expect(ethUtil.bufferToHex(utils.eip712Hash(typedData, 'V3'))).toBe(
    '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2',
  );
  expect(ethUtil.bufferToHex(address)).toBe(
    '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826',
  );
  expect(sig).toBe(
    '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c',
  );
});

it('signedTypeData with bytes', function () {
  const typedDataWithBytes = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
        { name: 'payload', type: 'bytes' },
      ],
    },
    primaryType: 'Mail' as const,
    domain: {
      name: 'Ether Mail',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: {
      from: {
        name: 'Cow',
        wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
      },
      to: {
        name: 'Bob',
        wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
      },
      contents: 'Hello, Bob!',
      payload:
        '0x25192142931f380985072cdd991e37f65cf8253ba7a0e675b54163a1d133b8ca',
    },
  };
  const utils = sigUtil.TypedDataUtils;
  const privateKey = ethUtil.sha3('cow');
  const address = ethUtil.privateToAddress(privateKey);
  const sig = sigUtil.signTypedData(
    privateKey,
    { data: typedDataWithBytes },
    'V3',
  );

  expect(
    ethUtil.bufferToHex(utils.hashType('Mail', typedDataWithBytes.types)),
  ).toBe('0x43999c52db673245777eb64b0330105de064e52179581a340a9856c32372528e');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        typedDataWithBytes.primaryType,
        typedDataWithBytes.message,
        typedDataWithBytes.types,
        'V3',
      ),
    ),
  ).toBe('0xe004bdc1ca57ba9ad5ea8c81e54dcbdb3bfce2d1d5ad92113f0871fb2a6eb052');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'EIP712Domain',
        typedDataWithBytes.domain,
        typedDataWithBytes.types,
        'V3',
      ),
    ),
  ).toBe('0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f');
  expect(ethUtil.bufferToHex(utils.eip712Hash(typedDataWithBytes, 'V3'))).toBe(
    '0xb4aaf457227fec401db772ec22d2095d1235ee5d0833f56f59108c9ffc90fb4b',
  );
  expect(ethUtil.bufferToHex(address)).toBe(
    '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826',
  );
  expect(sig).toBe(
    '0xdd17ea877a7da411c85ff94bc54180631d0e86efdcd68876aeb2e051417b68e76be6858d67b20baf7be9c6402d49930bfea2535e9ae150e85838ee265094fd081b',
  );
});

it('signedTypeData_v4', function () {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallets', type: 'address[]' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person[]' },
        { name: 'contents', type: 'string' },
      ],
      Group: [
        { name: 'name', type: 'string' },
        { name: 'members', type: 'Person[]' },
      ],
    },
    domain: {
      name: 'Ether Mail',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    primaryType: 'Mail' as const,
    message: {
      from: {
        name: 'Cow',
        wallets: [
          '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
        ],
      },
      to: [
        {
          name: 'Bob',
          wallets: [
            '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
            '0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57',
            '0xB0B0b0b0b0b0B000000000000000000000000000',
          ],
        },
      ],
      contents: 'Hello, Bob!',
    },
  };

  const utils = sigUtil.TypedDataUtils;

  expect(ethUtil.bufferToHex(utils.hashType('Person', typedData.types))).toBe(
    '0xfabfe1ed996349fc6027709802be19d047da1aa5d6894ff5f6486d92db2e6860',
  );

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('Person', typedData.message.from, typedData.types, 'V4'),
    ),
  ).toBe('0x9b4846dd48b866f0ac54d61b9b21a9e746f921cefa4ee94c4c0a1c49c774f67f');

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'Person',
        typedData.message.to[0],
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xefa62530c7ae3a290f8a13a5fc20450bdb3a6af19d9d9d2542b5a94e631a9168');

  expect(ethUtil.bufferToHex(utils.hashType('Mail', typedData.types))).toBe(
    '0x4bd8a9a2b93427bb184aca81e24beb30ffa3c747e2a33d4225ec08bf12e2e753',
  );
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xeb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('EIP712Domain', typedData.domain, typedData.types, 'V4'),
    ),
  ).toBe('0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f');
  expect(ethUtil.bufferToHex(utils.eip712Hash(typedData, 'V4'))).toBe(
    '0xa85c2e2b118698e88db68a8105b794a8cc7cec074e89ef991cb4f5f533819cc2',
  );

  const privateKey = ethUtil.keccak('cow');

  const address = ethUtil.privateToAddress(privateKey);
  expect(ethUtil.bufferToHex(address)).toBe(
    '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826',
  );

  const sig = sigUtil.signTypedData(privateKey, { data: typedData }, 'V4');

  expect(sig).toBe(
    '0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f749061b',
  );
});

it('signedTypeData_v4', function () {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallets', type: 'address[]' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person[]' },
        { name: 'contents', type: 'string' },
      ],
      Group: [
        { name: 'name', type: 'string' },
        { name: 'members', type: 'Person[]' },
      ],
    },
    domain: {
      name: 'Ether Mail',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    primaryType: 'Mail' as const,
    message: {
      from: {
        name: 'Cow',
        wallets: [
          '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
        ],
      },
      to: [
        {
          name: 'Bob',
          wallets: [
            '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
            '0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57',
            '0xB0B0b0b0b0b0B000000000000000000000000000',
          ],
        },
      ],
      contents: 'Hello, Bob!',
    },
  };

  const utils = sigUtil.TypedDataUtils;

  expect(ethUtil.bufferToHex(utils.hashType('Person', typedData.types))).toBe(
    '0xfabfe1ed996349fc6027709802be19d047da1aa5d6894ff5f6486d92db2e6860',
  );

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('Person', typedData.message.from, typedData.types, 'V4'),
    ),
  ).toBe('0x9b4846dd48b866f0ac54d61b9b21a9e746f921cefa4ee94c4c0a1c49c774f67f');

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'Person',
        typedData.message.to[0],
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xefa62530c7ae3a290f8a13a5fc20450bdb3a6af19d9d9d2542b5a94e631a9168');

  expect(ethUtil.bufferToHex(utils.hashType('Mail', typedData.types))).toBe(
    '0x4bd8a9a2b93427bb184aca81e24beb30ffa3c747e2a33d4225ec08bf12e2e753',
  );
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xeb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('EIP712Domain', typedData.domain, typedData.types, 'V4'),
    ),
  ).toBe('0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f');
  expect(ethUtil.bufferToHex(utils.eip712Hash(typedData, 'V4'))).toBe(
    '0xa85c2e2b118698e88db68a8105b794a8cc7cec074e89ef991cb4f5f533819cc2',
  );

  const privateKey = ethUtil.keccak('cow');

  const address = ethUtil.privateToAddress(privateKey);
  expect(ethUtil.bufferToHex(address)).toBe(
    '0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826',
  );

  const sig = sigUtil.signTypedData(privateKey, { data: typedData }, 'V4');

  expect(sig).toBe(
    '0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f749061b',
  );
});

it('signedTypeData_v4 with recursive types', function () {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'mother', type: 'Person' },
        { name: 'father', type: 'Person' },
      ],
    },
    domain: {
      name: 'Family Tree',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    primaryType: 'Person' as const,
    message: {
      name: 'Jon',
      mother: {
        name: 'Lyanna',
        father: {
          name: 'Rickard',
        },
      },
      father: {
        name: 'Rhaegar',
        father: {
          name: 'Aeris II',
        },
      },
    },
  };

  const utils = sigUtil.TypedDataUtils;

  expect(ethUtil.bufferToHex(utils.hashType('Person', typedData.types))).toBe(
    '0x7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
  );

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'Person',
        typedData.message.mother,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0x9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b');

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'Person',
        typedData.message.father,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xb852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8');

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xfdc7b6d35bbd81f7fa78708604f57569a10edff2ca329c8011373f0667821a45');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('EIP712Domain', typedData.domain, typedData.types, 'V4'),
    ),
  ).toBe('0xfacb2c1888f63a780c84c216bd9a81b516fc501a19bae1fc81d82df590bbdc60');
  expect(ethUtil.bufferToHex(utils.eip712Hash(typedData, 'V4'))).toBe(
    '0x807773b9faa9879d4971b43856c4d60c2da15c6f8c062bd9d33afefb756de19c',
  );

  const privateKey = ethUtil.keccak('dragon');

  const address = ethUtil.privateToAddress(privateKey);
  expect(ethUtil.bufferToHex(address)).toBe(
    '0x065a687103c9f6467380bee800ecd70b17f6b72f',
  );

  const sig = sigUtil.signTypedData(privateKey, { data: typedData }, 'V4');

  expect(sig).toBe(
    '0xf2ec61e636ff7bb3ac8bc2a4cc2c8b8f635dd1b2ec8094c963128b358e79c85c5ca6dd637ed7e80f0436fe8fce39c0e5f2082c9517fe677cc2917dcd6c84ba881c',
  );
});

it('signedTypeMessage V4 with recursive types', function () {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'mother', type: 'Person' },
        { name: 'father', type: 'Person' },
      ],
    },
    domain: {
      name: 'Family Tree',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    primaryType: 'Person' as const,
    message: {
      name: 'Jon',
      mother: {
        name: 'Lyanna',
        father: {
          name: 'Rickard',
        },
      },
      father: {
        name: 'Rhaegar',
        father: {
          name: 'Aeris II',
        },
      },
    },
  };

  const utils = sigUtil.TypedDataUtils;

  expect(ethUtil.bufferToHex(utils.hashType('Person', typedData.types))).toBe(
    '0x7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
  );

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'Person',
        typedData.message.mother,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0x9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b');

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        'Person',
        typedData.message.father,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xb852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8');

  expect(
    ethUtil.bufferToHex(
      utils.hashStruct(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xfdc7b6d35bbd81f7fa78708604f57569a10edff2ca329c8011373f0667821a45');
  expect(
    ethUtil.bufferToHex(
      utils.hashStruct('EIP712Domain', typedData.domain, typedData.types, 'V4'),
    ),
  ).toBe('0xfacb2c1888f63a780c84c216bd9a81b516fc501a19bae1fc81d82df590bbdc60');
  expect(ethUtil.bufferToHex(utils.eip712Hash(typedData, 'V4'))).toBe(
    '0x807773b9faa9879d4971b43856c4d60c2da15c6f8c062bd9d33afefb756de19c',
  );

  const privateKey = ethUtil.keccak('dragon');

  const address = ethUtil.privateToAddress(privateKey);
  expect(ethUtil.bufferToHex(address)).toBe(
    '0x065a687103c9f6467380bee800ecd70b17f6b72f',
  );

  const sig = sigUtil.signTypedData(privateKey, { data: typedData }, 'V4');

  expect(sig).toBe(
    '0xf2ec61e636ff7bb3ac8bc2a4cc2c8b8f635dd1b2ec8094c963128b358e79c85c5ca6dd637ed7e80f0436fe8fce39c0e5f2082c9517fe677cc2917dcd6c84ba881c',
  );
});

it('unbound sign typed data utility functions', function () {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'mother', type: 'Person' },
        { name: 'father', type: 'Person' },
      ],
    },
    domain: {
      name: 'Family Tree',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    primaryType: 'Person' as const,
    message: {
      name: 'Jon',
      mother: {
        name: 'Lyanna',
        father: {
          name: 'Rickard',
        },
      },
      father: {
        name: 'Rhaegar',
        father: {
          name: 'Aeris II',
        },
      },
    },
  };

  const { encodeData, encodeType, hashStruct, hashType, eip712Hash } =
    sigUtil.TypedDataUtils;

  expect(encodeType('Person', typedData.types)).toBe(
    'Person(string name,Person mother,Person father)',
  );

  expect(ethUtil.bufferToHex(hashType('Person', typedData.types))).toBe(
    '0x7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
  );

  expect(
    ethUtil.bufferToHex(
      encodeData('Person', typedData.message.mother, typedData.types, 'V4'),
    ),
  ).toBe(
    `0x${[
      '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
      'afe4142a2b3e7b0503b44951e6030e0e2c5000ef83c61857e2e6003e7aef8570',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '88f14be0dd46a8ec608ccbff6d3923a8b4e95cdfc9648f0db6d92a99a264cb36',
    ].join('')}`,
  );
  expect(
    ethUtil.bufferToHex(
      hashStruct('Person', typedData.message.mother, typedData.types, 'V4'),
    ),
  ).toBe('0x9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b');

  expect(
    ethUtil.bufferToHex(
      encodeData('Person', typedData.message.father, typedData.types, 'V4'),
    ),
  ).toBe(
    `0x${[
      '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
      'b2a7c7faba769181e578a391a6a6811a3e84080c6a3770a0bf8a856dfa79d333',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '02cc7460f2c9ff107904cff671ec6fee57ba3dd7decf999fe9fe056f3fd4d56e',
    ].join('')}`,
  );
  expect(
    ethUtil.bufferToHex(
      hashStruct('Person', typedData.message.father, typedData.types, 'V4'),
    ),
  ).toBe('0xb852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8');

  expect(
    ethUtil.bufferToHex(
      encodeData(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe(
    `0x${[
      '7c5c8e90cb92c8da53b893b24962513be98afcf1b57b00327ae4cc14e3a64116',
      'e8d55aa98b6b411f04dbcf9b23f29247bb0e335a6bc5368220032fdcb9e5927f',
      '9ebcfbf94f349de50bcb1e3aa4f1eb38824457c99914fefda27dcf9f99f6178b',
      'b852e5abfeff916a30cb940c4e24c43cfb5aeb0fa8318bdb10dd2ed15c8c70d8',
    ].join('')}`,
  );
  expect(
    ethUtil.bufferToHex(
      hashStruct(
        typedData.primaryType,
        typedData.message,
        typedData.types,
        'V4',
      ),
    ),
  ).toBe('0xfdc7b6d35bbd81f7fa78708604f57569a10edff2ca329c8011373f0667821a45');
  expect(
    ethUtil.bufferToHex(
      hashStruct('EIP712Domain', typedData.domain, typedData.types, 'V4'),
    ),
  ).toBe('0xfacb2c1888f63a780c84c216bd9a81b516fc501a19bae1fc81d82df590bbdc60');
  expect(ethUtil.bufferToHex(eip712Hash(typedData, 'V4'))).toBe(
    '0x807773b9faa9879d4971b43856c4d60c2da15c6f8c062bd9d33afefb756de19c',
  );
});
