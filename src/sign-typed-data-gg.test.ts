// Allow using snapshots in this file.
/*
eslint jest/no-restricted-matchers: [
  'error',
  {
    resolves: 'Use `expect(await promise)` instead.',
    toBeFalsy: 'Avoid `toBeFalsy`',
    toBeTruthy: 'Avoid `toBeTruthy`',
  }
]
*/

import * as ethUtil from '@ethereumjs/util';
import Ajv from 'ajv';
import {
  recoverTypedSignature,
  signTypedData,
  TypedDataUtils,
  typedSignatureHash,
  SignTypedDataVersion,
  TYPED_MESSAGE_SCHEMA,
} from './sign-typed-data';

const privateKey = Buffer.from(
  '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0',
  'hex',
);

/**
 * Get a list of all Solidity types supported by EIP-712.
 *
 * @returns A list of all supported Solidity types.
 */
function getEip712SolidityTypes() {
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

const eip712SolidityTypes = getEip712SolidityTypes();


const encodeDataExamples = {
  // dynamic types supported by EIP-712:
  // bytes: [10, '10', '0x10', Buffer.from('10', 'utf8')],
  // string: [
  //   'Hello!',
  //   '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
  //   '0xabcd',
  //   '😁',
  //   10,
  // ],
  // atomic types supported by EIP-712:
  address: [
    // '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    // '0x0',
    // 10,
    'bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    // Number.MAX_SAFE_INTEGER,
  ],
  // bool: [true, false, 'true', 'false', 0, 1, -1, Number.MAX_SAFE_INTEGER],
  // bytes1: [
  //   '0x10',
  //   10,
  //   0,
  //   1,
  //   -1,
  //   Number.MAX_SAFE_INTEGER,
  //   Buffer.from('10', 'utf8'),
  // ],
  // bytes32: [
  //   '0x10',
  //   10,
  //   0,
  //   1,
  //   -1,
  //   Number.MAX_SAFE_INTEGER,
  //   Buffer.from('10', 'utf8'),
  // ],
  // int8: [0, '0', '0x0', 255, -255],
  // int256: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER],
  // uint8: [0, '0', '0x0', 255],
  // uint256: [0, '0', '0x0', Number.MAX_SAFE_INTEGER],
  // // atomic types not supported by EIP-712:
  // int: [0, '0', '0x0', Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER], // interpreted as `int256` by `ethereumjs-abi`
  // uint: [0, '0', '0x0', Number.MAX_SAFE_INTEGER], // interpreted as `uint256` by `ethereumjs-abi`
  // `fixed` and `ufixed` types omitted because their encoding in `ethereumjs-abi` is very broken at the moment.
  // `function` type omitted because it is not supported by `ethereumjs-abi`.
};

const encodeDataErrorExamples = {
  // address: [
  //   {
  //     input: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB0',
  //     errorMessage: 'Supplied uint exceeds width: 160 vs 164',
  //   },
  // ],
  // int8: [{ input: '256', errorMessage: 'Supplied int exceeds width: 8 vs 9' }],
  // uint: [{ input: -1, errorMessage: 'Supplied uint is negative' }],
  // uint8: [{ input: -1, errorMessage: 'Supplied uint is negative' }],
  // uint256: [{ input: -1, errorMessage: 'Supplied uint is negative' }],
  // bytes1: [
  //   { input: 'a', errorMessage: 'Cannot convert string to buffer' },
  //   { input: 'test', errorMessage: 'Cannot convert string to buffer' },
  // ],
  // bytes32: [
  //   { input: 'a', errorMessage: 'Cannot convert string to buffer' },
  //   { input: 'test', errorMessage: 'Cannot convert string to buffer' },
  // ],
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


  // This test suite covers all cases where data should be encoded identically
  // on V3 and V4
  // describe('V3/V4 identical encodings', function () {
  //   describe('example data', function () {
  //     for (const type of allExampleTypes) {
  //       describe(`type "${type}"`, function () {
  //         // Test all examples that do not crash
  //         const inputs = encodeDataExamples[type] || [];
  //         for (const input of inputs) {
  //           const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
  //           it(`should encode "${input}" (type "${inputType}")`, function () {
  //             const types = {
  //               Message: [{ name: 'data', type }],
  //             };
  //             const message = { data: input };

  //             const v3Signature = TypedDataUtils.encodeData(
  //               'Message',
  //               message,
  //               types,
  //               SignTypedDataVersion.V3,
  //             ).toString('hex');
  //             const v4Signature = TypedDataUtils.encodeData(
  //               'Message',
  //               message,
  //               types,
  //               SignTypedDataVersion.V4,
  //             ).toString('hex');

  //             expect(v3Signature).toBe(v4Signature);
  //           });
  //         }
  //       });
  //     }
  //   });
  // });

  describe('V4', function () {
    describe('example data', function () {
      for (const type of allExampleTypes) {
        describe(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            it(`should encode "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              expect(
                TypedDataUtils.encodeData(
                  'Message',
                  message,
                  types,
                  SignTypedDataVersion.V4,
                ).toString('hex'),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          const errorInputs = encodeDataErrorExamples[type] || [];
          for (const { input, errorMessage } of errorInputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            it(`should fail to encode "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              expect(() =>
                TypedDataUtils.encodeData(
                  'Message',
                  message,
                  types,
                  SignTypedDataVersion.V4,
                ).toString('hex'),
              ).toThrow(errorMessage);
            });
          }

          it(`should encode array of all ${type} example data`, function () {
            const types = {
              Message: [{ name: 'data', type: `${type}[]` }],
            };
            const message = { data: inputs };
            expect(
              TypedDataUtils.encodeData(
                'Message',
                message,
                types,
                SignTypedDataVersion.V4,
              ).toString('hex'),
            ).toMatchSnapshot();
          });
        });
      }
    });
  });
});