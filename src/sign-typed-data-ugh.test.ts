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

import * as ethUtil from 'ethereumjs-util';
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

/**
 * Validate the given message with the typed message schema.
 *
 * @param typedMessage - The typed message to validate.
 * @returns Whether the message is valid.
 */
function validateTypedMessageSchema(
  typedMessage: Record<string, unknown>,
): boolean {
  const ajv = new Ajv();
  const validate = ajv.compile(TYPED_MESSAGE_SCHEMA);
  return validate(typedMessage);
}


const encodeDataExamples = {
  // dynamic types supported by EIP-712:
  bytes: [10, '10'],
  // bytes: [10, '10', '0x10', Buffer.from('10', 'utf8')],
  // string: [
  //   'Hello!',
  //   '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
  //   '0xabcd',
  //   '😁',
  //   10,
  // ],
  // // atomic types supported by EIP-712:
  // address: [
  //   '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
  //   '0x0',
  //   10,
  //   'bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
  //   Number.MAX_SAFE_INTEGER,
  // ],
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
const allExampleTypes = [...new Set(Object.keys(encodeDataExamples))];
// const allExampleTypes = [
//   ...new Set(
//     Object.keys(encodeDataExamples).concat(
//       Object.keys(encodeDataErrorExamples),
//     ),
//   ),
// ];


describe.only('TypedDataUtils.hashStruct', function () {
  // These tests mirror the `TypedDataUtils.encodeData` tests. The same inputs are expected.
  // See the `encodeData` test comments for more information about these test cases.
  describe.only('V3', function () {
    describe.only('example data', function () {
      for (const type of allExampleTypes) {
        describe.only(`type "${type}"`, function () {
          // Test all examples that do not crash
          const inputs = encodeDataExamples[type] || [];
          for (const input of inputs) {
            const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
            it(`should hash "${input}" (type "${inputType}")`, function () {
              const types = {
                Message: [{ name: 'data', type }],
              };
              const message = { data: input };

              expect(
                TypedDataUtils.hashStruct(
                  'Message',
                  message,
                  types,
                  SignTypedDataVersion.V3,
                ).toString('hex'),
              ).toMatchSnapshot();
            });
          }

          // Test all examples that crash
          // const errorInputs = encodeDataErrorExamples[type] || [];
          // for (const { input, errorMessage } of errorInputs) {
          //   const inputType = input instanceof Buffer ? 'Buffer' : typeof input;
          //   it(`should fail to hash "${input}" (type "${inputType}")`, function () {
          //     const types = {
          //       Message: [{ name: 'data', type }],
          //     };
          //     const message = { data: input };

          //     expect(() =>
          //       TypedDataUtils.hashStruct(
          //         'Message',
          //         message,
          //         types,
          //         SignTypedDataVersion.V3,
          //       ).toString('hex'),
          //     ).toThrow(errorMessage);
          //   });
          // }
        });
      }
    });

  });

});