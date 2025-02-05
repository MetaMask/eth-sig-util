import { bufferToHex, privateToAddress } from '@ethereumjs/util';

import {
  signEIP7702Authorization,
  recoverEIP7702Authorization,
  EIP7702Authorization,
  hashEIP7702Authorization,
} from './sign-eip7702-authorization';

const TEST_PRIVATE_KEY = Buffer.from(
  '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0',
  'hex',
);

const TEST_ADDRESS = bufferToHex(privateToAddress(TEST_PRIVATE_KEY));

const TEST_AUTHORIZATION: EIP7702Authorization = [
  8545,
  '0x1234567890123456789012345678901234567890',
  1,
];

const EXPECTED_AUTHORIZATION_HASH = Buffer.from(
  'b847dee5b33802280f3279d57574e1eb6bf5d628d7f63049e3cb20bad211056c',
  'hex',
);

const EXPECTED_SIGNATURE =
  '0xebea1ac12f17a56a514dfecbcbc8bbee7b089fa3fcee31680d1e2c1588f623df7973cab74e12536678995377da38c96c65c52897750b73462c6760ef2737dba41b';

describe('signAuthorization', () => {
  describe('signEIP7702Authorization()', () => {
    it('should produce the correct signature', () => {
      const signature = signEIP7702Authorization({
        privateKey: TEST_PRIVATE_KEY,
        authorization: TEST_AUTHORIZATION,
      });

      expect(signature).toBe(EXPECTED_SIGNATURE);
    });

    it('should throw if private key is null', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: null as any,
          authorization: TEST_AUTHORIZATION,
        }),
      ).toThrow('Missing privateKey parameter');
    });

    it('should throw if private key is undefined', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: undefined as any,
          authorization: TEST_AUTHORIZATION,
        }),
      ).toThrow('Missing privateKey parameter');
    });

    it('should throw if authorization is null', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: null as any,
        }),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if authorization is undefined', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: undefined as any,
        }),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if chainId is null', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            null as unknown as number,
            TEST_AUTHORIZATION[1],
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Missing chainId parameter');
    });

    it('should throw if chainId is not a number', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            '123' as any as number,
            TEST_AUTHORIZATION[1],
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow(
        'Invalid chainId: must be a non-negative number less than 2^256',
      );
    });

    it('should throw if chainId is too large', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            2 ** 257,
            TEST_AUTHORIZATION[1],
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow(
        'Invalid chainId: must be a non-negative number less than 2^256',
      );
    });

    it('should throw if chainId is negative', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [-1, TEST_AUTHORIZATION[1], TEST_AUTHORIZATION[2]],
        }),
      ).toThrow(
        'Invalid chainId: must be a non-negative number less than 2^256',
      );
    });

    it('should throw if nonce is null', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            TEST_AUTHORIZATION[1],
            null as unknown as number,
          ],
        }),
      ).toThrow('Missing nonce parameter');
    });

    it('should throw if nonce is not a number', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            TEST_AUTHORIZATION[1],
            '123' as any as number,
          ],
        }),
      ).toThrow('Invalid nonce: must be a non-negative number less than 2^64');
    });

    it('should throw if nonce is negative', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [TEST_AUTHORIZATION[0], TEST_AUTHORIZATION[1], -123],
        }),
      ).toThrow('Invalid nonce: must be a non-negative number less than 2^64');
    });

    it('should throw if nonce is too large', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            TEST_AUTHORIZATION[1],
            2 ** 65,
          ],
        }),
      ).toThrow('Invalid nonce: must be a non-negative number less than 2^64');
    });

    it('should throw if contractAddress is null', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            null as unknown as string,
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Missing contractAddress parameter');
    });

    it('should throw if contractAddress is not a string', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            123 as any as string,
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Invalid contractAddress: must be a 20 byte hex string');
    });

    it('should throw if contractAddress is too short', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            TEST_AUTHORIZATION[1].slice(10),
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Invalid contractAddress: must be a 20 byte hex string');
    });

    it('should throw if contractAddress is too long', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            `${TEST_AUTHORIZATION[1]}00`,
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Invalid contractAddress: must be a 20 byte hex string');
    });

    it('should throw if contractAddress is not valid hex', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            '0xghijklmnopqrstuvwxyghijklmnopqrstuvwxyghij',
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Invalid contractAddress: must be a 20 byte hex string');
    });

    it('should throw if contractAddress is missing the 0x prefix', () => {
      expect(() =>
        signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization: [
            TEST_AUTHORIZATION[0],
            TEST_AUTHORIZATION[1].slice(2),
            TEST_AUTHORIZATION[2],
          ],
        }),
      ).toThrow('Invalid contractAddress: must be a 20 byte hex string');
    });
  });

  describe('hashEIP7702Authorization()', () => {
    it('should produce the correct hash', () => {
      const hash = hashEIP7702Authorization(TEST_AUTHORIZATION);

      expect(hash).toStrictEqual(EXPECTED_AUTHORIZATION_HASH);
    });

    it('should throw if authorization is null', () => {
      expect(() =>
        hashEIP7702Authorization(null as unknown as EIP7702Authorization),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if authorization is undefined', () => {
      expect(() =>
        hashEIP7702Authorization(undefined as unknown as EIP7702Authorization),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if chainId is null', () => {
      expect(() =>
        hashEIP7702Authorization([
          null as unknown as number,
          TEST_AUTHORIZATION[1],
          TEST_AUTHORIZATION[2],
        ]),
      ).toThrow('Missing chainId parameter');
    });

    it('should throw if contractAddress is null', () => {
      expect(() =>
        hashEIP7702Authorization([
          TEST_AUTHORIZATION[0],
          null as unknown as string,
          TEST_AUTHORIZATION[2],
        ]),
      ).toThrow('Missing contractAddress parameter');
    });

    it('should throw if nonce is null', () => {
      expect(() =>
        hashEIP7702Authorization([
          TEST_AUTHORIZATION[0],
          TEST_AUTHORIZATION[1],
          null as unknown as number,
        ]),
      ).toThrow('Missing nonce parameter');
    });
  });

  describe('recoverEIP7702Authorization()', () => {
    it('should recover the address from a signature', () => {
      const recoveredAddress = recoverEIP7702Authorization({
        authorization: TEST_AUTHORIZATION,
        signature: EXPECTED_SIGNATURE,
      });

      expect(recoveredAddress).toBe(TEST_ADDRESS);
    });

    it('should throw if signature is null', () => {
      expect(() =>
        recoverEIP7702Authorization({
          signature: null as unknown as string,
          authorization: TEST_AUTHORIZATION,
        }),
      ).toThrow('Missing signature parameter');
    });

    it('should throw if signature is undefined', () => {
      expect(() =>
        recoverEIP7702Authorization({
          signature: undefined as unknown as string,
          authorization: TEST_AUTHORIZATION,
        }),
      ).toThrow('Missing signature parameter');
    });

    it('should throw if authorization is null', () => {
      expect(() =>
        recoverEIP7702Authorization({
          signature: EXPECTED_SIGNATURE,
          authorization: null as unknown as EIP7702Authorization,
        }),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if authorization is undefined', () => {
      expect(() =>
        recoverEIP7702Authorization({
          signature: EXPECTED_SIGNATURE,
          authorization: undefined as unknown as EIP7702Authorization,
        }),
      ).toThrow('Missing authorization parameter');
    });
  });

  describe('sign-and-recover', () => {
    const testCases = {
      zeroChainId: [0, '0x1234567890123456789012345678901234567890', 1],
      highChainId: [98765, '0x1234567890123456789012345678901234567890', 1],
      zeroNonce: [8545, '0x1234567890123456789012345678901234567890', 0],
      highNonce: [8545, '0x1234567890123456789012345678901234567890', 98765],
      zeroContractAddress: [1, '0x0000000000000000000000000000000000000000', 1],
      allZeroValues: [0, '0x0000000000000000000000000000000000000000', 0],
    } as { [key: string]: EIP7702Authorization };

    it.each(Object.entries(testCases))(
      'should sign and recover %s',
      (_, authorization) => {
        const signature = signEIP7702Authorization({
          privateKey: TEST_PRIVATE_KEY,
          authorization,
        });

        const recoveredAddress = recoverEIP7702Authorization({
          authorization,
          signature,
        });

        expect(recoveredAddress).toBe(TEST_ADDRESS);
      },
    );
  });
});
