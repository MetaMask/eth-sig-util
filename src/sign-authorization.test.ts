import { bufferToHex, privateToAddress } from '@ethereumjs/util';

import {
  signAuthorization,
  recoverAuthorization,
  Authorization,
  hashAuthorization,
} from './sign-authorization';

const testPrivateKey = Buffer.from(
  '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0',
  'hex',
);

const testAddress = bufferToHex(privateToAddress(testPrivateKey));

const testAuthorization: Authorization = [
  8545,
  '0x1234567890123456789012345678901234567890',
  1,
];

const expectedAuthorizationHash = Buffer.from(
  'b847dee5b33802280f3279d57574e1eb6bf5d628d7f63049e3cb20bad211056c',
  'hex',
);

const expectedSignature =
  '0xebea1ac12f17a56a514dfecbcbc8bbee7b089fa3fcee31680d1e2c1588f623df7973cab74e12536678995377da38c96c65c52897750b73462c6760ef2737dba41b';

describe('signAuthorization', () => {
  describe('signAuthorization()', () => {
    it('should produce the correct signature', () => {
      const signature = signAuthorization({
        privateKey: testPrivateKey,
        authorization: testAuthorization,
      });

      expect(signature).toBe(expectedSignature);
    });

    it('should throw if private key is null', () => {
      expect(() =>
        signAuthorization({
          privateKey: null as any,
          authorization: testAuthorization,
        }),
      ).toThrow('Missing privateKey parameter');
    });

    it('should throw if private key is undefined', () => {
      expect(() =>
        signAuthorization({
          privateKey: undefined as any,
          authorization: testAuthorization,
        }),
      ).toThrow('Missing privateKey parameter');
    });

    it('should throw if authorization is null', () => {
      expect(() =>
        signAuthorization({
          privateKey: testPrivateKey,
          authorization: null as any,
        }),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if authorization is undefined', () => {
      expect(() =>
        signAuthorization({
          privateKey: testPrivateKey,
          authorization: undefined as any,
        }),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if chainId is null', () => {
      expect(() =>
        signAuthorization({
          privateKey: testPrivateKey,
          authorization: [
            null as unknown as number,
            testAuthorization[1],
            testAuthorization[2],
          ],
        }),
      ).toThrow('Missing chainId parameter');
    });

    it('should throw if contractAddress is null', () => {
      expect(() =>
        signAuthorization({
          privateKey: testPrivateKey,
          authorization: [
            testAuthorization[0],
            null as unknown as string,
            testAuthorization[2],
          ],
        }),
      ).toThrow('Missing contractAddress parameter');
    });

    it('should throw if nonce is null', () => {
      expect(() =>
        signAuthorization({
          privateKey: testPrivateKey,
          authorization: [
            testAuthorization[0],
            testAuthorization[1],
            null as unknown as number,
          ],
        }),
      ).toThrow('Missing nonce parameter');
    });
  });

  describe('hashAuthorization()', () => {
    it('should produce the correct hash', () => {
      const hash = hashAuthorization(testAuthorization);

      expect(hash).toStrictEqual(expectedAuthorizationHash);
    });

    it('should throw if authorization is null', () => {
      expect(() => hashAuthorization(null as unknown as Authorization)).toThrow(
        'Missing authorization parameter',
      );
    });

    it('should throw if authorization is undefined', () => {
      expect(() =>
        hashAuthorization(undefined as unknown as Authorization),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if chainId is null', () => {
      expect(() =>
        hashAuthorization([
          null as unknown as number,
          testAuthorization[1],
          testAuthorization[2],
        ]),
      ).toThrow('Missing chainId parameter');
    });

    it('should throw if contractAddress is null', () => {
      expect(() =>
        hashAuthorization([
          testAuthorization[0],
          null as unknown as string,
          testAuthorization[2],
        ]),
      ).toThrow('Missing contractAddress parameter');
    });

    it('should throw if nonce is null', () => {
      expect(() =>
        hashAuthorization([
          testAuthorization[0],
          testAuthorization[1],
          null as unknown as number,
        ]),
      ).toThrow('Missing nonce parameter');
    });
  });

  describe('recoverAuthorization()', () => {
    it('should recover the address from a signature', () => {
      const recoveredAddress = recoverAuthorization({
        authorization: testAuthorization,
        signature: expectedSignature,
      });

      expect(recoveredAddress).toBe(testAddress);
    });

    it('should throw if signature is null', () => {
      expect(() =>
        recoverAuthorization({
          signature: null as unknown as string,
          authorization: testAuthorization,
        }),
      ).toThrow('Missing signature parameter');
    });

    it('should throw if signature is undefined', () => {
      expect(() =>
        recoverAuthorization({
          signature: undefined as unknown as string,
          authorization: testAuthorization,
        }),
      ).toThrow('Missing signature parameter');
    });

    it('should throw if authorization is null', () => {
      expect(() =>
        recoverAuthorization({
          signature: expectedSignature,
          authorization: null as unknown as Authorization,
        }),
      ).toThrow('Missing authorization parameter');
    });

    it('should throw if authorization is undefined', () => {
      expect(() =>
        recoverAuthorization({
          signature: expectedSignature,
          authorization: undefined as unknown as Authorization,
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
    } as { [key: string]: Authorization };

    for (const [label, authorization] of Object.entries(testCases)) {
      it(`should sign and recover ${label}`, () => {
        const signature = signAuthorization({
          privateKey: testPrivateKey,
          authorization,
        });

        const recoveredAddress = recoverAuthorization({
          authorization,
          signature,
        });

        expect(recoveredAddress).toBe(testAddress);
      });
    }
  });
});
