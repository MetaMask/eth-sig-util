import {
  decrypt,
  decryptSafely,
  encrypt,
  encryptSafely,
  getEncryptionPublicKey,
} from './encryption';

describe('encryption', function () {
  const bob = {
    ethereumPrivateKey:
      '7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816',
    encryptionPrivateKey: 'flN07C7w2Rdhpucv349qxmVRm/322gojKc8NgEUUuBY=',
    encryptionPublicKey: 'C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=',
  };

  const secretMessage = 'My name is Satoshi Buterin';

  const encryptedData = {
    version: 'x25519-xsalsa20-poly1305',
    nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
    ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
    ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
  };

  it("getting bob's encryptionPublicKey", async function () {
    const result = getEncryptionPublicKey(bob.ethereumPrivateKey);
    expect(result).toBe(bob.encryptionPublicKey);
  });

  // encryption test
  it("alice encrypts message with bob's encryptionPublicKey", async function () {
    const result = encrypt({
      publicKey: bob.encryptionPublicKey,
      data: secretMessage,
      version: 'x25519-xsalsa20-poly1305',
    });

    expect(result.ciphertext).toHaveLength(56);
    expect(result.ephemPublicKey).toHaveLength(44);
    expect(result.nonce).toHaveLength(32);
    expect(result.version).toBe('x25519-xsalsa20-poly1305');
  });

  // safe encryption test
  it("alice encryptsSafely message with bob's encryptionPublicKey", async function () {
    const version = 'x25519-xsalsa20-poly1305';
    const result = encryptSafely({
      publicKey: bob.encryptionPublicKey,
      data: secretMessage,
      version,
    });

    expect(result.ciphertext).toHaveLength(2732);
    expect(result.ephemPublicKey).toHaveLength(44);
    expect(result.nonce).toHaveLength(32);
    expect(result.version).toBe('x25519-xsalsa20-poly1305');
  });

  // safe decryption test
  it('bob decryptSafely message that Alice encryptSafely for him', async function () {
    const version = 'x25519-xsalsa20-poly1305';
    const result = encryptSafely({
      publicKey: bob.encryptionPublicKey,
      data: secretMessage,
      version,
    });

    const plaintext = decryptSafely({
      encryptedData: result,
      privateKey: bob.ethereumPrivateKey,
    });
    expect(plaintext).toBe(secretMessage);
  });

  // decryption test
  it('bob decrypts message that Alice sent to him', function () {
    const result = decrypt({
      encryptedData,
      privateKey: bob.ethereumPrivateKey,
    });
    expect(result).toBe(secretMessage);
  });

  it('decryption failed because version is wrong or missing', function () {
    const badVersionData = {
      version: 'x256k1-aes256cbc',
      nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
      ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
      ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
    };

    expect(() =>
      decrypt({
        encryptedData: badVersionData,
        privateKey: bob.ethereumPrivateKey,
      }),
    ).toThrow('Encryption type/version not supported.');
  });

  it('decryption failed because nonce is wrong or missing', function () {
    // encrypted data
    const badNonceData = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: '',
      ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
      ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
    };

    expect(() =>
      decrypt({
        encryptedData: badNonceData,
        privateKey: bob.ethereumPrivateKey,
      }),
    ).toThrow('bad nonce size');
  });

  it('decryption failed because ephemPublicKey is wrong or missing', function () {
    // encrypted data
    const badEphemData = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
      ephemPublicKey: 'FFFF/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
      ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
    };

    expect(() =>
      decrypt({
        encryptedData: badEphemData,
        privateKey: bob.ethereumPrivateKey,
      }),
    ).toThrow('Decryption failed.');
  });

  it('decryption failed because cyphertext is wrong or missing', function () {
    // encrypted data
    const badEphemData = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
      ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
      ciphertext: 'ffffff/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
    };

    expect(() =>
      decrypt({
        encryptedData: badEphemData,
        privateKey: bob.ethereumPrivateKey,
      }),
    ).toThrow('Decryption failed.');
  });

  describe('validation', function () {
    describe('encrypt', function () {
      it('should throw if passed null public key', function () {
        expect(() =>
          encrypt({
            publicKey: null as any,
            data: secretMessage,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing publicKey parameter');
      });

      it('should throw if passed undefined public key', function () {
        expect(() =>
          encrypt({
            publicKey: undefined as any,
            data: secretMessage,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing publicKey parameter');
      });

      it('should throw if passed null data', function () {
        expect(() =>
          encrypt({
            publicKey: bob.encryptionPublicKey,
            data: null,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing data parameter');
      });

      it('should throw if passed undefined data', function () {
        expect(() =>
          encrypt({
            publicKey: bob.encryptionPublicKey,
            data: undefined,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing data parameter');
      });

      it('should throw if passed null version', function () {
        expect(() =>
          encrypt({
            publicKey: bob.encryptionPublicKey,
            data: secretMessage,
            version: null as any,
          }),
        ).toThrow('Missing version parameter');
      });

      it('should throw if passed undefined version', function () {
        expect(() =>
          encrypt({
            publicKey: bob.encryptionPublicKey,
            data: secretMessage,
            version: undefined as any,
          }),
        ).toThrow('Missing version parameter');
      });
    });

    describe('encryptSafely', function () {
      it('should throw if passed null public key', function () {
        expect(() =>
          encryptSafely({
            publicKey: null as any,
            data: secretMessage,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing publicKey parameter');
      });

      it('should throw if passed undefined public key', function () {
        expect(() =>
          encryptSafely({
            publicKey: undefined as any,
            data: secretMessage,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing publicKey parameter');
      });

      it('should throw if passed null data', function () {
        expect(() =>
          encryptSafely({
            publicKey: bob.encryptionPublicKey,
            data: null,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing data parameter');
      });

      it('should throw if passed undefined data', function () {
        expect(() =>
          encryptSafely({
            publicKey: bob.encryptionPublicKey,
            data: undefined,
            version: 'x25519-xsalsa20-poly1305',
          }),
        ).toThrow('Missing data parameter');
      });

      it('should throw if passed null version', function () {
        expect(() =>
          encryptSafely({
            publicKey: bob.encryptionPublicKey,
            data: secretMessage,
            version: null as any,
          }),
        ).toThrow('Missing version parameter');
      });

      it('should throw if passed undefined version', function () {
        expect(() =>
          encryptSafely({
            publicKey: bob.encryptionPublicKey,
            data: secretMessage,
            version: undefined as any,
          }),
        ).toThrow('Missing version parameter');
      });
    });

    describe('decrypt', function () {
      it('should throw if passed null encrypted data', function () {
        expect(() =>
          decrypt({
            encryptedData: null as any,
            privateKey: bob.ethereumPrivateKey,
          }),
        ).toThrow('Missing encryptedData parameter');
      });

      it('should throw if passed undefined encrypted data', function () {
        expect(() =>
          decrypt({
            encryptedData: undefined as any,
            privateKey: bob.ethereumPrivateKey,
          }),
        ).toThrow('Missing encryptedData parameter');
      });

      it('should throw if passed null private key', function () {
        expect(() =>
          decrypt({
            encryptedData,
            privateKey: null as any,
          }),
        ).toThrow('Missing privateKey parameter');
      });

      it('should throw if passed undefined private key', function () {
        expect(() =>
          decrypt({
            encryptedData,
            privateKey: undefined as any,
          }),
        ).toThrow('Missing privateKey parameter');
      });
    });

    describe('decryptSafely', function () {
      it('should throw if passed null encrypted data', function () {
        expect(() =>
          decryptSafely({
            encryptedData: null as any,
            privateKey: bob.ethereumPrivateKey,
          }),
        ).toThrow('Missing encryptedData parameter');
      });

      it('should throw if passed undefined encrypted data', function () {
        expect(() =>
          decryptSafely({
            encryptedData: undefined as any,
            privateKey: bob.ethereumPrivateKey,
          }),
        ).toThrow('Missing encryptedData parameter');
      });

      it('should throw if passed null private key', function () {
        expect(() =>
          decryptSafely({
            encryptedData,
            privateKey: null as any,
          }),
        ).toThrow('Missing privateKey parameter');
      });

      it('should throw if passed undefined private key', function () {
        expect(() =>
          decryptSafely({
            encryptedData,
            privateKey: undefined as any,
          }),
        ).toThrow('Missing privateKey parameter');
      });
    });
  });
});
