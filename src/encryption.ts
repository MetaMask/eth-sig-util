import { base64, utf8 } from '@scure/base';
import * as nacl from 'tweetnacl';

import { isNullish } from './utils';

export type EthEncryptedData = {
  version: string;
  nonce: string;
  ephemPublicKey: string;
  ciphertext: string;
};

/**
 * Encrypt a message.
 *
 * @param options - The encryption options.
 * @param options.publicKey - The public key of the message recipient.
 * @param options.data - The message data.
 * @param options.version - The type of encryption to use.
 * @returns The encrypted data.
 */
export function encrypt({
  publicKey,
  data,
  version,
}: {
  publicKey: string;
  data: unknown;
  version: string;
}): EthEncryptedData {
  if (isNullish(publicKey)) {
    throw new Error('Missing publicKey parameter');
  } else if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(version)) {
    throw new Error('Missing version parameter');
  }

  switch (version) {
    case 'x25519-xsalsa20-poly1305': {
      if (typeof data !== 'string') {
        throw new Error('Message data must be given as a string');
      }
      // generate ephemeral keypair
      const ephemeralKeyPair = nacl.box.keyPair();

      // assemble encryption parameters - from string to UInt8
      let pubKeyUInt8Array: Uint8Array;
      try {
        pubKeyUInt8Array = base64.decode(publicKey);
      } catch (err) {
        throw new Error('Bad public key');
      }

      const msgParamsUInt8Array = utf8.decode(data);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);

      // encrypt
      const encryptedMessage = nacl.box(
        msgParamsUInt8Array,
        nonce,
        pubKeyUInt8Array,
        ephemeralKeyPair.secretKey,
      );

      // handle encrypted data
      const output = {
        version: 'x25519-xsalsa20-poly1305',
        nonce: base64.encode(nonce),
        ephemPublicKey: base64.encode(ephemeralKeyPair.publicKey),
        ciphertext: base64.encode(encryptedMessage),
      };
      // return encrypted msg data
      return output;
    }

    default:
      throw new Error('Encryption type/version not supported');
  }
}

/**
 * Encrypt a message in a way that obscures the message length.
 *
 * The message is padded to a multiple of 2048 before being encrypted so that the length of the
 * resulting encrypted message can't be used to guess the exact length of the original message.
 *
 * @param options - The encryption options.
 * @param options.publicKey - The public key of the message recipient.
 * @param options.data - The message data.
 * @param options.version - The type of encryption to use.
 * @returns The encrypted data.
 */
export function encryptSafely({
  publicKey,
  data,
  version,
}: {
  publicKey: string;
  data: unknown;
  version: string;
}): EthEncryptedData {
  if (isNullish(publicKey)) {
    throw new Error('Missing publicKey parameter');
  } else if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(version)) {
    throw new Error('Missing version parameter');
  }

  const DEFAULT_PADDING_LENGTH = 2 ** 11;
  const NACL_EXTRA_BYTES = 16;

  if (typeof data === 'object' && data && 'toJSON' in data) {
    // remove toJSON attack vector
    // TODO, check all possible children
    throw new Error(
      'Cannot encrypt with toJSON property.  Please remove toJSON property',
    );
  }

  // add padding
  const dataWithPadding = {
    data,
    padding: '',
  };

  // calculate padding
  const dataLength = Buffer.byteLength(
    JSON.stringify(dataWithPadding),
    'utf-8',
  );
  const modVal = dataLength % DEFAULT_PADDING_LENGTH;
  let padLength = 0;
  // Only pad if necessary
  if (modVal > 0) {
    padLength = DEFAULT_PADDING_LENGTH - modVal - NACL_EXTRA_BYTES; // nacl extra bytes
  }
  dataWithPadding.padding = '0'.repeat(padLength);

  const paddedMessage = JSON.stringify(dataWithPadding);
  return encrypt({ publicKey, data: paddedMessage, version });
}

/**
 * Decrypt a message.
 *
 * @param options - The decryption options.
 * @param options.encryptedData - The encrypted data.
 * @param options.privateKey - The private key to decrypt with.
 * @returns The decrypted message.
 */
export function decrypt({
  encryptedData,
  privateKey,
}: {
  encryptedData: EthEncryptedData;
  privateKey: string;
}): string {
  if (isNullish(encryptedData)) {
    throw new Error('Missing encryptedData parameter');
  } else if (isNullish(privateKey)) {
    throw new Error('Missing privateKey parameter');
  }

  switch (encryptedData.version) {
    case 'x25519-xsalsa20-poly1305': {
      const receiverPrivateKeyUint8Array = Buffer.from(privateKey, 'hex');
      const receiverEncryptionPrivateKey = nacl.box.keyPair.fromSecretKey(
        receiverPrivateKeyUint8Array,
      ).secretKey;

      // assemble decryption parameters
      const nonce = base64.decode(encryptedData.nonce);
      const ciphertext = base64.decode(encryptedData.ciphertext);
      const ephemPublicKey = base64.decode(encryptedData.ephemPublicKey);

      // decrypt
      const decryptedMessage = nacl.box.open(
        ciphertext,
        nonce,
        ephemPublicKey,
        receiverEncryptionPrivateKey,
      );

      // return decrypted msg data
      try {
        if (!decryptedMessage) {
          throw new Error();
        }
        const output = utf8.encode(decryptedMessage);
        // TODO: This is probably extraneous but was kept to minimize changes during refactor
        if (!output) {
          throw new Error();
        }
        return output;
      } catch (err) {
        if (err && typeof err.message === 'string' && err.message.length) {
          throw new Error(`Decryption failed: ${err.message as string}`);
        }
        throw new Error(`Decryption failed.`);
      }
    }

    default:
      throw new Error('Encryption type/version not supported.');
  }
}

/**
 * Decrypt a message that has been encrypted using `encryptSafely`.
 *
 * @param options - The decryption options.
 * @param options.encryptedData - The encrypted data.
 * @param options.privateKey - The private key to decrypt with.
 * @returns The decrypted message.
 */
export function decryptSafely({
  encryptedData,
  privateKey,
}: {
  encryptedData: EthEncryptedData;
  privateKey: string;
}): string {
  if (isNullish(encryptedData)) {
    throw new Error('Missing encryptedData parameter');
  } else if (isNullish(privateKey)) {
    throw new Error('Missing privateKey parameter');
  }

  const dataWithPadding = JSON.parse(decrypt({ encryptedData, privateKey }));
  return dataWithPadding.data;
}

/**
 * Get the encryption public key for the given key.
 *
 * @param privateKey - The private key to generate the encryption public key with.
 * @returns The encryption public key.
 */
export function getEncryptionPublicKey(privateKey: string): string {
  const privateKeyUint8Array = Buffer.from(privateKey, 'hex');
  const encryptionPublicKey =
    nacl.box.keyPair.fromSecretKey(privateKeyUint8Array).publicKey;
  return base64.encode(encryptionPublicKey);
}
