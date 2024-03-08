import type { ToBufferInputTypes } from '@ethereumjs/util';
import {
  bufferToHex,
  ecsign,
  hashPersonalMessage,
  publicToAddress,
  toBuffer,
} from '@ethereumjs/util';

import {
  concatSig,
  isNullish,
  legacyToBuffer,
  recoverPublicKey,
} from './utils';

/**
 * Create an Ethereum-specific signature for a message.
 *
 * This function is equivalent to the `eth_sign` Ethereum JSON-RPC method as specified in EIP-1417,
 * as well as the MetaMask's `personal_sign` method.
 *
 * @param options - The personal sign options.
 * @param options.privateKey - The key to sign with.
 * @param options.data - The hex data to sign.
 * @returns The '0x'-prefixed hex encoded signature.
 */
export function personalSign({
  privateKey,
  data,
}: {
  privateKey: Buffer;
  data: ToBufferInputTypes;
}): string {
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(privateKey)) {
    throw new Error('Missing privateKey parameter');
  }

  const message = legacyToBuffer(data);
  const msgHash = hashPersonalMessage(message);
  const sig = ecsign(msgHash, privateKey);
  const serialized = concatSig(toBuffer(sig.v), sig.r, sig.s);
  return serialized;
}

/**
 * Recover the address of the account used to create the given Ethereum signature. The message
 * must have been signed using the `personalSign` function, or an equivalent function.
 *
 * @param options - The signature recovery options.
 * @param options.data - The hex data that was signed.
 * @param options.signature - The '0x'-prefixed hex encoded message signature.
 * @returns The '0x'-prefixed hex encoded address of the message signer.
 */
export function recoverPersonalSignature({
  data,
  signature,
}: {
  data: ToBufferInputTypes;
  signature: string;
}): string {
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(signature)) {
    throw new Error('Missing signature parameter');
  }

  const publicKey = getPublicKeyFor(data, signature);
  const sender = publicToAddress(publicKey);
  const senderHex = bufferToHex(sender);
  return senderHex;
}

/**
 * Recover the public key of the account used to create the given Ethereum signature. The message
 * must have been signed using the `personalSign` function, or an equivalent function.
 *
 * @param options - The public key recovery options.
 * @param options.data - The hex data that was signed.
 * @param options.signature - The '0x'-prefixed hex encoded message signature.
 * @returns The '0x'-prefixed hex encoded public key of the message signer.
 */
export function extractPublicKey({
  data,
  signature,
}: {
  data: ToBufferInputTypes;
  signature: string;
}): string {
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(signature)) {
    throw new Error('Missing signature parameter');
  }

  const publicKey = getPublicKeyFor(data, signature);
  return `0x${publicKey.toString('hex')}`;
}

/**
 * Get the public key for the given signature and message.
 *
 * @param message - The message that was signed.
 * @param signature - The '0x'-prefixed hex encoded message signature.
 * @returns The public key of the signer.
 */
function getPublicKeyFor(
  message: ToBufferInputTypes,
  signature: string,
): Buffer {
  const messageHash = hashPersonalMessage(legacyToBuffer(message));
  return recoverPublicKey(messageHash, signature);
}
