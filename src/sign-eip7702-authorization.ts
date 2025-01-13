import { encode } from '@ethereumjs/rlp';
import { ecsign, publicToAddress, toBuffer } from '@ethereumjs/util';
import { bytesToHex } from '@metamask/utils';
import { keccak256 } from 'ethereum-cryptography/keccak';

import { concatSig, isNullish, recoverPublicKey } from './utils';

/**
 * The authorization struct as defined in EIP-7702.
 *
 * @property chainId - The chain ID or 0 for any chain.
 * @property contractAddress - The address of the contract being authorized.
 * @property nonce - The nonce of the signing account (at the time of submission).
 */
export type EIP7702Authorization = [
  chainId: number,
  contractAddress: string,
  nonce: number,
];

/**
 * Sign an authorization message with the provided private key.
 *
 * @param options - The signing options.
 * @param options.privateKey - The private key to sign with.
 * @param options.authorization - The authorization data to sign.
 * @returns The '0x'-prefixed hex encoded signature.
 */
export function signEIP7702Authorization({
  privateKey,
  authorization,
}: {
  privateKey: Buffer;
  authorization: EIP7702Authorization;
}): string {
  validateEIP7702Authorization(authorization);

  if (isNullish(privateKey)) {
    throw new Error('Missing privateKey parameter');
  }

  const messageHash = hashEIP7702Authorization(authorization);

  const { r, s, v } = ecsign(messageHash, privateKey);

  // v is either 27n or 28n so is guaranteed to be a single byte
  const vBuffer = toBuffer(v);

  return concatSig(vBuffer, r, s);
}

/**
 * Recover the address of the account that created the given authorization
 * signature.
 *
 * @param options - The signature recovery options.
 * @param options.signature - The '0x'-prefixed hex encoded message signature.
 * @param options.authorization - The authorization data that was signed.
 * @returns The '0x'-prefixed hex address of the signer.
 */
export function recoverEIP7702Authorization({
  signature,
  authorization,
}: {
  signature: string;
  authorization: EIP7702Authorization;
}): string {
  validateEIP7702Authorization(authorization);

  if (isNullish(signature)) {
    throw new Error('Missing signature parameter');
  }

  const messageHash = hashEIP7702Authorization(authorization);

  const publicKey = recoverPublicKey(messageHash, signature);

  const sender = publicToAddress(publicKey);

  return bytesToHex(sender);
}

/**
 * Hash an authorization message according to the signing scheme.
 * The message is encoded according to EIP-7702.
 *
 * @param authorization - The authorization data to hash.
 * @returns The hash of the authorization message as a Buffer.
 */
export function hashEIP7702Authorization(
  authorization: EIP7702Authorization,
): Buffer {
  validateEIP7702Authorization(authorization);

  const encodedAuthorization = encode(authorization);

  const message = Buffer.concat([
    Buffer.from('05', 'hex'),
    encodedAuthorization,
  ]);

  return Buffer.from(keccak256(message));
}

/**
 * Validates an authorization object to ensure all required parameters are present.
 *
 * @param authorization - The authorization object to validate.
 * @throws {Error} If the authorization object or any of its required parameters are missing.
 */
function validateEIP7702Authorization(authorization: EIP7702Authorization) {
  if (isNullish(authorization)) {
    throw new Error('Missing authorization parameter');
  }

  const [chainId, contractAddress, nonce] = authorization;

  if (isNullish(chainId)) {
    throw new Error('Missing chainId parameter');
  }

  if (isNullish(contractAddress)) {
    throw new Error('Missing contractAddress parameter');
  }

  if (isNullish(nonce)) {
    throw new Error('Missing nonce parameter');
  }
}
