type hexPrefixedHex = string;
type MsgParams = { data: string, sig?: string };
type SignedMsgParams = {data: string, sig: string };
type ITypedEntry = {
  type: string, // Ideally enumerate the valid types here.
  name: string,

}
type TypedData = ITypedEntry[];
type EthJsBinary = Buffer | Uint8Array;
type EthEncryptedData = { 
  version: string,
  nonce: string,
  ephemPublicKey: string,
  ciphertext: string
}

interface TypedDataParam extends MsgParams {
  data: TypedData,
}

declare module "eth-sig-util" {
  import { Buffer } from "safe-buffer"

  export function concatSig(v: number, r: Buffer, s: Buffer): Buffer
  export function normalize (input: number | string ): hexPrefixedHex
  export function personalSign (privateKeyBuffer: Buffer, msgParams: MsgParams): string
  export function recoverPersonalSignature(msgParams: SignedMsgParams): string
  export function extractPublicKey(msgParams: SignedMsgParams)
  export function typedSignatureHash(typedData: TypedData): EthJsBinary

  export function getEncryptionPublicKey (privateKey: string): string

  export function encrypt (receiverPublicKey: string, msgParams: MsgParams, version: string): EthEncryptedData 
  export function decrypt (encryptedData: EthEncryptedData, receiverPublicKey: string): string

  export function encryptSafely(receiverPublicKey: string, msgParams: MsgParams, version: string): EthEncryptedData 
  export function decryptSafely (encryptedData: EthEncryptedData, receiverPublicKey: string): string

  export function signTypedDataLegacy(privateKey: EthJsBinary, msgParams: TypedDataParam): hexPrefixedHex
  export function recoverTypedSignatureLegacy(msgParams: SignedMsgParams): hexPrefixedHex;

  export function signTypedData(privateKey: EthJsBinary, msgParams: TypedDataParam): hexPrefixedHex
  export function recoverTypedSignature(msgParams: SignedMsgParams): hexPrefixedHex;

  export function signTypedData_v4(privateKey: EthJsBinary, msgParams: TypedDataParam): hexPrefixedHex
  export function recoverTypedSignature_v4(msgParams: SignedMsgParams): hexPrefixedHex;
}
