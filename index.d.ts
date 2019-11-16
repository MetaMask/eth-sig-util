type hexPrefixedHex = string;
type MsgParams = { data: string, sig?: string };
type SignedMsgParams = {data: string, sig: string };

export type ITypedField = {
  name: string
  type: string // Ethereum supported type strings: uint256, string, address, ClassName, etc.
}

export interface ITypedValue {
  [key: string]: string | number | ITypedValue | ITypedValue[]
}

export type ITypedData = {
  types: {
    EIP712Domain: Array<ITypedField>
    [ typeName:string ]: Array<ITypedField>
  }
  domain?: {
    name?: string
    version?: string
    chainId?: number
    verifyingContract?: string
  }
  primaryType: string
  message: ITypedValue
}

export type ITypedDataSignatureParams = {
  from: string
  data: ITypedData
}

type EthJsBinary = Buffer | Uint8Array;
type EthEncryptedData = { 
  version: string,
  nonce: string,
  ephemPublicKey: string,
  ciphertext: string
}
export interface ISignedTypedData {
  data: ITypedData,
  sig: string,
}

declare module "eth-sig-util" {
  export function concatSig(v: number, r: Buffer, s: Buffer): Buffer
  export function normalize (input: number | string ): hexPrefixedHex
  export function personalSign (privateKeyBuffer: Buffer, msgParams: MsgParams): string
  export function recoverPersonalSignature(msgParams: SignedMsgParams): string
  export function extractPublicKey(msgParams: SignedMsgParams): hexPrefixedHex
  export function typedSignatureHash(typedData: ITypedData): EthJsBinary

  export function getEncryptionPublicKey (privateKey: string): string

  export function encrypt (receiverPublicKey: string, msgParams: MsgParams, version: string): EthEncryptedData 
  export function decrypt (encryptedData: EthEncryptedData, receiverPublicKey: string): string

  export function encryptSafely(receiverPublicKey: string, msgParams: MsgParams, version: string): EthEncryptedData 
  export function decryptSafely (encryptedData: EthEncryptedData, receiverPublicKey: string): string

  export function signTypedDataLegacy(privateKey: EthJsBinary, msgParams: ITypedDataSignatureParams): hexPrefixedHex
  export function recoverTypedSignatureLegacy(msgParams: SignedMsgParams): hexPrefixedHex;

  export function signTypedData(privateKey: EthJsBinary, msgParams: ITypedDataSignatureParams): hexPrefixedHex
  export function recoverTypedSignature(msgParams: SignedMsgParams): hexPrefixedHex;

  export function signTypedData_v4(privateKey: EthJsBinary, msgParams: ITypedDataSignatureParams): hexPrefixedHex
  export function recoverTypedSignature_v4(msgParams: SignedMsgParams): hexPrefixedHex;
}
