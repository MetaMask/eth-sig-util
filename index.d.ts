type TBuffer = Buffer | Uint8Array;
type TMsgParams = {
  data: any;
  sig?: any;
};
type TEncryptVersion = "x25519-xsalsa20-poly1305";
type TEncryptResult = {
  version: TEncryptVersion;
  nonce: string;
  ephemPublicKey: string;
  ciphertext: string;
};

declare module "eth-sig-util" {
  const TYPED_MESSAGE_SCHEMA: {
    type: string;
    properties: {
      types: {
        type: string;
        additionalProperties: {
          type: string;
          items: {
            type: string;
            properties: {
              name: {
                type: string;
              };
              type: {
                type: string;
              };
            };
            required: string[];
          };
        };
      };
      primaryType: {
        type: string;
      };
      domain: {
        type: string;
      };
      message: {
        type: string;
      };
    };
    required: string[];
  };
  namespace TypedDataUtils {
    function encodeData(primaryType: string, data: {}, types: {}): string;
    function encodeType(primaryType: string, types: {}): string;
    function findTypeDependencies(
      primaryType: string,
      types: {},
      results?: string[]
    ): string[];
    function hashStruct(primaryType: string, data: {}, types: {}): string;
    function hashType(primaryType: string, types: {}): string;
    function sanitizeData(data: {}): {};
    function sign(typedData): TBuffer;
  }

  function concatSig(v, r, s): string;
  function normalize(input: number | string): string;
  function personalSign(privateKey: TBuffer, msgParams: TMsgParams): string;
  function recoverPersonalSignature(msgParams: TMsgParams): string;
  function extractPublicKey(msgParams: TMsgParams): string;
  function typedSignatureHash(typedData: any[]): string;
  function signTypedDataLegacy(
    privateKey: TBuffer,
    msgParams: TMsgParams
  ): string;
  function recoverTypedSignatureLegacy(msgParams: TMsgParams): string;
  function encrypt(
    receiverPublicKey: string,
    msgParams: TMsgParams,
    version: TEncryptVersion
  ): TEncryptResult;
  function encryptSafely(
    receiverPublicKey: string,
    msgParams: TMsgParams,
    version: TEncryptVersion
  ): TEncryptResult;
  function decrypt(
    encryptedData: TEncryptResult,
    receiverPrivateKey: string
  ): string;
  function decryptSafely(
    encryptedData: TEncryptResult,
    receiverPrivateKey: string
  ): string;
  function getEncryptionPublicKey(privateKey: string): string;
  function signTypedData(privateKey: TBuffer, msgParams: TMsgParams): string;
  function recoverTypedSignature(msgParams: TMsgParams): string;
}
