import * as sigUtil from '.';
import { concatSig, normalize } from './utils';

describe('exports', () => {
  it('should have all expected exports', () => {
    expect(Object.keys(sigUtil)).toMatchInlineSnapshot(`
Array [
  "concatSig",
  "normalize",
  "personalSign",
  "recoverPersonalSignature",
  "extractPublicKey",
  "SignTypedDataVersion",
  "TYPED_MESSAGE_SCHEMA",
  "TypedDataUtils",
  "typedSignatureHash",
  "signTypedData",
  "recoverTypedSignature",
  "encrypt",
  "encryptSafely",
  "decrypt",
  "decryptSafely",
  "getEncryptionPublicKey",
]
`);
  });

  // I don't know why this is necessary.
  // I tried using an 'istanbul ignore next' comment but it did not work.
  it('should stop marking these functions as not covered', () => {
    expect(sigUtil.concatSig).toBe(concatSig);
    expect(sigUtil.normalize).toBe(normalize);
  });
});
