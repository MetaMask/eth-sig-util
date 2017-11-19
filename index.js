const ethUtil = require('ethereumjs-util')
const ethAbi = require('ethereumjs-abi')
const nacl = require('tweetnacl')
nacl.util = require('tweetnacl-util')

module.exports = {

  concatSig: function (v, r, s) {
    const rSig = ethUtil.fromSigned(r)
    const sSig = ethUtil.fromSigned(s)
    const vSig = ethUtil.bufferToInt(v)
    const rStr = padWithZeroes(ethUtil.toUnsigned(rSig).toString('hex'), 64)
    const sStr = padWithZeroes(ethUtil.toUnsigned(sSig).toString('hex'), 64)
    const vStr = ethUtil.stripHexPrefix(ethUtil.intToHex(vSig))
    return ethUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex')
  },

  normalize: function (input) {
    if (!input) return

    if (typeof input === 'number') {
      const buffer = ethUtil.toBuffer(input)
      input = ethUtil.bufferToHex(buffer)
    }

    if (typeof input !== 'string') {
      let msg = 'eth-sig-util.normalize() requires hex string or integer input.'
      msg += ` received ${typeof input}: ${input}`
      throw new Error(msg)
    }

    return ethUtil.addHexPrefix(input.toLowerCase())
  },

  encrypt: function (privateKey, msgParams) {
    const theirPubKey = getPublicKeyFor(msgParams);

    // encrypt with recipient's public key and encryptor's private key
    var privKeyUInt8Array = nacl_decodeHex(privateKey);
    var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

    var trimmedPubKeyUInt8Array = new Uint8Array(pubKeyUInt8Array.slice(0,32));
    var nonce = nacl.randomBytes(nacl.box.nonceLength);
    var msgParamsUInt8Array = new Uint8Array(msgParams.data);
    var encryptedMessage = nacl.box(msgParamsUInt8Array, nonce, trimmedPubKeyUInt8Array, privKeyUInt8Array);

    var output = {
      alg: 'curve25519-xsalsa20-poly1305',
      nonce: nacl.util.encodeBase64(nonce),
      ciphertext: nacl.util.encodeBase64(encryptedMessage)
    };

    // return encrypted msg data
    return output;
  },

  decrypt: function (privateKey, msgParams) {
    const theirPubKey = getPublicKeyForCiphertext(msgParams);

    // decrypt using recipient's public key and encryptor's private key
    var privKeyUInt8Array = nacl_decodeHex(privateKey);
    var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

    var trimmedPubKeyUInt8Array = new Uint8Array(pubKeyUInt8Array.slice(0,32));
    var nonce = nacl.util.decodeBase64(msgParams.data.nonce);
    var ciphertext = nacl.util.decodeBase64(msgParams.data.ciphertext);
    var cleartext = nacl.box.open(ciphertext, nonce, trimmedPubKeyUInt8Array, privKeyUInt8Array);

    // return decrypted msg data
    return cleartext;
  },

  personalSign: function (privateKey, msgParams) {
    var message = ethUtil.toBuffer(msgParams.data)
    var msgHash = ethUtil.hashPersonalMessage(message)
    var sig = ethUtil.ecsign(msgHash, privateKey)
    var serialized = ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
    return serialized
  },

  personalSignCiphertext: function (privateKey, msgParams) {
    var message = ethUtil.toBuffer(msgParams.data.ciphertext)
    var msgHash = ethUtil.hashPersonalMessage(message)
    var sig = ethUtil.ecsign(msgHash, privateKey)
    var serialized = ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
    return serialized
  },

  recoverPersonalSignature: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    const sender = ethUtil.publicToAddress(publicKey)
    senderHex = ethUtil.bufferToHex(sender)
    return senderHex
  },

  extractPublicKey: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    return '0x' + publicKey.toString('hex')
  },

  typedSignatureHash: function (typedData) {
    const hashBuffer = typedSignatureHash(typedData)
    return ethUtil.bufferToHex(hashBuffer)
  },

  signTypedData: function (privateKey, msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const sig = ethUtil.ecsign(msgHash, privateKey)
    return ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
  },

  recoverTypedSignature: function (msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const publicKey = recoverPublicKey(msgHash, msgParams.sig)
    const sender = ethUtil.publicToAddress(publicKey)
    return ethUtil.bufferToHex(sender)
  }

}

/**
 * @param typedData - Array of data along with types, as per EIP712.
 * @returns Buffer
 */
function typedSignatureHash(typedData) {
  const error = new Error('Expect argument to be non-empty array')
  if (typeof typedData !== 'object' || !typedData.length) throw error

  const data = typedData.map(function (e) { return e.value })
  const types = typedData.map(function (e) { return e.type })
  const schema = typedData.map(function (e) {
    if (!e.name) throw error
    return `${e.type} ${e.name}`
  })

  return ethAbi.soliditySHA3(
    ['bytes32', 'bytes32'],
    [
      ethAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema),
      ethAbi.soliditySHA3(types, data)
    ]
  )
}

function recoverPublicKey(hash, sig) {
  const signature = ethUtil.toBuffer(sig)
  const sigParams = ethUtil.fromRpcSig(signature)
  return ethUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s)
}

function getPublicKeyFor (msgParams) {
  const message = ethUtil.toBuffer(msgParams.data)
  const msgHash = ethUtil.hashPersonalMessage(message)
  return recoverPublicKey(msgHash, msgParams.sig)
}

function getPublicKeyForCiphertext (msgParams) {
  const message = ethUtil.toBuffer(msgParams.data.ciphertext)
  const msgHash = ethUtil.hashPersonalMessage(message)
  return recoverPublicKey(msgHash, msgParams.sig)
}

function padWithZeroes (number, length) {
  var myString = '' + number
  while (myString.length < length) {
    myString = '0' + myString
  }
  return myString
}

function nacl_encodeHex(msgUInt8Arr) {
  var msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}
