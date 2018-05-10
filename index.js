const ethUtil = require('ethereumjs-util');
const ethAbi = require('ethereumjs-abi');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

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
      var msg = 'eth-sig-util.normalize() requires hex string or integer input.'
      msg += ' received ' + (typeof input) + ': ' + input
      throw new Error(msg)
    }

    return ethUtil.addHexPrefix(input.toLowerCase())
  },

  personalSign: function (privateKey, msgParams) {
    var message = ethUtil.toBuffer(msgParams.data)
    var msgHash = ethUtil.hashPersonalMessage(message)
    var sig = ethUtil.ecsign(msgHash, privateKey)
    var serialized = ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
    return serialized
  },

  recoverPersonalSignature: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    const sender = ethUtil.publicToAddress(publicKey)
    const senderHex = ethUtil.bufferToHex(sender)
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
  },

  encrypt: function(receiverPublicKey, msgParams, version) {

    switch(version) {
      case 'some-version':
        //code block
        break;
      default:
        //generate ephemeral keypair
        var ephemeralKeyPair = nacl.box.keyPair()

        // assemble encryption parameters - from string to UInt8
        var pubKeyUInt8Array = nacl.util.decodeBase64(receiverPublicKey);
        var msgParamsUInt8Array = nacl.util.decodeUTF8(msgParams.data);
        var nonce = nacl.randomBytes(nacl.box.nonceLength);

        // encrypt
        var encryptedMessage = nacl.box(msgParamsUInt8Array, nonce, pubKeyUInt8Array, ephemeralKeyPair.secretKey);

        // handle encrypted data 
        var output = {
          version: 'x25519-xsalsa20-poly1305',
          nonce: nacl.util.encodeBase64(nonce),
          ephemPublicKey: nacl.util.encodeBase64(ephemeralKeyPair.publicKey),
          ciphertext: nacl.util.encodeBase64(encryptedMessage)
        };

        // return encrypted msg data
        return output;
    }
  },

  decrypt: async function(encryptedData, receiverPrivateKey, version) {

    switch(version) {
      case 'some-version':
        //code block
        break;
      default:
        //string to buffer to UInt8Array
        var recieverPrivateKeyUint8Array = nacl_decodeHex(receiverPrivateKey)
        var recieverEncryptionPrivateKey = nacl.box.keyPair.fromSecretKey(recieverPrivateKeyUint8Array).secretKey

        // assemble decryption parameters
        var nonce = nacl.util.decodeBase64(encryptedData.nonce);
        var ciphertext = nacl.util.decodeBase64(encryptedData.ciphertext);
        var ephemPublicKey = nacl.util.decodeBase64(encryptedData.ephemPublicKey);

        // decrypt
        var decryptedMessage = nacl.box.open(ciphertext, nonce, ephemPublicKey, recieverEncryptionPrivateKey);

        // return decrypted msg data
        return nacl.util.encodeUTF8(decryptedMessage);
    }
    
  },

  getEncryptionPublicKey: function(privateKey){
    var privateKeyUint8Array = nacl_decodeHex(privateKey)
    var encryptionPublicKey = nacl.box.keyPair.fromSecretKey(privateKeyUint8Array).publicKey
    return nacl.util.encodeBase64(encryptionPublicKey)
  }

}

/**
 * @param typedData - Array of data along with types, as per EIP712.
 * @returns Buffer
 */
function typedSignatureHash(typedData) {
  const error = new Error('Expect argument to be non-empty array')
  if (typeof typedData !== 'object' || !typedData.length) throw error

  const data = typedData.map(function (e) {
    return e.type === 'bytes' ? ethUtil.toBuffer(e.value) : e.value
  })
  const types = typedData.map(function (e) { return e.type })
  const schema = typedData.map(function (e) {
    if (!e.name) throw error
    return e.type + ' ' + e.name
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


function padWithZeroes (number, length) {
  var myString = '' + number
  while (myString.length < length) {
    myString = '0' + myString
  }
  return myString
}

//converts hex strings to the Uint8Array format used by nacl
function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}



