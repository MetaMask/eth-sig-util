'use strict'

const EC = require('elliptic').ec

const ec = new EC('secp256k1')
const cryptoObj = global.crypto || global.msCrypto || {}
const subtle = cryptoObj.subtle || cryptoObj.webkitSubtle

function assert (condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed')
  }
}

function randomBytes (size) {
  const arr = new Uint8Array(size)
  global.crypto.getRandomValues(arr)
  return Buffer.from(arr)
}

function sha512 (msg) {
  return subtle.digest({ name: 'SHA-512' }, msg).then(function (hash) {
    return Buffer.from(new Uint8Array(hash))
  })
}

function getAes (op) {
  return function (iv, key, data) {
    const importAlgorithm = { name: 'AES-CBC' }
    const keyp = subtle.importKey('raw', key, importAlgorithm, false, [op])
    return keyp.then(function (cryptoKey) {
      const encAlgorithm = { name: 'AES-CBC', iv }
      return subtle[op](encAlgorithm, cryptoKey, data)
    }).then(function (result) {
      return Buffer.from(new Uint8Array(result))
    })
  }
}

const aesCbcEncrypt = getAes('encrypt')
const aesCbcDecrypt = getAes('decrypt')

function hmacSha256Sign (key, msg) {
  const algorithm = { name: 'HMAC', hash: { name: 'SHA-256' } }
  const keyp = subtle.importKey('raw', key, algorithm, false, ['sign'])
  return keyp.then(function (cryptoKey) {
    return subtle.sign(algorithm, cryptoKey, msg)
  }).then(function (sig) {
    return Buffer.from(new Uint8Array(sig))
  })
}

function hmacSha256Verify (key, msg, sig) {
  const algorithm = { name: 'HMAC', hash: { name: 'SHA-256' } }
  const keyp = subtle.importKey('raw', key, algorithm, false, ['verify'])
  return keyp.then(function (cryptoKey) {
    return subtle.verify(algorithm, cryptoKey, sig, msg)
  })
}

const getPublic = function (privateKey) {
  assert(privateKey.length === 32, 'Bad private key')
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic('arr'))
}
exports.getPublic = getPublic

const derive = function (privateKeyA, publicKeyB) {
  return new Promise(function (resolve) {
    assert(Buffer.isBuffer(privateKeyA), 'Bad input')
    assert(Buffer.isBuffer(publicKeyB), 'Bad input')
    assert(privateKeyA.length === 32, 'Bad private key')
    assert(publicKeyB.length === 65, 'Bad public key')
    assert(publicKeyB[0] === 4, 'Bad public key')
    const keyA = ec.keyFromPrivate(privateKeyA)
    const keyB = ec.keyFromPublic(publicKeyB)
    const Px = keyA.derive(keyB.getPublic()) // BN instance
    resolve(Buffer.from(Px.toArray()))
  })
}
exports.derive = derive

const encrypt = function (publicKeyTo, msg, opts) {
  assert(subtle, 'WebCryptoAPI is not available')
  opts = opts || {}
  // Tmp variables to save context from flat promises;
  let iv, ephemPublicKey, ciphertext, macKey
  return new Promise(function (resolve) {
    const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32)
    ephemPublicKey = getPublic(ephemPrivateKey)
    resolve(derive(ephemPrivateKey, publicKeyTo))
  }).then(function (Px) {
    return sha512(Px)
  }).then(function (hash) {
    iv = opts.iv || randomBytes(16)
    const encryptionKey = hash.slice(0, 32)
    macKey = hash.slice(32)
    return aesCbcEncrypt(iv, encryptionKey, msg)
  }).then(function (data) {
    ciphertext = data
    const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext])
    return hmacSha256Sign(macKey, dataToMac)
  }).then(function (mac) {
    return {
      iv,
      ephemPublicKey,
      ciphertext,
      mac,
    }
  })
}
const decrypt = function (privateKey, opts) {
  assert(subtle, 'WebCryptoAPI is not available')
  // Tmp variable to save context from flat promises;
  let encryptionKey
  return derive(privateKey, opts.ephemPublicKey).then(function (Px) {
    return sha512(Px)
  }).then(function (hash) {
    encryptionKey = hash.slice(0, 32)
    const macKey = hash.slice(32)
    const dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext,
    ])
    return hmacSha256Verify(macKey, dataToMac, opts.mac)
  }).then(function (macGood) {
    assert(macGood, 'Bad MAC')
    return aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext)
  }).then(function (msg) {
    return Buffer.from(new Uint8Array(msg))
  })
}

module.exports = {
  async decryptWithPrivateKey (privateKey, encrypted) {
    console.log(privateKey)
    const twoStripped = privateKey.replace(/^.{2}/gu, '')
    console.log(twoStripped)
    const encryptedBuffer = {
      iv: Buffer.from(encrypted.iv, 'hex'),
      ephemPublicKey: Buffer.from(encrypted.ephemPublicKey, 'hex'),
      ciphertext: Buffer.from(encrypted.ciphertext, 'hex'),
      mac: Buffer.from(encrypted.mac, 'hex'),
    }

    const decryptedBuffer = await decrypt(
      Buffer.from(twoStripped, 'hex'),
      encryptedBuffer,
    )
    return decryptedBuffer.toString()


  },
  async encryptWithPublicKey (receiverPublicKey, payload) {
    const pubString = `04${receiverPublicKey}`
    const encryptedBuffers = await encrypt(
      Buffer.from(pubString, 'hex'),
      Buffer.from(payload),
    )
    const encrypted = {
      iv: encryptedBuffers.iv.toString('hex'),
      ephemPublicKey: encryptedBuffers.ephemPublicKey.toString('hex'),
      ciphertext: encryptedBuffers.ciphertext.toString('hex'),
      mac: encryptedBuffers.mac.toString('hex'),
    }
    return encrypted
  },
}
