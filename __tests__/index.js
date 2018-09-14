const sigUtil = require('../')
const ethUtil = require('ethereumjs-util')

const typedData = {
  types: {
      EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' }
      ],
      Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' }
      ],
  },
  primaryType: 'Mail',
  domain: {
      name: 'Ether Mail',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
  },
  message: {
      from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
      },
      to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
      },
      contents: 'Hello, Bob!',
  },
}

test('normalize address lower cases', function () {
  expect.assertions(1)
  const initial = '0xA06599BD35921CfB5B71B4BE3869740385b0B306'
  const result = sigUtil.normalize(initial)
  expect(result).toBe(initial.toLowerCase())
})

test('normalize address adds hex prefix', function () {
  expect.assertions(1)
  const initial = 'A06599BD35921CfB5B71B4BE3869740385b0B306'
  const result = sigUtil.normalize(initial)
  expect(result).toBe('0x' + initial.toLowerCase())
})

test('normalize an integer converts to byte-pair hex', function () {
  expect.assertions(1)
  const initial = 1
  const result = sigUtil.normalize(initial)
  expect(result).toBe('0x01')
})

test('normalize an unsupported type throws', function () {
  expect.assertions(1)
  const initial = {}
  try {
    const result = sigUtil.normalize(initial)
    expect(false).toBeTruthy()
  } catch (e) {
    expect(e).toBeTruthy()
  }
})

test('personalSign and recover', function () {
  expect.assertions(1)
  const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b'
  console.log('for address ' + address)
  const privKeyHex = '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0'
  const privKey = new Buffer(privKeyHex, 'hex')
  const message = 'Hello, world!'
  const msgParams = { data: message }

  const signed = sigUtil.personalSign(privKey, msgParams)
  msgParams.sig = signed
  const recovered = sigUtil.recoverPersonalSignature(msgParams)

  expect(recovered).toBe(address)
})

test('personalSign and extractPublicKey', function () {
  expect.assertions(1)
  const privKeyHex = '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0'
  const pubKeyHex = '0x9e9e45b2ec5f070b4e26f57c7fedf647afa7a03e894789816fbd12fedc5acd79d0dfeea925688e177caccb8f5e09f0c289bbcfc7adb98d76f5f8c5259478903a'

  const privKey = new Buffer(privKeyHex, 'hex')
  const message = 'Hello, world!'
  const msgParams = { data: message }

  const signed = sigUtil.personalSign(privKey, msgParams)
  msgParams.sig = signed
  const publicKey = sigUtil.extractPublicKey(msgParams)

  expect(publicKey).toBe(pubKeyHex)
})

test('signTypedDataLegacy and recoverTypedSignatureLegacy - single message', function () {
  expect.assertions(1)
  const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b'
  const privKeyHex = '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0'

  const privKey = Buffer.from(privKeyHex, 'hex')

  const typedData = [
    {
      type: 'string',
      name: 'message',
      value: 'Hi, Alice!'
    }
  ]

  const msgParams = { data: typedData }

  const signature = sigUtil.signTypedDataLegacy(privKey, msgParams)
  const recovered = sigUtil.recoverTypedSignatureLegacy({ data: msgParams.data, sig: signature })

  expect(address).toBe(recovered)
})

test('signTypedDataLegacy and recoverTypedSignatureLegacy - multiple messages', function () {
  expect.assertions(1)
  const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b'
  const privKeyHex = '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0'

  const privKey = Buffer.from(privKeyHex, 'hex')

  const typedData = [
    {
      type: 'string',
      name: 'message',
      value: 'Hi, Alice!'
    },
    {
      type: 'uint8',
      name: 'value',
      value: 10
    },
  ]

  const msgParams = { data: typedData }

  const signature = sigUtil.signTypedDataLegacy(privKey, msgParams)
  const recovered = sigUtil.recoverTypedSignatureLegacy({ data: msgParams.data, sig: signature })

  expect(address).toBe(recovered)
})

test('typedSignatureHash - single value', function () {
  expect.assertions(1)
  const typedData = [
    {
      type: 'string',
      name: 'message',
      value: 'Hi, Alice!'
    }
  ]
  const hash = sigUtil.typedSignatureHash(typedData)
  expect(hash).toBe('0x14b9f24872e28cc49e72dc104d7380d8e0ba84a3fe2e712704bcac66a5702bd5')
})

test('typedSignatureHash - multiple values', function () {
  expect.assertions(1)
  const typedData = [
    {
      type: 'string',
      name: 'message',
      value: 'Hi, Alice!'
    },
    {
      type: 'uint8',
      name: 'value',
      value: 10
    },
  ]
  const hash = sigUtil.typedSignatureHash(typedData)
  expect(hash).toBe('0xf7ad23226db5c1c00ca0ca1468fd49c8f8bbc1489bc1c382de5adc557a69c229')
})

test('typedSignatureHash - bytes', function () {
    expect.assertions(1)
    const typedData = [
        {
            type: 'bytes',
            name: 'message',
            value: '0xdeadbeaf'
        }
    ]
    const hash = sigUtil.typedSignatureHash(typedData)
    expect(hash).toBe('0x6c69d03412450b174def7d1e48b3bcbbbd8f51df2e76e2c5b3a5d951125be3a9')
})

typedSignatureHashThrowsTest({
    testLabel: 'empty array',
    argument: []
})

typedSignatureHashThrowsTest({
    testLabel: 'not array',
    argument: 42
})

typedSignatureHashThrowsTest({
    testLabel: 'null',
    argument: null
})

typedSignatureHashThrowsTest({
  testLabel: 'wrong type',
  argument: [
    {
      type: 'jocker',
      name: 'message',
      value: 'Hi, Alice!'
    }
  ]
})

typedSignatureHashThrowsTest({
  testLabel: 'no type',
  argument: [
    {
      name: 'message',
      value: 'Hi, Alice!'
    }
  ]
})

typedSignatureHashThrowsTest({
  testLabel: 'no name',
  argument: [
    {
      type: 'string',
      value: 'Hi, Alice!'
    }
  ]
})

// personal_sign was declared without an explicit set of test data
// so I made a script out of geth's internals to create this test data
// https://gist.github.com/kumavis/461d2c0e9a04ea0818e423bb77e3d260

signatureTest({
  testLabel: 'personalSign - kumavis fml manual test I',
  // "hello world"
  message: '0x68656c6c6f20776f726c64',
  signature: '0xce909e8ea6851bc36c007a0072d0524b07a3ff8d4e623aca4c71ca8e57250c4d0a3fc38fa8fbaaa81ead4b9f6bd03356b6f8bf18bccad167d78891636e1d69561b',
  addressHex: '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb',
  privateKey: new Buffer('6969696969696969696969696969696969696969696969696969696969696969', 'hex'),
})

signatureTest({
  testLabel: 'personalSign - kumavis fml manual test II',
  // some random binary message from parity's test
  message: '0x0cc175b9c0f1b6a831c399e26977266192eb5ffee6ae2fec3ad71c777531578f',
  signature: '0x9ff8350cc7354b80740a3580d0e0fd4f1f02062040bc06b893d70906f8728bb5163837fd376bf77ce03b55e9bd092b32af60e86abce48f7b8d3539988ee5a9be1c',
  addressHex: '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb',
  privateKey: new Buffer('6969696969696969696969696969696969696969696969696969696969696969', 'hex'),
})

signatureTest({
  testLabel: 'personalSign - kumavis fml manual test III',
  // random binary message data and pk from parity's test
  // https://github.com/ethcore/parity/blob/5369a129ae276d38f3490abb18c5093b338246e0/rpc/src/v1/tests/mocked/eth.rs#L301-L317
  // note: their signature result is incorrect (last byte moved to front) due to a parity bug
  message: '0x0cc175b9c0f1b6a831c399e26977266192eb5ffee6ae2fec3ad71c777531578f',
  signature: '0xa2870db1d0c26ef93c7b72d2a0830fa6b841e0593f7186bc6c7cc317af8cf3a42fda03bd589a49949aa05db83300cdb553116274518dbe9d90c65d0213f4af491b',
  addressHex: '0xe0da1edcea030875cd0f199d96eb70f6ab78faf2',
  privateKey: new Buffer('4545454545454545454545454545454545454545454545454545454545454545', 'hex'),
})

function signatureTest(opts) {
  test(opts.testLabel, function () {
    expect.assertions(2)

    const address = opts.addressHex
    const privKey = opts.privateKey
    const message = opts.message
    const msgParams = { data: message }

    const signed = sigUtil.personalSign(privKey, msgParams)
    expect(signed).toBe(opts.signature)

    msgParams.sig = signed
    const recovered = sigUtil.recoverPersonalSignature(msgParams)

    expect(recovered).toBe(address)
  })
}

function typedSignatureHashThrowsTest(opts) {
  const label = `typedSignatureHash - malformed arguments - ${opts.testLabel}`
  test(label, function () {
    expect.assertions(1)

    const argument = opts.argument

    expect(() => {
      sigUtil.typedSignatureHash(argument)
    }).toThrow()
  })
}

const bob = { 
  ethereumPrivateKey: '7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816',
  encryptionPrivateKey: 'flN07C7w2Rdhpucv349qxmVRm/322gojKc8NgEUUuBY=',
  encryptionPublicKey: 'C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=' }

const secretMessage = {data:'My name is Satoshi Buterin'};

const encryptedData = { version: 'x25519-xsalsa20-poly1305',
nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' };

test("Getting bob's encryptionPublicKey", async () => {
  expect.assertions(1);

  const result = await sigUtil.getEncryptionPublicKey(bob.ethereumPrivateKey)
  expect(result).toBe(bob.encryptionPublicKey);
});

//encryption test
test("Alice encrypts message with bob's encryptionPublicKey", async () => {
  

  expect.assertions(4);

  const result = await sigUtil.encrypt(
    bob.encryptionPublicKey,
    secretMessage,
    'x25519-xsalsa20-poly1305'
  );

  console.log("RESULT", result)

  expect(result.version).toBeTruthy();
  expect(result.nonce).toBeTruthy();
  expect(result.ephemPublicKey).toBeTruthy();
  expect(result.ciphertext).toBeTruthy();

});

// decryption test
test("Bob decrypts message that Alice sent to him", () => {
  expect.assertions(1);

  const result = sigUtil.decrypt(encryptedData, bob.ethereumPrivateKey);
  expect(result).toBe(secretMessage.data);
});

test('Decryption failed because version is wrong or missing', () => {
  expect.assertions(1)

  const badVersionData = { version: 'x256k1-aes256cbc',
  nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
  ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
  ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' };

  expect(function() { sigUtil.decrypt(badVersionData, bob.ethereumPrivateKey)}).toThrow()
});

test('Decryption failed because nonce is wrong or missing', () => {
  expect.assertions(1);

    //encrypted data
  const badNonceData = { version: 'x25519-xsalsa20-poly1305',
  nonce: '',
  ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
  ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' };

  expect(function() { sigUtil.decrypt(badNonceData, bob.ethereumPrivateKey)}).toThrow()

});

test('Decryption failed because ephemPublicKey is wrong or missing', () => {
  expect.assertions(1);

    //encrypted data
  const badEphemData = { version: 'x25519-xsalsa20-poly1305',
  nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
  ephemPublicKey: 'FFFF/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
  ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' };

  expect(function() { sigUtil.decrypt(badEphemData, bob.ethereumPrivateKey)}).toThrow()
});

test('Decryption failed because cyphertext is wrong or missing', async () => {
  expect.assertions(1);

    //encrypted data
  const badCypherData = { version: 'x25519-xsalsa20-poly1305',
  nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
  ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
  ciphertext: 'ffffff/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy' };

  expect(function() { sigUtil.decrypt(badEphemData, bob.ethereumPrivateKey)}).toThrow()
});

test("Decryption fails because you are not the recipient", () => {
  expect.assertions(1);

  expect(function() { sigUtil.decrypt(encryptedData, alice.ethereumPrivateKey)}).toThrow()
});

test('signedTypeData', () => {
  expect.assertions(8)
  const utils = sigUtil.TypedDataUtils
  const privateKey = ethUtil.sha3('cow')
  const address = ethUtil.privateToAddress(privateKey)
  const sig = sigUtil.signTypedData(privateKey, { data: typedData })

  expect(utils.encodeType('Mail', typedData.types)).toBe(
    'Mail(Person from,Person to,string contents)Person(string name,address wallet)'
  )
  expect(ethUtil.bufferToHex(utils.hashType('Mail', typedData.types))).toBe('0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2')
  expect(
    ethUtil.bufferToHex(utils.encodeData(typedData.primaryType, typedData.message, typedData.types))
  ).toBe(
    '0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8'
  )
  expect(
    ethUtil.bufferToHex(utils.hashStruct(typedData.primaryType, typedData.message, typedData.types))
  ).toBe('0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e')
  expect(
    ethUtil.bufferToHex(utils.hashStruct('EIP712Domain', typedData.domain, typedData.types))
  ).toBe('0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f')
  expect(ethUtil.bufferToHex(utils.sign(typedData))).toBe('0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2')
  expect(ethUtil.bufferToHex(address)).toBe('0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826')
  expect(sig).toBe(
    '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c'
  )
})
