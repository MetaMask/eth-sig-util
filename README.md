# Eth-Sig-Util [![CircleCI](https://circleci.com/gh/MetaMask/eth-sig-util.svg?style=svg)](https://circleci.com/gh/MetaMask/eth-sig-util)

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-sig-util.svg)](https://greenkeeper.io/)

A small collection of ethereum signing functions.

You can find usage examples [here](https://github.com/flyswatter/js-eth-personal-sign-examples)

[Available on NPM](https://www.npmjs.com/package/eth-sig-util)

## Supported Signing Methods

Currently there is only one supported signing protocol. More will be added as standardized.

- Personal Sign (`personal_sign`) [geth thread](https://github.com/ethereum/go-ethereum/pull/2940)


## Installation

```
npm install eth-sig-util --save
```

## Typed Signature Versions

| Version | Explanation                                                  |
| ------- | ------------------------------------------------------------ |
| `V1`    | This early version of the spec lacked some later security improvements, and should generally be neglected in favor of `V3`. |
| `V3`    | Currently represents the latest version of the [EIP 712 spec](https://eips.ethereum.org/EIPS/eip-712), making it the most secure method for signing cheap-to-verify data on-chain that we have yet. |
| `V4`    | Currently represents the latest version of the [EIP 712 spec](https://eips.ethereum.org/EIPS/eip-712), with added support for arrays and with a breaking fix for the way structs are encoded |




## Methods

### concatSig(v, r, s)

All three arguments should be provided as buffers.

Returns a continuous, hex-prefixed hex value for the signature, suitable for inclusion in a JSON transaction's data field.

### normalize(address)

Takes an address of either upper or lower case, with or without a hex prefix, and returns an all-lowercase, hex-prefixed address, suitable for submitting to an ethereum provider.

### personalSign (privateKeyBuffer, msgParams)

msgParams should have a `data` key that is hex-encoded data to sign.

Returns the prefixed signature expected for calls to `eth.personalSign`.

### recoverPersonalSignature (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded sender address.

### signTypedData (privateKeyBuffer, msgParams, typedSignatureVersion)

Signs typed data as per [an early draft of EIP 712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca).

Data should be under `data` key of `msgParams`. The method returns prefixed signature.

### recoverTypedSignature ({data, sig}, typedSignatureVersion)

Return address of a signer that did `signTypedData`.

Expects the same data that were used for signing. `sig` is a prefixed signature.

### typedSignatureHash (typedData)

Return hex-encoded hash of typed data params according to [EIP712](https://github.com/ethereum/EIPs/pull/712) schema.

### extractPublicKey (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded public key.
