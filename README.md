# Eth-Sig-Util [![CircleCI](https://circleci.com/gh/MetaMask/eth-sig-util.svg?style=svg)](https://circleci.com/gh/MetaMask/eth-sig-util)

A small collection of ethereum signing functions.

You can find usage examples [here](https://github.com/metamask/test-dapp)

[Available on NPM](https://www.npmjs.com/package/eth-sig-util)

## Installation

```shell
npm install eth-sig-util --save
```

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

### signTypedData (privateKeyBuffer, msgParams)

Signs typed data as per [an early draft of EIP 712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca).

Data should be under `data` key of `msgParams`. The method returns prefixed signature.

### signTypedData_v3 (privateKeyBuffer, msgParams)

Signs typed data as per the published version of [EIP 712](https://github.com/ethereum/EIPs/pull/712).

Data should be under `data` key of `msgParams`. The method returns prefixed signature.

### signTypedData_v4 (privateKeyBuffer, msgParams)

Signs typed data as per an extension of the published version of [EIP 712](https://github.com/MetaMask/eth-sig-util/pull/54).

This extension adds support for arrays and recursive data types.

Data should be under `data` key of `msgParams`. The method returns prefixed signature.

### recoverTypedSignature ({data, sig})

Return address of a signer that did `signTypedData`.

Expects the same data that were used for signing. `sig` is a prefixed signature.

### recoverTypedSignature_V4 ({data, sig})

Return address of a signer that did `signTypedData` as per an extension of the published version of [EIP 712](https://github.com/MetaMask/eth-sig-util/pull/54).

This extension adds support for arrays and recursive data types.

Expects the same data that were used for signing. `sig` is a prefixed signature.

### typedSignatureHash (typedData)

Return hex-encoded hash of typed data params according to [EIP712](https://github.com/ethereum/EIPs/pull/712) schema.

### extractPublicKey (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded public key.

## Contributing

### Setup

- Install [Node.js](https://nodejs.org) version 12
  - If you are using [nvm](https://github.com/creationix/nvm#installation) (recommended) running `nvm use` will automatically choose the right node version for you.
- Install [Yarn v1](https://yarnpkg.com/en/docs/install)
- Run `yarn setup` to install dependencies and run any requried post-install scripts
  - **Warning:** Do not use the `yarn` / `yarn install` command directly. Use `yarn setup` instead. The normal install command will skip required post-install scripts, leaving your development environment in an invalid state.

### Testing and Linting

Run `yarn test` to run the tests.

Run `yarn lint` to run the linter, or run `yarn lint:fix` to run the linter and fix any automatically fixable issues.
