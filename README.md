# Eth-Sig-Util

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

### Release & Publishing

The project follows the same release process as the other libraries in the MetaMask organization. The GitHub Actions [`action-create-release-pr`](https://github.com/MetaMask/action-create-release-pr) and [`action-publish-release`](https://github.com/MetaMask/action-publish-release) are used to automate the release process; see those repositories for more information about how they work.

1. Choose a release version.

   - The release version should be chosen according to SemVer. Analyze the changes to see whether they include any breaking changes, new features, or deprecations, then choose the appropriate SemVer version. See [the SemVer specification](https://semver.org/) for more information.

2. If this release is backporting changes onto a previous release, then ensure there is a major version branch for that version (e.g. `1.x` for a `v1` backport release).

   - The major version branch should be set to the most recent release with that major version. For example, when backporting a `v1.0.2` release, you'd want to ensure there was a `1.x` branch that was set to the `v1.0.1` tag.

3. Trigger the [`workflow_dispatch`](https://docs.github.com/en/actions/reference/events-that-trigger-workflows#workflow_dispatch) event [manually](https://docs.github.com/en/actions/managing-workflow-runs/manually-running-a-workflow) for the `Create Release Pull Request` action to create the release PR.

   - For a backport release, the base branch should be the major version branch that you ensured existed in step 2. For a normal release, the base branch should be the main branch for that repository (which should be the default value).
   - This should trigger the [`action-create-release-pr`](https://github.com/MetaMask/action-create-release-pr) workflow to create the release PR.

4. Update the changelog to move each change entry into the appropriate change category ([See here](https://keepachangelog.com/en/1.0.0/#types) for the full list of change categories, and the correct ordering), and edit them to be more easily understood by users of the package.

   - Generally any changes that don't affect consumers of the package (e.g. lockfile changes or development environment changes) are omitted. Exceptions may be made for changes that might be of interest despite not having an effect upon the published package (e.g. major test improvements, security improvements, improved documentation, etc.).
   - Try to explain each change in terms that users of the package would understand (e.g. avoid referencing internal variables/concepts).
   - Consolidate related changes into one change entry if it makes it easier to explain.
   - Run `yarn auto-changelog validate --rc` to check that the changelog is correctly formatted.

5. Review and QA the release.

   - If changes are made to the base branch, the release branch will need to be updated with these changes and review/QA will need to restart again. As such, it's probably best to avoid merging other PRs into the base branch while review is underway.

6. Squash & Merge the release.

   - This should trigger the [`action-publish-release`](https://github.com/MetaMask/action-publish-release) workflow to tag the final release commit and publish the release on GitHub.

7. Publish the release on npm.

   - Be very careful to use a clean local environment to publish the release, and follow exactly the same steps used during CI.
   - Use `npm publish --dry-run` to examine the release contents to ensure the correct files are included. Compare to previous releases if necessary (e.g. using `https://unpkg.com/browse/[package name]@[package version]/`).
   - Once you are confident the release contents are correct, publish the release using `npm publish`.
