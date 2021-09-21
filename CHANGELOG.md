# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0]
### Uncategorized
- Replace README API docs with generated docs ([#213](https://github.com/MetaMask/eth-sig-util/pull/213))
- Bump tmpl from 1.0.4 to 1.0.5 ([#216](https://github.com/MetaMask/eth-sig-util/pull/216))
- Add subpath exports ([#214](https://github.com/MetaMask/eth-sig-util/pull/214))
- Use hex data for `personalSign` tests ([#215](https://github.com/MetaMask/eth-sig-util/pull/215))
- Split into multiple modules ([#211](https://github.com/MetaMask/eth-sig-util/pull/211))
- Fix missing parameter descriptions in docs ([#212](https://github.com/MetaMask/eth-sig-util/pull/212))
- Add TypeDoc docs ([#207](https://github.com/MetaMask/eth-sig-util/pull/207))
- Add validation to check that parameters aren't nullish ([#205](https://github.com/MetaMask/eth-sig-util/pull/205))
- Add ESLint JSDoc rules. ([#206](https://github.com/MetaMask/eth-sig-util/pull/206))
- Use options bag parameters rather than MsgParams type ([#204](https://github.com/MetaMask/eth-sig-util/pull/204))
- Add `signTypedData` version validation ([#201](https://github.com/MetaMask/eth-sig-util/pull/201))
- Simplify function type signatures ([#198](https://github.com/MetaMask/eth-sig-util/pull/198))
- Reorganize old tests ([#202](https://github.com/MetaMask/eth-sig-util/pull/202))
- Remove redundant dependencies from lockfile ([#203](https://github.com/MetaMask/eth-sig-util/pull/203))
- Remove `signTypedData` version `V2` ([#200](https://github.com/MetaMask/eth-sig-util/pull/200))
- Fix Node.js v16 CI job ([#199](https://github.com/MetaMask/eth-sig-util/pull/199))
- Consolidate the data encoding for `signTypedData` V3 and V4 ([#197](https://github.com/MetaMask/eth-sig-util/pull/197))
- Bump tar from 6.1.5 to 6.1.11 ([#196](https://github.com/MetaMask/eth-sig-util/pull/196))
- Update `ethereumjs-util` from v5 to v6 ([#195](https://github.com/MetaMask/eth-sig-util/pull/195))
- Fix `concatSig` parameter and handling of return value ([#194](https://github.com/MetaMask/eth-sig-util/pull/194))
- Add `typedSignatureHash` tests ([#187](https://github.com/MetaMask/eth-sig-util/pull/187))
- Add `signTypedData` and `recoverTypedSignature` tests ([#185](https://github.com/MetaMask/eth-sig-util/pull/185))
- Reorganize `TypedDataUtils` unbound tests ([#188](https://github.com/MetaMask/eth-sig-util/pull/188))
- Fix `eip712Hash` tests that included data ([#184](https://github.com/MetaMask/eth-sig-util/pull/184))
- Add solidity types to schema ([#189](https://github.com/MetaMask/eth-sig-util/pull/189))
- Fix `typedSignatureHash` documentation ([#186](https://github.com/MetaMask/eth-sig-util/pull/186))
- Add `personalSign` tests ([#182](https://github.com/MetaMask/eth-sig-util/pull/182))
- Add inline docs for all public functions ([#181](https://github.com/MetaMask/eth-sig-util/pull/181))
- Add `.prettierrc.js` ([#183](https://github.com/MetaMask/eth-sig-util/pull/183))
- Add `salt` to the EIP-712 `domain` type ([#176](https://github.com/MetaMask/eth-sig-util/pull/176))
- Add `TypedDataUtils.eip712Hash` unit tests ([#173](https://github.com/MetaMask/eth-sig-util/pull/173))
- Add docs and tests for `normalize` ([#178](https://github.com/MetaMask/eth-sig-util/pull/178))
- Add `TypedDataUtils.hashType` tests ([#171](https://github.com/MetaMask/eth-sig-util/pull/171))
- Add `TypedDataUtils.hashStruct` tests ([#170](https://github.com/MetaMask/eth-sig-util/pull/170))
- Improve padWithZeroes implementation and add tests ([#180](https://github.com/MetaMask/eth-sig-util/pull/180))
- Simplify findTypeDependencies implementation ([#179](https://github.com/MetaMask/eth-sig-util/pull/179))
- Add `concatSig` docs and unit tests ([#177](https://github.com/MetaMask/eth-sig-util/pull/177))
- Add `TypedDataUtils.sanitizeData` tests ([#172](https://github.com/MetaMask/eth-sig-util/pull/172))
- Add `TypedDataUtils.findTypeDependencies` tests ([#169](https://github.com/MetaMask/eth-sig-util/pull/169))
- Export functions directly rather than in object ([#175](https://github.com/MetaMask/eth-sig-util/pull/175))
- Improve`TypedDataUtils.eip712Hash` inline docs ([#174](https://github.com/MetaMask/eth-sig-util/pull/174))
- Add `TypedDataUtils.encodeType` tests ([#167](https://github.com/MetaMask/eth-sig-util/pull/167))
- Add encode data tests ([#164](https://github.com/MetaMask/eth-sig-util/pull/164))
- Bump path-parse from 1.0.6 to 1.0.7 ([#168](https://github.com/MetaMask/eth-sig-util/pull/168))
- Bump tar from 6.1.0 to 6.1.5 ([#166](https://github.com/MetaMask/eth-sig-util/pull/166))
- Add `build:clean` script and use before publishing ([#153](https://github.com/MetaMask/eth-sig-util/pull/153))
- Allow `TypedDataUtils` to be called unbound ([#152](https://github.com/MetaMask/eth-sig-util/pull/152))
- Bump @metamask/auto-changelog from 2.4.0 to 2.5.0 ([#165](https://github.com/MetaMask/eth-sig-util/pull/165))
- Migrate tests from tape to Jest ([#161](https://github.com/MetaMask/eth-sig-util/pull/161))
- Consolidate `signTypedData` and `recoverTypedSignature` functions ([#156](https://github.com/MetaMask/eth-sig-util/pull/156))
- Move package under `@metamask` npm organization ([#162](https://github.com/MetaMask/eth-sig-util/pull/162))
- Bump glob-parent from 5.1.1 to 5.1.2 ([#160](https://github.com/MetaMask/eth-sig-util/pull/160))
- Fix various mistakes in the README API documentation ([#157](https://github.com/MetaMask/eth-sig-util/pull/157))
- Update minimum `teetnacl-util` version ([#155](https://github.com/MetaMask/eth-sig-util/pull/155))
- Remove CircleCI badge from README ([#154](https://github.com/MetaMask/eth-sig-util/pull/154))
- Remove browser tests ([#158](https://github.com/MetaMask/eth-sig-util/pull/158))
- Use standard TypeScript config ([#159](https://github.com/MetaMask/eth-sig-util/pull/159))
- Fix encoding and hash function versions used in unit tests ([#151](https://github.com/MetaMask/eth-sig-util/pull/151))
- Add release automation actions ([#150](https://github.com/MetaMask/eth-sig-util/pull/150))
- Add `@metamask/auto-changelog` ([#149](https://github.com/MetaMask/eth-sig-util/pull/149))
- rename TypedDataUtils.sign to TypedDataUtils.eip712Hash ([#104](https://github.com/MetaMask/eth-sig-util/pull/104))
- Migrate from CircleCI to GitHub Actions ([#148](https://github.com/MetaMask/eth-sig-util/pull/148))
- Add `@lavamoat/allow-scripts` ([#147](https://github.com/MetaMask/eth-sig-util/pull/147))
- Update ESLint config to v7.0.1 ([#144](https://github.com/MetaMask/eth-sig-util/pull/144))
- Add test for sign typed data with bytes ([#146](https://github.com/MetaMask/eth-sig-util/pull/146))
- Add Dependabot config ([#145](https://github.com/MetaMask/eth-sig-util/pull/145))
- Upgrading sub-dep xmlhttprequest-ssl -> ^1.6.2 ([#141](https://github.com/MetaMask/eth-sig-util/pull/141))
- Bump hosted-git-info from 2.8.8 to 2.8.9 ([#140](https://github.com/MetaMask/eth-sig-util/pull/140))
- Bump lodash from 4.17.19 to 4.17.21 ([#139](https://github.com/MetaMask/eth-sig-util/pull/139))
- fix: upgrade ethereumjs-util from 5.2.0 to 5.2.1 ([#138](https://github.com/MetaMask/eth-sig-util/pull/138))
- Repo standardization ([#136](https://github.com/MetaMask/eth-sig-util/pull/136))
- Bump elliptic from 6.5.3 to 6.5.4 ([#133](https://github.com/MetaMask/eth-sig-util/pull/133))
- doc/readme - update link to usage example repo

## [3.0.1] - 2021-02-04
### Changed
- Update `ethereumjs-abi` ([#96](https://github.com/MetaMask/eth-sig-util/pull/96))
- Remove unused dependencies ([#117](https://github.com/MetaMask/eth-sig-util/pull/117))
- Update minimum `tweetnacl` to latest version ([#123](https://github.com/MetaMask/eth-sig-util/pull/123))

## [3.0.0] - 2020-11-09
### Changed
- [**BREAKING**] Migrate to TypeScript ([#74](https://github.com/MetaMask/eth-sig-util/pull/74))
- Fix package metadata ([#81](https://github.com/MetaMask/eth-sig-util/pull/81)
- Switch from Node.js v8 to Node.js v10 ([#76](https://github.com/MetaMask/eth-sig-util/pull/77) and [#80](https://github.com/MetaMask/eth-sig-util/pull/80))


## [2.5.4] - 2021-02-04
### Changed
- Update `ethereumjs-abi` ([#121](https://github.com/MetaMask/eth-sig-util/pull/121))
- Remove unused dependencies ([#120](https://github.com/MetaMask/eth-sig-util/pull/120))
- Update minimum `tweetnacl` to latest version ([#124](https://github.com/MetaMask/eth-sig-util/pull/124))

## [2.5.3] - 2020-03-16 [WITHDRAWN]
### Changed
- [**BREAKING**] Migrate to TypeScript ([#74](https://github.com/MetaMask/eth-sig-util/pull/74))
- Fix package metadata ([#81](https://github.com/MetaMask/eth-sig-util/pull/81)
- Switch from Node.js v8 to Node.js v10 ([#76](https://github.com/MetaMask/eth-sig-util/pull/77) and [#80](https://github.com/MetaMask/eth-sig-util/pull/80))

[Unreleased]: https://github.com/MetaMask/eth-sig-util/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/MetaMask/eth-sig-util/compare/v3.0.1...v4.0.0
[3.0.1]: https://github.com/MetaMask/eth-sig-util/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/MetaMask/eth-sig-util/compare/v2.5.4...v3.0.0
[2.5.4]: https://github.com/MetaMask/eth-sig-util/compare/v2.5.3...v2.5.4
[2.5.3]: https://github.com/MetaMask/eth-sig-util/releases/tag/v2.5.3
