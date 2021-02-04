module.exports = {
  root: true,
  extends: [
    '@metamask/eslint-config',
    '@metamask/eslint-config/config/nodejs',
  ],
  parserOptions: {
    ecmaVersion: '2018',
    sourceType: 'script',
  },
  rules: {
    'camelcase': ['error', {
      'allow': [
        'nacl_decodeHex',
        'recoverTypedSignature_v4',
        'signTypedData_v4',
      ],
    }],
    'no-param-reassign': 'off',
  },
}
