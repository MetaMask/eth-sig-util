module.exports = {
  root: true,
  extends: ['@metamask/eslint-config', '@metamask/eslint-config-nodejs'],
  overrides: [
    {
      files: ['*.ts'],
      extends: ['@metamask/eslint-config-typescript'],
    },
    {
      files: ['*.test.ts'],
      extends: ['@metamask/eslint-config-jest'],
    },
  ],
  rules: {
    camelcase: [
      'error',
      {
        allow: [
          'nacl_decodeHex',
          'recoverTypedSignature_v4',
          'signTypedData_v4',
        ],
      },
    ],
    'no-param-reassign': 'off',
  },
  ignorePatterns: ['!.eslintrc.js', 'test/*.js', 'dist'],
};
