module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // GitHub truncates subjects over 72 characters, and squash-merging appends
    // " (#NNNN)", so the authored subject gets 64.
    'header-max-length': [2, 'always', 64],
    'body-no-subject-line': [2, 'always'],
  },
  plugins: [
    {
      rules: {
        // A squash-merged PR body that opens with a conventional subject makes
        // release-please list the commit twice.
        'body-no-subject-line': ({ body }) => [
          !/^[a-z]+(\([^)]+\))?!?: /.test((body || '').trimStart()),
          'body must not begin with a conventional subject line',
        ],
      },
    },
  ],
};
