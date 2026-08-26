# Mutation campaign

This campaign verifies that noblefuzz catches deliberately incorrect Noble implementations. It mutates generated JavaScript in an isolated temporary copy of each checkout, runs the normal fuzzer bootstrap plus one generated case, and discards the copy. The checked-out repositories are never edited.

The audited revisions are:

| Checkout | Commit | Package version |
| --- | --- | --- |
| `noble-hashes` | `a169e0961b17c91025af1b4ecb7a14a10822b142` | 2.3.0 |
| `noble-ciphers` | `5053f9059ad9c6881583c900b6d212de4d5444b4` | 2.3.0 |
| `noble-curves` | `d5b95e489a418b1deb7862755dda5ef0db342acb` | 2.3.0 |
| `noble-post-quantum` | `cf4cc8f7babca87566711c0624ac20f398e2be79` | 0.7.0 |

Place those four clones beneath one directory using the checkout names above, then run `npm ci` and `npm run build` in each clone. Run the complete campaign and render its audit table with:

```sh
node noblefuzz/mutation/run.mjs \
  --root /path/to/clones \
  --output noblefuzz/mutation-report.json

node noblefuzz/mutation/report.mjs \
  --output noblefuzz/mutation-report.md \
  noblefuzz/mutation-report.json
```

Use `--project noble-curves` to select one project or `--id schnorr-tag-prefix` to debug one mutation. A single-selection run still exits nonzero because the audit policy requires at least 15 detected defect classes per selected project.

A mutant is detected only by a nonzero fuzzer exit caused by a startup check or saved testcase failure. A watchdog timeout, process timeout, signal, or zero exit is a survivor. The runner checks that every mutation site exists exactly where expected, that defect classes are unique per project, and that every selected project has at least 15 detected classes with no survivors.
