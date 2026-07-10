# CRA Evidence SAST Rule Pack

A starter set of Opengrep rules for the `code-check` command.

## Scope

These rules detect a narrow set of high-signal patterns in Python, JavaScript,
TypeScript, and Go source files.

### Python (`python.yaml`) -- structural patterns

- SQL injection via string formatting in `execute()`
- `subprocess` called with `shell=True`
- `yaml.load()` without an explicit Loader
- `pickle.loads()` / `pickle.load()`

### Python (`python-taint.yaml`) -- intrafile taint tracking

These rules use Opengrep taint mode to follow untrusted input (Flask
`request.*` and `input()`) through local variables to dangerous sinks:

- Untrusted input reaching a SQL `execute()` query string (CWE-89)
- Untrusted input reaching `subprocess` with `shell=True` (CWE-78)
- Untrusted input reaching `eval()` or `exec()` (CWE-95)

### JavaScript / TypeScript (`javascript.yaml`)

- `eval()` called with any argument
- `child_process.exec` / `execSync` called with a concatenated command string

### Go (`go.yaml`)

- MD5 or SHA-1 used for security purposes (CWE-327)
- `tls.Config` with `InsecureSkipVerify: true` (CWE-295)
- HMAC output compared with `bytes.Equal()` -- timing side-channel (CWE-208)
- `hmac.New()` receiving a closure that returns a shared hash instance (CWE-327)
- 64-bit `ParseInt`/`ParseUint`/`Atoi` result downcast to `int32`/`uint32`
  without a range check (CWE-190)
- Mismatched mutex lock/unlock pairs (CWE-667)

The Go rules derived from dgryski/semgrep-go are used under the MIT license;
each carries an `origin` field in its metadata.

The pack is intentionally narrow. It is a starting point for review, not a
complete security audit. A clean scan does not prove the absence of
vulnerabilities. Use a dedicated SAST tool for broader coverage.

## What these rules do not cover

- Secrets and credentials (see `secrets-check`)
- Infrastructure-as-code misconfigurations (see `config-check`)
- Runtime vulnerabilities, dependency CVEs, or supply-chain issues

## License

MIT. See LICENSE in this directory.
