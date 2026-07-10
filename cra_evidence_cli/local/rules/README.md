# CRA Evidence SAST Rule Pack

A starter set of Opengrep rules for the `code-check` command.

## Scope

These rules detect a narrow set of high-signal patterns in Python, JavaScript,
TypeScript, and Go source files. Each rule lives in its own file under
`<language>/<subcategory>/<rule-id>.yaml`.

### Python (`python/`) -- structural patterns

- SQL injection via string formatting in `execute()`
- `subprocess` called with `shell=True`
- `yaml.load()` without an explicit Loader
- `pickle.loads()` / `pickle.load()`

### Python (`python/injection/`) -- intrafile taint tracking

These rules use Opengrep taint mode to follow untrusted input (Flask
`request.*` and `input()`) through local variables to dangerous sinks:

- Untrusted input reaching a SQL `execute()` query string (CWE-89)
- Untrusted input reaching `subprocess` with `shell=True` (CWE-78)
- Untrusted input reaching `eval()` or `exec()` (CWE-95)

### JavaScript / TypeScript (`javascript/`)

- `eval()` called with any argument
- `child_process.exec` / `execSync` called with a concatenated command string

### Go (`go/`)

- MD5 or SHA-1 used for security purposes (CWE-327)
- `tls.Config` with `InsecureSkipVerify: true` (CWE-295)
- HMAC output compared with `bytes.Equal()` -- timing side-channel (CWE-208)
- `hmac.New()` receiving a closure that returns a shared hash instance (CWE-327)
- 64-bit `ParseInt`/`ParseUint`/`Atoi` result downcast to `int32`/`uint32`
  without a range check (CWE-190)
- Mismatched mutex lock/unlock pairs (CWE-667)

The Go rules derived from dgryski/semgrep-go are used under the MIT license;
each carries an `origin` field in its metadata.

### Python web frameworks

Framework-specific rules authored from CWE, OWASP, and the frameworks' own
documentation. Taint-mode rules follow untrusted `request.*` input to a sink
within a single file; pattern-mode rules match a dangerous call or a risky
configuration form.

Flask (`python/flask/`):

- `render_template_string()` built from untrusted input -- template injection (CWE-1336)
- `send_file()` with a request-controlled path -- path traversal (CWE-22)
- `redirect()` built from request input -- open redirect (CWE-601)
- `debug=True` -- interactive debugger exposed (CWE-489)
- Hardcoded `SECRET_KEY` literal (CWE-798)
- `SESSION_COOKIE_SECURE` / `SESSION_COOKIE_HTTPONLY` set to `False` (CWE-614, CWE-1004)
- CORS wildcard origin with credentials (CWE-942)
- Flask-WTF CSRF protection disabled (CWE-352)
- `Markup()` built from untrusted input -- XSS (CWE-79)
- Request password compared with `==` instead of a verification helper (CWE-256)
- `jsonify()` reflecting a whole request or environment object (CWE-200)

Django (`python/django/`):

- `raw()` / `RawSQL` / `.extra()` with interpolated SQL (CWE-89)
- `mark_safe()` / `format_html()` misuse on untrusted input (CWE-79)
- `HttpResponse` body built from untrusted formatted input (CWE-79). The rule
  cannot read the `content_type`, so a formatted non-HTML response (for example
  `text/plain`) may still be flagged.
- `redirect()` / `HttpResponseRedirect` from request input (CWE-601)
- Request input reaching `open()` through a computed path -- path traversal (CWE-22)
- `signing.loads()` / `unsign_object()` with a pickle serializer (CWE-502)
- `@csrf_exempt` on a view (CWE-352)
- Settings hardening: `DEBUG=True`, hardcoded `SECRET_KEY`, `ALLOWED_HOSTS=['*']`,
  insecure session cookie, `SECURE_SSL_REDIRECT=False` (CWE-489, CWE-798, CWE-16,
  CWE-614, CWE-319)

SQLAlchemy (`python/sqlalchemy/`):

- `text()` / `exec_driver_sql()` / `literal_column()` with interpolated input (CWE-89)
- An interpolated string passed directly to `.order_by()` / `.group_by()` (CWE-89).
  Current SQLAlchemy treats a bare string here as a label reference and requires
  `text()` for raw SQL; this rule targets the legacy string-criterion form.

JWT (`python/jwt/`):

- `decode()` with signature verification disabled (CWE-347)
- `algorithms` allowlist containing `none` (CWE-347)
- `decode()` with no `algorithms` argument (CWE-347)
- Hardcoded JWT key literal (CWE-798)

The pack is intentionally narrow. It is a starting point for review, not a
complete security audit. A clean scan does not prove the absence of
vulnerabilities. Use a dedicated SAST tool for broader coverage.

## What these rules do not cover

- General-purpose secret scanning (see `secrets-check`). The JWT and framework
  hardcoded-key rules above target a specific committed-key pattern, not a full
  credential scan.
- Infrastructure-as-code misconfigurations (see `config-check`)
- Runtime vulnerabilities, dependency CVEs, or supply-chain issues

## License

MIT. See LICENSE in this directory.
