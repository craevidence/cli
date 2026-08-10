# CRA Evidence SAST Rule Pack

A starter set of Opengrep rules for the `code-check` command.

## Scope

These rules detect a focused set of high-signal patterns. The 43 Python rules
are enabled by default. Go, JavaScript/TypeScript, Java, C, C++, Rust, PHP, and
C# contain 50 experimental rules and require `--include-experimental`.
Each rule lives in its own file under
`<language>/<subcategory>/<rule-id>.yaml`. This tiering states the evidence
boundary; it does not imply complete SAST coverage for any language.

### Python (`python/`) -- structural patterns

- SQL injection via string formatting in `execute()`
- `subprocess` called with `shell=True`
- `yaml.load()` without a loader or with `Loader` / `UnsafeLoader`
- `pickle.loads()` / `pickle.load()`

### Python (`python/injection/`) -- intrafile taint tracking

These rules use Opengrep taint mode to follow untrusted input (Flask
`request.*` and `input()`) through local variables to dangerous sinks:

- Untrusted input reaching a SQL `execute()` query string (CWE-89)
- Untrusted input reaching `subprocess` with `shell=True`, `os.system()`, or
  `os.popen()` (CWE-78)
- Untrusted input reaching `eval()` or `exec()` (CWE-95)

### JavaScript / TypeScript (`javascript/`)

Experimental. The broad `eval()` review rule is warning-level because a call can
execute a constant or internally generated string; it is not proof of injection.

- `eval()` called with any argument
- `child_process.exec` / `execSync` called with a concatenated command string

### Go (`go/`)

Experimental. These rules match syntax and do not infer security intent. In
particular, the weak-hash rule also reports non-security checksums, the integer
rule does not recognize every valid range-check spelling, and the lock rule is
sensitive to statement layout. Those measured limitations block default use.

- MD5 or SHA-1 use that requires review for security intent (CWE-327)
- `tls.Config` with `InsecureSkipVerify: true` (CWE-295)
- HMAC output compared with `bytes.Equal()` -- timing side-channel (CWE-208)
- `hmac.New()` receiving a closure that returns a shared hash instance (CWE-327)
- `ParseInt`/`ParseUint`/`Atoi` result downcast to `int32`/`uint32` when
  the rule cannot establish a recognized safe range check (CWE-190)
- Mismatched mutex lock/unlock pairs (CWE-667)

The integer downcast rule recognizes a bounds check by its shape and position in
the source, not by control flow. It does not verify that the check runs before
the cast on every path. A check nested inside another conditional, placed in a
loop that may not execute, or written inside a closure or a deferred function
suppresses the finding just as a check on the straight-line path does, so a
truncation that the check does not actually prevent is missed. This code returns
705032705 for the input 5000000001 when `strict` is false, and the rule stays
silent:

```go
v, _ := strconv.ParseUint(s, 10, 64)
if strict {
    if v > math.MaxUint32 {
        return 0
    }
}
return uint32(v)
```

The same holds for the statement that rejects an out-of-range value: it counts
even when it is itself nested inside a further conditional in the guard body, so
a guard that only sometimes returns still suppresses the finding. Read a clean
run of this rule as evidence that no unguarded downcast was found in the shapes
it matches, not as evidence that every downcast in the file is guarded.

The Go rules derived from dgryski/semgrep-go are used under the MIT license;
each carries an `origin` field in its metadata.

### Java (`java/`)

Experimental: eight focused rules, not general Java SAST coverage. Each rule
publishes its exact detection scope and engine limitations in its metadata.

- Servlet request data reaching operating system command execution (CWE-78)
- Servlet request data reaching JDBC query text (CWE-89)
- Servlet request data reaching filesystem paths (CWE-22)
- Servlet request data controlling outbound URLs (CWE-918)
- Native Java object deserialization (CWE-502)
- XML parser settings that permit DTDs or external entities (CWE-611)
- MD2, MD5, or SHA-1 message digests selected by a literal or same-class static-final
  algorithm name (CWE-328)
- TLS hostname verifiers that accept every hostname (CWE-297)

On OWASP Benchmark Java commit `007786f86b965a9ea8e4a7613baa5f90adbbd611`,
the currently applicable rules detect 172 of 660 vulnerable cases (26.1%) and
produce 24 findings on benchmark-safe cases. The exact per-CWE results are:
CWE-22 21/133 with seven false positives, CWE-78 5/126 with no false
positives, CWE-89 57/272 with 17 false positives, and CWE-328 89/129 with no
false positives. The full benchmark has
2,740 cases, including 1,415 vulnerable cases. The scorer excludes 1,481 cases
and 755 vulnerable cases because this pack has no Java rule for CWE-79 XSS,
CWE-90 LDAP injection, CWE-327 broken cryptography, CWE-330 weak randomness,
CWE-501 trust-boundary violations, CWE-614 secure cookies, or CWE-643 XPath
injection. Recall across all vulnerable benchmark cases is therefore 172 of
1,415 (12.2%). The per-CWE counts and full denominator live in
`tests/rulepack_benchmarks.json`. These results block promotion.

The pinned NIST Juliet Java 1.3 archive supplies a second known-answer source.
The fetch gate verifies its 76,798,417-byte archive at SHA-256
`d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`,
retains the CC0 legal text, and derives a valid 28,881-case manifest by removing
only two independently checked extra closing tags. Two exact-location scans
produce these case-recall results:

| Rule | Cases detected | Case recall | Findings at manifest flaw locations |
|---|---:|---:|---:|
| Command injection | 42 of 444 | 9.5% | 40 of 42 |
| SQL injection | 210 of 2,220 | 9.5% | 152 of 210 |
| Weak message digest | 51 of 51 | 100.0% | 51 of 51 |

Juliet files contain both good and bad methods, so these figures measure case
recall and location corroboration, not standalone precision or true negatives.
The message-digest rule also does not resolve external constants, concatenated
strings, or runtime configuration, and it cannot infer whether a checksum has
security significance. These limits keep all eight Java rules experimental.
Rules with known safe-case findings or no independent precision measurement are
warning-level. The command-injection rule remains error-level because OWASP
measures no false positives in its 126 applicable cases, although its low recall
still prevents default coverage.

### C and C++ (`c/`, `cpp/`)

Experimental: six rules per language, not general memory-safety or C/C++ SAST
coverage.

- Command-line arguments passed directly to `system()` (CWE-78)
- Environment values reaching `system()` within one file (CWE-78)
- Command-line arguments used directly as `printf` format strings (CWE-134)
- Command-line arguments copied with `strcpy()` (CWE-120)
- Predictable temporary filename APIs (CWE-377)
- Disabled cURL certificate or hostname verification (CWE-295)

The command-line argument rules test both `char *argv[]` and `char **argv`.
The C++ fixtures also test qualified and unqualified standard-library calls.

The engine does not evaluate preprocessor conditionals, so these rules report
code that the compiler would discard. A `system(argv[1])` call inside `#if 0`
or an `#ifdef` whose macro is never defined is reported the same as live code.
Treat a finding in a conditionally compiled block as a finding about the source
text, not about the build you ship, and confirm against your own build
configuration before acting on it.

Pinned curl and fmt scans produce no findings, but Opengrep reports partial
parsing in 31 curl C files and four fmt C++ headers. These coverage gaps block
promotion and are recorded in `tests/rulepack_real_projects.json`. The fmt scan
selects only 19 of 72 tracked C/C++ files: 53 files under `test/` are excluded
by the engine. Juliet results are not measurable for these rules because its
representative cases use macro-indirected sinks and `fgetws` sources that the
rules do not model.

### Rust (`rust/`)

Experimental: seven focused rules. Calls inside user-defined macros may not be
visible to Opengrep. The fixtures cover an MD5 constructor alias, multi-statement
command builders, SQLx scalar queries, Tokio filesystem calls, Reqwest POST
destinations, base64 JWT keys, and invalid-hostname settings. The two structural
configuration rules exclude modules named `test` or `tests` to avoid test-only
secrets and TLS overrides.

`Sha1::default()` is not matched. Adding it produced a reviewed false positive in
Axum's RFC-mandated WebSocket handshake, so the broader spelling is withheld until
the rule can distinguish protocol compatibility hashing from security hashing.

- Reqwest clients configured to accept invalid TLS certificates (CWE-295)
- Process arguments passed to `sh -c` or `bash -c` (CWE-78)
- Process input reaching SQLx query text (CWE-89)
- Process input reaching filesystem reads (CWE-22)
- Process input controlling Reqwest destinations (CWE-918)
- MD5 or SHA-1 digest construction (CWE-328)
- Literal symmetric secrets passed to jsonwebtoken keys (CWE-798)

### PHP (`php/`)

Experimental: seven focused rules. Opengrep 1.26.0 warns that intrafile taint may
be limited to intraprocedural analysis for PHP. Dynamic dispatch, variable
variables, `call_user_func` indirection, and template syntax outside PHP parsing
are not covered. The pack has no labelled PHP corpus from which to claim recall
or precision.

- HTTP superglobals flowing to command execution functions within one file (CWE-78)
- HTTP superglobals flowing to `unserialize()` within one file (CWE-502)
- HTTP superglobals reaching SQL query text (CWE-89)
- HTTP superglobals reaching `echo` or `print` without `htmlspecialchars` or
  `htmlentities` (CWE-79)
- HTTP superglobals reaching filesystem operations (CWE-22)
- HTTP superglobals controlling cURL destinations (CWE-918)
- Submitted passwords hashed with MD5 or SHA-1 (CWE-916)

PHP taint findings are useful review leads, but the engine warning above means a
clean PHP scan is not evidence that every local helper flow was analyzed.

### C# (`csharp/`)

Experimental: eight focused rules. The bundled engine does not provide
cross-file analysis for this pack. Request-source fixtures cover ASP.NET
`FromQuery`, `FromBody`, and `FromRoute` parameters in addition to request
indexers. Minimal API implicit binding and Razor model binding are not modeled.

- TLS certificate callbacks that accept every certificate (CWE-295)
- `BinaryFormatter.Deserialize()` usage (CWE-502)
- ASP.NET request data reaching ADO.NET or EF Core raw SQL text (CWE-89)
- ASP.NET request data reaching process or command-interpreter APIs (CWE-78)
- ASP.NET request data reaching filesystem reads or writes (CWE-22)
- ASP.NET request data controlling HttpClient or WebRequest destinations (CWE-918)
- MD5 or SHA-1 hash construction (CWE-328)
- Literal symmetric JWT keys (CWE-798)

Dapper query extensions and archive-entry zip-slip flows need separate rules and
are not covered. The local Juliet C# checkout has no evidence manifest, so it
provides no precision or recall measurement for this pack.

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
- `jsonify()` reflecting a whole request or environment object (CWE-201)

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
  insecure session cookie, `SECURE_SSL_REDIRECT=False` (CWE-489, CWE-798, CWE-346,
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

The pack favors high-confidence findings over broad pattern counts. It is a
starting point for review, not a complete security audit. A clean scan does not
prove the absence of vulnerabilities. Use multiple testing methods for broader
coverage.

## Taint sanitizer limits

Every taint rule either declares tested expression sanitizers or records why a
sound sanitizer is not modeled. Seventeen rules currently carry that explicit
limitation. Their recommended fixes depend on replacing the sink or on checked
control flow, such as canonicalization followed by a containment check, or an
allowlist plus DNS and address validation. A lone `basename`, `parse_url`,
`normalize`, or `canonicalize` call is not treated as proof that the full
validation happened. These rules can therefore keep reporting a flow after an
application-specific mitigation; review the finding against the complete
validation branch.

Python framework sanitizers use qualified names so a local function named
`escape`, `safe_join`, `url_for`, or `check_password_hash` cannot hide a finding.
The fixtures verify a direct import alias as well as a shadowed local name.
Runtime rebinding and monkeypatching are not modeled.

## Engine coverage boundaries

Taint tracking is intrafile. Data flow between files is not followed. Opengrep's
built-in exclusions can omit paths with a component named `tests`; the evidence
gate copies fixtures to a neutral path before scanning. A per-rule timeout can
drop that rule's analysis for a file, so any engine timeout makes a blocking
`--fail-on` run nonzero even when completed findings are still shown.

Python receives an additional CPython syntax preflight. Scan output names the
host interpreter grammar because supported Python versions may parse new syntax
differently. The other eight languages have no preflight and rely on engine
parser reports, which cover one of the two failure modes:

- A file the engine parses **partially** is reported. A syntax error after valid
  code produces a recoverable parse error, the readable code is still analysed,
  and coverage is marked degraded, which an explicit `--fail-on` policy surfaces
  as exit 29.
- A file the engine cannot parse **at all** is not reported. It is counted among
  the scanned paths with no parse error and no degraded-coverage signal, so a
  run over such a file alone exits 0.

For those eight languages, treat a clean result as covering the files the engine
could parse. The run does not enumerate which files those were.

## Real-project evidence

Pinned scans cover Flask, chi, Hono, Spring Petclinic, curl, fmt, axum, Symfony
Demo, and .NET eShop. The manifest records exact commits, selected-file counts,
engine exclusions, parser errors, and whether each project contains the rule
pack's sources or sinks. Several zero-finding runs are null security signals:
they demonstrate parser compatibility and an absence of obvious false
positives on the selected files, not precision or recall. The Hono baseline
contains one reviewed `eval` finding and one partial-parse report.

## What these rules do not cover

- General-purpose secret scanning (see `secrets-check`). The JWT and framework
  hardcoded-key rules above target a specific committed-key pattern, not a full
  credential scan.
- Infrastructure-as-code misconfigurations (see `config-check`)
- Runtime vulnerabilities, dependency CVEs, or supply-chain issues

## License

MIT. See LICENSE in this directory.
