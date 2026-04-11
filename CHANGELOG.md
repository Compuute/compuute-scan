# Changelog

All notable changes to `compuute-scan` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-04-11

**Focus: Enterprise language coverage + offline CVE matching.**

Released within weeks of the official [Microsoft MCP C# SDK v1.0](https://devblogs.microsoft.com/dotnet/release-v10-of-the-official-mcp-csharp-sdk/) (March 2026), this release makes `compuute-scan` the first MCP security scanner to cover the full set of languages with official MCP SDKs.

### Added

- **C#/.NET rules (L1-028 to L1-032)** — 5 rules covering `Process.Start` injection, SQL concatenation in `SqlCommand`, `[AllowAnonymous]` on sensitive endpoints, dangerous deserializers (`BinaryFormatter`, `SoapFormatter`), and `AllowAnyOrigin` in ASP.NET Core CORS. Compatible with the official Microsoft MCP C# SDK.
- **Java/Kotlin rules (L1-033 to L1-037)** — 5 rules covering `Runtime.exec()` command injection, JDBC string concatenation, `ObjectInputStream` deserialization, Spring Security `permitAll()`, and `@CrossOrigin` wildcards. Aligned with the official MCP Java/Spring SDK.
- **Offline CVE database** — curated vulnerability list for 40+ top npm/PyPI/Go packages (lodash, axios, requests, django, golang.org/x/net, etc.). Detects known-vulnerable dependency versions without any network calls.
- **Dependency age check** — flags packages two or more major versions behind current (e.g., react@16 when current is 18). Helps satisfy NIS2 Art. 21(2)(e) secure-development requirements.
- **License compliance check** — flags copyleft licenses (GPL, AGPL, LGPL, SSPL, EUPL, OSL) in `node_modules` that may create distribution obligations.
- **Dependency file parsing** — `.csproj` (NuGet `PackageReference`), `pom.xml` (Maven), and `build.gradle` / `build.gradle.kts` (Gradle) are now parsed for L0 discovery.
- **Language extensions** — `.cs`, `.java`, and `.kt` added to the scanner's file extension set.
- **Skip directories** — `bin`, `obj`, `target`, `.gradle` added to the default skip list.
- **47 new test assertions** — per-rule tests for L1-028 through L1-037 plus end-to-end CVE/age checks (231 total, up from 184).

### Changed

- Scanner now covers **8 languages**: TypeScript, JavaScript, Python, Go, Rust, C#, Java, Kotlin — matching the full set of officially supported MCP SDK languages.
- L0 discovery report now includes dependencies from `.csproj`, `pom.xml`, and `build.gradle` in addition to `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, and `Cargo.toml`.

### Unchanged (intentionally)

- **Zero runtime dependencies.** Still Node.js built-ins only (`fs`, `path`).
- **Single-file distribution.** `npx compuute-scan` still works unchanged.
- **Supply chain integrity.** `verify-integrity.js` still passes — no `child_process`, no network, no `eval`.
- **Privacy.** No telemetry, no uploads, no API calls. Runs fully offline.

### Removed

- Nothing.

---

## [0.5.0] — 2026-03

**Focus: Module split, Rust support, function-aware guards.**

### Added

- Rust rules L1-023 to L1-027: `unsafe` blocks, `Command::new` with format strings, SQL via `format!()`, `danger_accept_invalid_certs`, and missing `#[deny(unsafe_code)]`.
- Rust ecosystem support: `.rs` files, `Cargo.toml` dependency parsing.
- Function-boundary-aware guard system — guards are now checked within the enclosing function body instead of a fixed ±15 line window, reducing false positives by 40-60%.
- Module split: source is now organized under `src/` with a build step (`scripts/build.js`) that produces the single-file `compuute-scan.js`.
- GitLab and Bitbucket URL support in the web UI (previously GitHub-only).
- Persistent rate limiter with Upstash Redis fallback.
- Extended test suite to 184 assertions.

### Changed

- `compuute-scan.js` is now generated output — edit `src/*.js` and run `npm run build`.
- README: ecosystem coverage updated to reflect TS/JS/Python/Go/Rust (84% of MCP ecosystem at the time).

---

## [0.3.1] — 2026-02

**Focus: Credibility.**

### Added

- GitHub Actions CI workflow (`verify-integrity`, tests, self-scan).
- Inline ignore comments: `// compuute-scan-ignore-next-line [L1-NNN]`.
- Configuration file support: `.compuute-scan.json` for per-rule severity overrides, rule disabling, and ignore patterns.
- npm release automation workflow.

### Changed

- Bumped version and fixed broken CI badge in README.

---

## [0.3.0] — 2026-01

### Added

- Supply-chain integrity verifier (`verify-integrity.js`).
- `SECURITY.md` with disclosure process.
- Docker-isolated scanning workflow (`scan.sh`).
- 22 L0/L1 rules covering TS/JS, Python, Go.

---

[0.6.0]: https://github.com/Compuute/compuute-scan/releases/tag/v0.6.0
[0.5.0]: https://github.com/Compuute/compuute-scan/releases/tag/v0.5.0
[0.3.1]: https://github.com/Compuute/compuute-scan/releases/tag/v0.3.1
[0.3.0]: https://github.com/Compuute/compuute-scan/releases/tag/v0.3.0
