# MCP Security Scan Report

| Field | Value |
|-------|-------|
| **Repository** | `src` |
| **Date** | 2026-03-27 |
| **Files Scanned** | 192 |
| **Scan Duration** | 0.14s |
| **Scanner** | compuute-scan v0.1.0 |

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 38 |
| 🟡 Medium | 12 |
| 🟢 Low | 2 |
| Total | 54 |

## Layer Assessment

| Layer | Status | Findings | Description |
|-------|--------|----------|-------------|
| L0 | ✅ | 0 | Discovery & Metadata |
| L1 | 🔴 | 7 | Sandboxing & Code Execution |
| L2 | 🔴 | 4 | Authorization & Secrets |
| L3 | 🔴 | 38 | Tool Integrity & Data Handling |
| L4 | 🔴 | 5 | Monitoring & Logging |

## Detailed Findings

### 🔴 CRITICAL

#### L1-002: Shell command execution (exec/spawn)

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Layer** | L1 |
| **OWASP** | A03:2021 Injection |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/commands/create.ts` |
| **Line** | 133 |

**Code:**
```
execSync('npm install', {
```

**Description:** exec/execSync/spawn can execute arbitrary shell commands. Use execFile with explicit arguments instead.

**Recommendation:** Use child_process.execFile() or spawn() with an argument array (no shell interpolation). Never pass user input to exec().

---

#### L1-002: Shell command execution (exec/spawn)

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Layer** | L1 |
| **OWASP** | A03:2021 Injection |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/commands/deploy.ts` |
| **Line** | 221 |

**Code:**
```
execSync('npm install -D esbuild', { cwd, stdio: 'pipe' });
```

**Description:** exec/execSync/spawn can execute arbitrary shell commands. Use execFile with explicit arguments instead.

**Recommendation:** Use child_process.execFile() or spawn() with an argument array (no shell interpolation). Never pass user input to exec().

---

### 🟠 HIGH

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/commands/deploy.ts` |
| **Line** | 81 |

**Code:**
```
const stubPathEscaped = JSON.stringify(stubPath);
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-004: HTTP request to user-controlled URL (SSRF)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A10:2021 Server-Side Request Forgery |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/commands/deploy.ts` |
| **Line** | 436 |

**Code:**
```
res = await fetch(url, {
```

**Description:** Making HTTP requests to user-supplied URLs enables Server-Side Request Forgery. Attackers can probe internal networks.

**Recommendation:** Validate and whitelist allowed URLs/domains. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x).

---

#### L2-001: Hardcoded API key / secret / token

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L2 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **NIS2** | Art. 21(2)(f) — Security in acquisition, development and maintenance |
| **File** | `cli/commands/remote.ts` |
| **Line** | 47 |

**Code:**
```
process.stderr.write(`  ${ansi.dim('Token:')}     ${config.token ? ansi.green('configured') : ansi.yellow('not set')}\n`
```

**Description:** Secrets hardcoded in source code can be extracted by anyone with code access. Use environment variables or a secrets manager.

**Recommendation:** Store secrets in environment variables (process.env / os.environ). Use a secrets manager (AWS SM, HashiCorp Vault) for production.

---

#### L3-004: HTTP request to user-controlled URL (SSRF)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A10:2021 Server-Side Request Forgery |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/commands/token.ts` |
| **Line** | 42 |

**Code:**
```
const res = await fetch(`${remote.replace(/\/+$/, '')}/token/info`, {
```

**Description:** Making HTTP requests to user-supplied URLs enables Server-Side Request Forgery. Attackers can probe internal networks.

**Recommendation:** Validate and whitelist allowed URLs/domains. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x).

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/cloudflare.ts` |
| **Line** | 71 |

**Code:**
```
return JSON.stringify(pkg, null, 4) + '\n';
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/cloudflare.ts` |
| **Line** | 76 |

**Code:**
```
return JSON.stringify({
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/config.ts` |
| **Line** | 71 |

**Code:**
```
return JSON.stringify(pkg, null, 4) + '\n';
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/config.ts` |
| **Line** | 76 |

**Code:**
```
return JSON.stringify({
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/cursor.ts` |
| **Line** | 19 |

**Code:**
```
return JSON.stringify(serverConfig, null, 2) + '\n';
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/vercel.ts` |
| **Line** | 73 |

**Code:**
```
return JSON.stringify(pkg, null, 4) + '\n';
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `cli/templates/vercel.ts` |
| **Line** | 78 |

**Code:**
```
return JSON.stringify({
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L2-001: Hardcoded API key / secret / token

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L2 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **NIS2** | Art. 21(2)(f) — Security in acquisition, development and maintenance |
| **File** | `core/builder/ActionGroupBuilder.ts` |
| **Line** | 289 |

**Code:**
```
key: `${this._groupName}.${config.name}`,
```

**Description:** Secrets hardcoded in source code can be extracted by anyone with code access. Use environment variables or a secrets manager.

**Recommendation:** Store secrets in environment variables (process.env / os.environ). Use a secrets manager (AWS SM, HashiCorp Vault) for production.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/execution/ValidationErrorFormatter.ts` |
| **Line** | 101 |

**Code:**
```
return `Expected exactly: ${JSON.stringify(expected)}.`;
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/execution/ValidationErrorFormatter.ts` |
| **Line** | 220 |

**Code:**
```
return JSON.stringify(value).slice(0, 50);
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L2-001: Hardcoded API key / secret / token

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L2 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **NIS2** | Art. 21(2)(f) — Security in acquisition, development and maintenance |
| **File** | `core/response.ts` |
| **Line** | 396 |

**Code:**
```
parts.push(`  <detail key="${escapeXmlAttr(key)}">${escapeXml(value)}</detail>`);
```

**Description:** Secrets hardcoded in source code can be extracted by anyone with code access. Use environment variables or a secrets manager.

**Recommendation:** Store secrets in environment variables (process.env / os.environ). Use a secrets manager (AWS SM, HashiCorp Vault) for production.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/response.ts` |
| **Line** | 113 |

**Code:**
```
* - Objects are serialized with `JSON.stringify(data, null, 2)`
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/response.ts` |
| **Line** | 138 |

**Code:**
```
: (compiledStringify ? compiledStringify(data) : JSON.stringify(data, null, 2));
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/response.ts` |
| **Line** | 218 |

**Code:**
```
* for ~40-50% token reduction compared to `JSON.stringify()`.
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/schema/SchemaUtils.ts` |
| **Line** | 123 |

**Code:**
```
JSON.stringify(exEnum) !== JSON.stringify(incEnum)
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `fsm/StateMachineGate.ts` |
| **Line** | 105 |

**Code:**
```
*         await redis.set(`fsm:${sessionId}`, JSON.stringify(snapshot), { EX: 3600 });
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `handoff/DelegationToken.ts` |
| **Line** | 77 |

**Code:**
```
return Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `handoff/DelegationToken.ts` |
| **Line** | 89 |

**Code:**
```
return Buffer.byteLength(JSON.stringify(obj), 'utf8');
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `introspection/CapabilityLockfile.ts` |
| **Line** | 325 |

**Code:**
```
return JSON.stringify(lockfile, (_key, value) => {
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `introspection/IntrospectionResource.ts` |
| **Line** | 131 |

**Code:**
```
text: JSON.stringify(manifest, null, 2),
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `introspection/canonicalize.ts` |
| **Line** | 67 |

**Code:**
```
return JSON.stringify(obj, (_key, value) => {
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `observability/TelemetryBus.ts` |
| **Line** | 433 |

**Code:**
```
line = JSON.stringify(event) + '\n';
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `presenter/ResponseBuilder.ts` |
| **Line** | 99 |

**Code:**
```
: (compiledStringify ? compiledStringify(data) : JSON.stringify(data, null, 2));
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `presenter/ui.ts` |
| **Line** | 102 |

**Code:**
```
return { type: 'echarts', content: fence('echarts', JSON.stringify(config, null, 2)), ...(meta ? { meta } : {}) };
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `presenter/ui.ts` |
| **Line** | 150 |

**Code:**
```
* ui.codeBlock('json', JSON.stringify(config, null, 2));
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `presenter/ui.ts` |
| **Line** | 222 |

**Code:**
```
return { type: 'json', content: fence('json', JSON.stringify(data, null, 2)), ...(meta ? { meta } : {}) };
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `resource/ResourceBuilder.ts` |
| **Line** | 20 |

**Code:**
```
*         return { text: JSON.stringify(price) };
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `resource/ResourceBuilder.ts` |
| **Line** | 182 |

**Code:**
```
*         return { text: JSON.stringify(status) };
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `sandbox/SandboxEngine.ts` |
| **Line** | 381 |

**Code:**
```
const wrappedCode = `const __fn__ = ${code};\nJSON.stringify(__fn__(__input__));`;
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L1-001: eval() with non-literal argument

| Field | Value |
|-------|-------|
| **Severity** | HIGH (Mitigated) |
| **Layer** | L1 |
| **OWASP** | A03:2021 Injection |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `sandbox/SandboxGuard.ts` |
| **Line** | 58 |

**Code:**
```
{ pattern: /\beval\s*\(/, reason: 'eval() has no effect in the sandbox — use direct expressions instead.' },
```

> ✅ **Mitigated** — Guard detected at line 53: `{ pattern: /\bimport\s*\(/, reason: 'Dynamic import() is not available in the sandbox.' },`

**Description:** eval() executes arbitrary code. If the argument is user-controlled, an attacker can execute arbitrary commands.

**Recommendation:** Replace eval() with a safe parser or template engine. For JSON, use JSON.parse(). For math, use a sandboxed expression evaluator.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `sandbox/SandboxGuard.ts` |
| **Line** | 135 |

**Code:**
```
'The sandbox uses synchronous JSON.stringify(fn(input)) — ' +
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L2-001: Hardcoded API key / secret / token

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L2 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **NIS2** | Art. 21(2)(f) — Security in acquisition, development and maintenance |
| **File** | `server/ServerAttachment.ts` |
| **Line** | 838 |

**Code:**
```
const canonicalKey = `${flatRoute.builder.getName()}.${flatRoute.actionKey}`;
```

**Description:** Secrets hardcoded in source code can be extracted by anyone with code access. Use environment variables or a secrets manager.

**Recommendation:** Store secrets in environment variables (process.env / os.environ). Use a secrets manager (AWS SM, HashiCorp Vault) for production.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `server/ServerAttachment.ts` |
| **Line** | 382 |

**Code:**
```
*             await redis.set(`fsm:${sessionId}`, JSON.stringify(snapshot), { EX: 3600 });
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `server/startServer.ts` |
| **Line** | 473 |

**Code:**
```
g.__vinkius_edge_getState = () => JSON.stringify(state);
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

### 🟡 MEDIUM

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/ErrorUtils.ts` |
| **Line** | 21 |

**Code:**
```
if (err instanceof Error) return err.message;
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/createGroup.ts` |
| **Line** | 216 |

**Code:**
```
.map(i => `${i.path.join('.')}: ${i.message}`)
```

> ✅ **Mitigated** — Guard detected at line 201: `return toolError(`

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/execution/ValidationErrorFormatter.ts` |
| **Line** | 48 |

**Code:**
```
? issue.path.join('.')
```

> ✅ **Mitigated** — Guard detected at line 37: `export function formatValidationError(`

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/middleware/InputFirewall.ts` |
| **Line** | 102 |

**Code:**
```
const serialized = JSON.stringify(args, null, 2).replaceAll('`', String.raw`\u0060`);
```

> ✅ **Mitigated** — Guard detected at line 101: `// sanitize backticks to prevent markdown code fence escape.`

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `core/serialization/JsonSerializer.ts` |
| **Line** | 254 |

**Code:**
```
return JSON.stringify(data);
```

> ✅ **Mitigated** — Guard detected at line 241: `compile(schema: unknown): StringifyFn | undefined {`

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `introspection/ManifestCompiler.ts` |
| **Line** | 111 |

**Code:**
```
return JSON.parse(JSON.stringify(manifest)) as ManifestPayload;
```

> ✅ **Mitigated** — Guard detected at line 97: `input_schema: toolDef.inputSchema,`

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `presenter/PostProcessor.ts` |
| **Line** | 68 |

**Code:**
```
const rawJson = telemetry ? JSON.stringify(result) : '';
```

> ✅ **Mitigated** — Guard detected at line 65: `// Priority 3: Raw data + Presenter → pipe through MVA`

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `presenter/PresenterValidationError.ts` |
| **Line** | 46 |

**Code:**
```
? `'${issue.path.join('.')}'`
```

> ✅ **Mitigated** — Guard detected at line 34: `* - `cause`: The original `ZodError` for programmatic access`

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `prompt/PromptExecutionPipeline.ts` |
| **Line** | 149 |

**Code:**
```
const field = issue.path.join('.') || '(root)';
```

> ✅ **Mitigated** — Guard detected at line 146: `function formatPromptValidationError(issues: { path: (string | number)[]; message: string }[]): string {`

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `server/ServerAttachment.ts` |
| **Line** | 1026 |

**Code:**
```
text: JSON.stringify(manifest, null, 2),
```

> ✅ **Mitigated** — Guard detected at line 1038: `resourceServer.setRequestHandler(SubscribeRequestSchema, ((`

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `server/startServer.ts` |
| **Line** | 435 |

**Code:**
```
text: String(err?.stack || err?.message || e),
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L4-004: Silent error swallowing

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A09:2021 Security Logging and Monitoring Failures |
| **NIS2** | Art. 21(2)(g) — Audit and monitoring |
| **File** | `server/startServer.ts` |
| **Line** | 708 |

**Code:**
```
} catch (err) {
```

**Description:** Empty catch blocks silently swallow errors, hiding security-relevant failures from operators.

**Recommendation:** Always log caught errors, even if you handle them gracefully. At minimum, log at warning level.

---

### 🟢 LOW

#### L4-002: console.log used as primary logging

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Layer** | L4 |
| **OWASP** | A09:2021 Security Logging and Monitoring Failures |
| **NIS2** | Art. 21(2)(g) — Audit and monitoring |
| **File** | `cli/commands/lock.ts` |

**Code:**
```
12 occurrences found
```

**Description:** console.log provides no log levels, rotation, or structured output. Use a proper logging framework in production.

**Recommendation:** Use a structured logging library (winston, pino, bunyan) with log levels and optional file output.

---

#### L4-002: console.log used as primary logging

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Layer** | L4 |
| **OWASP** | A09:2021 Security Logging and Monitoring Failures |
| **NIS2** | Art. 21(2)(g) — Audit and monitoring |
| **File** | `server/DevServer.ts` |

**Code:**
```
7 occurrences found
```

**Description:** console.log provides no log levels, rotation, or structured output. Use a proper logging framework in production.

**Recommendation:** Use a structured logging library (winston, pino, bunyan) with log levels and optional file output.

---

## L0: Discovery

| Property | Value |
|----------|-------|
| **Transport** | stdio, SSE, Streamable HTTP |
| **MCP Tools** | ~95 detected |
| **Dependency Pinning** | ❌ No |
| **Containerization** | ❌ No |

---

> This scan automates pattern detection. Professional judgment and manual review are required for a complete NIS2/DORA assessment. Contact: daniel@compuute.se

*Generated by compuute-scan v0.1.0 | Compuute AB*
