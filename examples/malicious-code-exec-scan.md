# MCP Security Scan Report

| Field | Value |
|-------|-------|
| **Repository** | `vulnerable-mcp-server-malicious-code-exec` |
| **Date** | 2026-03-27 |
| **Files Scanned** | 1 |
| **Scan Duration** | 0.00s |
| **Scanner** | compuute-scan v0.1.0 |

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 3 |
| 🟡 Medium | 5 |
| 🟢 Low | 1 |
| Total | 10 |

## Layer Assessment

| Layer | Status | Findings | Description |
|-------|--------|----------|-------------|
| L0 | ✅ | 0 | Discovery & Metadata |
| L1 | ⚠️ | 1 | Sandboxing & Code Execution |
| L2 | ⚠️ | 1 | Authorization & Secrets |
| L3 | 🔴 | 4 | Tool Integrity & Data Handling |
| L4 | 🔴 | 4 | Monitoring & Logging |

## Detailed Findings

### 🔴 CRITICAL

#### L1-001: eval() with non-literal argument

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Layer** | L1 |
| **OWASP** | A03:2021 Injection |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 105 |

**Code:**
```
formattedOutput = eval(`(function() {
```

**Description:** eval() executes arbitrary code. If the argument is user-controlled, an attacker can execute arbitrary commands.

**Recommendation:** Replace eval() with a safe parser or template engine. For JSON, use JSON.parse(). For math, use a sandboxed expression evaluator.

---

### 🟠 HIGH

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 85 |

**Code:**
```
formattedOutput = JSON.stringify({
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
| **File** | `index.js` |
| **Line** | 106 |

**Code:**
```
const data = ${JSON.stringify(quoteData)};
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
| **File** | `index.js` |
| **Line** | 112 |

**Code:**
```
formattedOutput = `Format error: ${formatError.message}\n\n` + JSON.stringify({
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
| **File** | `index.js` |
| **Line** | 134 |

**Code:**
```
text: `Error fetching quote: ${error.message}`,
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
| **File** | `index.js` |
| **Line** | 154 |

**Code:**
```
server.run().catch(console.error);
```

**Description:** Empty catch blocks silently swallow errors, hiding security-relevant failures from operators.

**Recommendation:** Always log caught errors, even if you handle them gracefully. At minimum, log at warning level.

---

#### L2-003: No RBAC / permission system detected

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L2 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(c) — Access control policies |
| **File** | `(entire codebase)` |

**Code:**
```
Pattern not found in any source file
```

**Description:** No role-based access control or permission system was found. Tools should be restricted based on user roles.

**Recommendation:** Implement role-based tool access. Define which roles can invoke which tools. Use a deny-by-default policy.

---

#### L3-002: No input validation library detected

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L3 |
| **OWASP** | A03:2021 Injection |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `(entire codebase)` |

**Code:**
```
Pattern not found in any source file
```

**Description:** No input validation framework (zod, joi, yup, ajv) was found. Tool inputs should be validated against a schema.

**Recommendation:** Add input validation using zod, joi, yup, ajv, or use inputSchema with required fields in MCP tool definitions.

---

#### L4-001: No audit / telemetry in codebase

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A09:2021 Security Logging and Monitoring Failures |
| **NIS2** | Art. 21(2)(g) — Audit and monitoring |
| **File** | `(entire codebase)` |

**Code:**
```
Pattern not found in any source file
```

**Description:** No audit logging or telemetry was detected. MCP tool invocations should be logged for security monitoring and incident response.

**Recommendation:** Implement audit logging for all tool invocations. Log: who called what tool, when, with which arguments, and the outcome.

---

### 🟢 LOW

#### L4-005: No rate limiting detected

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(d) — Network security |
| **File** | `(entire codebase)` |

**Code:**
```
Pattern not found in any source file
```

**Description:** No rate limiting mechanism was found. MCP servers exposed over HTTP should limit request rates to prevent abuse.

**Recommendation:** Implement rate limiting using a middleware (express-rate-limit, slowapi) or at the gateway/proxy level.

---

## L0: Discovery

| Property | Value |
|----------|-------|
| **Transport** | stdio |
| **MCP Tools** | ~2 detected |
| **Dependency Pinning** | ✅ Yes |
| **Containerization** | ❌ No |
| **Dependencies** | 3 (package.json) |

<details>
<summary>Dependency List</summary>

- @modelcontextprotocol/sdk@^1.0.4
- node-fetch@^3.3.2
- xml2js@^0.6.2

</details>

---

> This scan automates pattern detection. Professional judgment and manual review are required for a complete NIS2/DORA assessment. Contact: daniel@compuute.se

*Generated by compuute-scan v0.1.0 | Compuute AB*
