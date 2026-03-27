# MCP Security Scan Report

| Field | Value |
|-------|-------|
| **Repository** | `vulnerable-mcp-server-outdated-pacakges` |
| **Date** | 2026-03-27 |
| **Files Scanned** | 1 |
| **Scan Duration** | 0.01s |
| **Scanner** | compuute-scan v0.1.0 |

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 7 |
| 🟡 Medium | 10 |
| 🟢 Low | 1 |
| Total | 18 |

## Layer Assessment

| Layer | Status | Findings | Description |
|-------|--------|----------|-------------|
| L0 | ✅ | 0 | Discovery & Metadata |
| L1 | ⚠️ | 2 | Sandboxing & Code Execution |
| L2 | ⚠️ | 2 | Authorization & Secrets |
| L3 | 🔴 | 7 | Tool Integrity & Data Handling |
| L4 | 🔴 | 7 | Monitoring & Logging |

## Detailed Findings

### 🟠 HIGH

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 139 |

**Code:**
```
await calculateSize(path.join(currentPath, item));
```

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L3-001: JSON.stringify as direct tool response

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L3 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 150 |

**Code:**
```
text: JSON.stringify({
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
| **Line** | 181 |

**Code:**
```
text: JSON.stringify({ directory: dirPath, items: itemList }, null, 2),
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
| **Line** | 212 |

**Code:**
```
text: JSON.stringify(info, null, 2),
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
| **Line** | 234 |

**Code:**
```
text: JSON.stringify({ path: targetPath, exists: true }, null, 2),
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
| **Line** | 243 |

**Code:**
```
text: JSON.stringify({ path: targetPath, exists: false }, null, 2),
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
| **Line** | 276 |

**Code:**
```
text: JSON.stringify(statsInfo, null, 2),
```

**Description:** Serializing raw data as a tool response can leak internal fields, database IDs, or sensitive properties.

**Recommendation:** Use a presenter, DTO, or explicit field selection (pick/omit) to control exactly which fields are exposed in tool responses.

---

### 🟡 MEDIUM

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (Mitigated) |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 174 |

**Code:**
```
path: path.join(dirPath, item.name),
```

> ✅ **Mitigated** — Guard detected at line 160: `content: [{ type: "text", text: `Error: ${error.message}` }],`

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 160 |

**Code:**
```
content: [{ type: "text", text: `Error: ${error.message}` }],
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 187 |

**Code:**
```
content: [{ type: "text", text: `Error: ${error.message}` }],
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 218 |

**Code:**
```
content: [{ type: "text", text: `Error: ${error.message}` }],
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 250 |

**Code:**
```
content: [{ type: "text", text: `Error: ${error.message}` }],
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L4-003: Error details leaked to client

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L4 |
| **OWASP** | A04:2021 Insecure Design |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `index.js` |
| **Line** | 282 |

**Code:**
```
content: [{ type: "text", text: `Error: ${error.message}` }],
```

**Description:** Exposing stack traces or internal error messages to clients reveals implementation details useful to attackers.

**Recommendation:** Return generic error messages to clients. Log detailed errors server-side only.

---

#### L2-002: No authentication mechanism detected

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Layer** | L2 |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **NIS2** | Art. 21(2)(c) — Access control policies |
| **File** | `(entire codebase)` |

**Code:**
```
Pattern not found in any source file
```

**Description:** No authentication mechanism was found in the codebase. MCP servers should authenticate clients to prevent unauthorized access.

**Recommendation:** Implement authentication using JWT, OAuth, API keys, or another mechanism appropriate for your transport.

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
| **MCP Tools** | ~6 detected |
| **Dependency Pinning** | ✅ Yes |
| **Containerization** | ❌ No |
| **Dependencies** | 31 (package.json) |

<details>
<summary>Dependency List</summary>

- @modelcontextprotocol/sdk@^0.5.0
- express@4.17.1
- lodash@4.17.20
- axios@0.21.1
- moment@2.29.1
- request@2.88.2
- minimist@1.2.5
- handlebars@4.7.6
- node-fetch@2.6.7
- underscore@1.12.1
- yargs@16.2.0
- ws@7.4.6
- body-parser@1.19.0
- cookie-parser@1.4.5
- multer@1.4.2
- jsonwebtoken@8.5.1
- dotenv@8.2.0
- morgan@1.10.0
- compression@1.7.4
- helmet@4.6.0
- cors@2.8.5
- validator@13.5.2
- socket.io@2.4.0
- pg@8.5.1
- mysql@2.18.1
- debug@4.3.1
- async@3.2.0
- glob@7.1.6
- xml2js@0.4.23
- webpack@5.30.0
- jest@26.6.3

</details>

---

> This scan automates pattern detection. Professional judgment and manual review are required for a complete NIS2/DORA assessment. Contact: daniel@compuute.se

*Generated by compuute-scan v0.1.0 | Compuute AB*
