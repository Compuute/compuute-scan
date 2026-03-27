# MCP Security Scan Report

| Field | Value |
|-------|-------|
| **Repository** | `vulnerable-mcp-server-filesystem-workspace-actions` |
| **Date** | 2026-03-27 |
| **Files Scanned** | 1 |
| **Scan Duration** | 0.01s |
| **Scanner** | compuute-scan v0.1.0 |

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 4 |
| 🟢 Low | 1 |
| Total | 9 |

## Layer Assessment

| Layer | Status | Findings | Description |
|-------|--------|----------|-------------|
| L0 | ✅ | 0 | Discovery & Metadata |
| L1 | 🔴 | 4 | Sandboxing & Code Execution |
| L2 | ⚠️ | 2 | Authorization & Secrets |
| L3 | ⚠️ | 1 | Tool Integrity & Data Handling |
| L4 | ⚠️ | 2 | Monitoring & Logging |

## Detailed Findings

### 🟠 HIGH

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `vulnerable-mcp-server-filesystem-workspace-actions-mcp.py` |
| **Line** | 201 |

**Code:**
```
full_path = os.path.join(self.workspace_dir, relative_path)
```

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L1-006: Path join without traversal validation

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `vulnerable-mcp-server-filesystem-workspace-actions-mcp.py` |
| **Line** | 237 |

**Code:**
```
entry_path = os.path.join(full_path, entry)
```

**Description:** Using path.join/os.path.join with user input without validating the resolved path allows directory traversal attacks (../../etc/passwd).

**Recommendation:** Resolve the full path with path.resolve()/os.path.realpath() and verify it starts with the expected base directory using startsWith().

---

#### L1-007: File read with variable path (no validation)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `vulnerable-mcp-server-filesystem-workspace-actions-mcp.py` |
| **Line** | 209 |

**Code:**
```
with open(full_path, 'r') as f:
```

**Description:** Reading files with a user-controlled path without validation enables arbitrary file read attacks.

**Recommendation:** Validate the resolved path starts with the expected base directory. Use a whitelist of allowed paths if possible.

---

#### L1-007: File read with variable path (no validation)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Layer** | L1 |
| **OWASP** | A01:2021 Broken Access Control |
| **NIS2** | Art. 21(2)(e) — Secure development |
| **File** | `vulnerable-mcp-server-filesystem-workspace-actions-mcp.py` |
| **Line** | 223 |

**Code:**
```
with open(full_path, 'w') as f:
```

**Description:** Reading files with a user-controlled path without validation enables arbitrary file read attacks.

**Recommendation:** Validate the resolved path starts with the expected base directory. Use a whitelist of allowed paths if possible.

---

### 🟡 MEDIUM

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
| **MCP Tools** | ~1 detected |
| **Dependency Pinning** | ❌ No |
| **Containerization** | ❌ No |

---

> This scan automates pattern detection. Professional judgment and manual review are required for a complete NIS2/DORA assessment. Contact: daniel@compuute.se

*Generated by compuute-scan v0.1.0 | Compuute AB*
