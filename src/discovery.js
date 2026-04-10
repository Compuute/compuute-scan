// ─────────────────────────────────────────────
// L0: DISCOVERY
// ─────────────────────────────────────────────

function runL0Discovery(repoPath, allContent, sourceFiles) {
  const discovery = {
    totalSourceFiles: sourceFiles.length,
    transports: [],
    toolCount: 0,
    hasDependencyPinning: false,
    hasContainerization: false,
    dependencies: [],
    dependencyFile: null,
  };

  // Detect transports
  const transportPatterns = [
    { name: 'stdio', pattern: /\b(stdio|StdioServerTransport|stdio_server|NewStdioServer|server\.ServeStdio)\b/ },
    { name: 'SSE', pattern: /\b(SSEServerTransport|SseServerTransport|sse|NewSSEServer|SSEHandler)\b/i },
    { name: 'Streamable HTTP', pattern: /\b(StreamableHTTPServerTransport|httpStream|streamable.http|StreamableHTTP)\b/ },
  ];
  for (const tp of transportPatterns) {
    if (tp.pattern.test(allContent)) {
      discovery.transports.push(tp.name);
    }
  }

  // Count MCP tools
  const toolPatterns = [
    /name\s*:\s*['"`]/g,
    /tools\/list/g,
    /registerTool/g,
    /\.tool\s*\(/g,
    /\.action\s*\(/g,
    /\.query\s*\(/g,
    /\.mutation\s*\(/g,
    /@\w+\.tool\s*\(/g,                // Python FastMCP decorator
    /@server\.call_tool\s*\(/g,         // Python low-level MCP
    /@server\.list_tools\s*\(/g,        // Python low-level MCP
    /AddTool\s*\(/g,                    // Go mcp-go
    /NewTool\s*\(/g,                    // Go mcp-go
    /server\.HandleFunc\s*\(/g,         // Go MCP handler
  ];
  let maxToolCount = 0;
  for (const tp of toolPatterns) {
    const matches = allContent.match(tp);
    if (matches && matches.length > maxToolCount) {
      maxToolCount = matches.length;
    }
  }
  discovery.toolCount = maxToolCount;

  // Dependency pinning
  const lockFiles = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt', 'poetry.lock', 'go.sum'];
  for (const lf of lockFiles) {
    if (fs.existsSync(path.join(repoPath, lf))) {
      discovery.hasDependencyPinning = true;
      break;
    }
  }

  // Containerization
  const containerFiles = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];
  for (const cf of containerFiles) {
    if (fs.existsSync(path.join(repoPath, cf))) {
      discovery.hasContainerization = true;
      break;
    }
  }

  // List dependencies
  const pkgJsonPath = path.join(repoPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      discovery.dependencies = Object.entries(deps).map(([name, ver]) => `${name}@${ver}`);
      discovery.dependencyFile = 'package.json';
    } catch (err) {
      console.error(`[warn] Failed to parse package.json: ${err.message}`);
    }
  }

  const reqTxtPath = path.join(repoPath, 'requirements.txt');
  if (fs.existsSync(reqTxtPath)) {
    try {
      const content = fs.readFileSync(reqTxtPath, 'utf-8');
      discovery.dependencies = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      discovery.dependencyFile = 'requirements.txt';
    } catch (err) {
      console.error(`[warn] Failed to parse requirements.txt: ${err.message}`);
    }
  }

  // Python pyproject.toml dependencies
  const pyprojectPath = path.join(repoPath, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath) && !discovery.dependencyFile) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      const deps = [];
      const depMatches = content.match(/["']([a-zA-Z0-9_-]+(?:\[[\w,]+\])?(?:[><=!~]+[^"']+)?)["']/g);
      if (depMatches) {
        for (const m of depMatches) {
          const cleaned = m.replace(/["']/g, '');
          if (cleaned.length > 1 && !/^(python|readme|license|description|name|version|author|url|homepage|repository)$/i.test(cleaned)) {
            deps.push(cleaned);
          }
        }
      }
      if (deps.length > 0) {
        discovery.dependencies = deps;
        discovery.dependencyFile = 'pyproject.toml';
      }
    } catch (err) {
      console.error(`[warn] Failed to parse pyproject.toml: ${err.message}`);
    }
  }

  // Python lock files for dependency pinning
  const pyLockFiles = ['poetry.lock', 'uv.lock', 'Pipfile.lock'];
  for (const lf of pyLockFiles) {
    if (fs.existsSync(path.join(repoPath, lf))) {
      discovery.hasDependencyPinning = true;
      break;
    }
  }

  // Go go.mod dependencies
  const goModPath = path.join(repoPath, 'go.mod');
  if (fs.existsSync(goModPath) && !discovery.dependencyFile) {
    try {
      const content = fs.readFileSync(goModPath, 'utf-8');
      const deps = [];
      const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
      if (requireBlock) {
        for (const line of requireBlock[1].split('\n')) {
          const m = line.trim().match(/^(\S+)\s+(\S+)/);
          if (m && !m[1].startsWith('//')) deps.push(`${m[1]}@${m[2]}`);
        }
      }
      for (const m of content.matchAll(/require\s+(\S+)\s+(v\S+)/g)) {
        if (!deps.some(d => d.startsWith(m[1]))) deps.push(`${m[1]}@${m[2]}`);
      }
      if (deps.length > 0) {
        discovery.dependencies = deps;
        discovery.dependencyFile = 'go.mod';
      }
    } catch (err) {
      console.error(`[warn] Failed to parse go.mod: ${err.message}`);
    }
  }

  // Rust Cargo.toml dependencies
  const cargoPath = path.join(repoPath, 'Cargo.toml');
  if (fs.existsSync(cargoPath) && !discovery.dependencyFile) {
    try {
      const content = fs.readFileSync(cargoPath, 'utf-8');
      const deps = [];
      // Parse [dependencies] section (simple TOML parsing, no external deps)
      const depSections = content.matchAll(/\[(?:dev-)?dependencies(?:\.[^\]]+)?\]\s*\n([\s\S]*?)(?=\n\[|\n*$)/g);
      for (const section of depSections) {
        for (const line of section[1].split('\n')) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          // name = "version" or name = { version = "..." }
          const simple = trimmed.match(/^(\S+)\s*=\s*"([^"]+)"/);
          if (simple) { deps.push(`${simple[1]}@${simple[2]}`); continue; }
          const table = trimmed.match(/^(\S+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/);
          if (table) deps.push(`${table[1]}@${table[2]}`);
        }
      }
      if (deps.length > 0) {
        discovery.dependencies = deps;
        discovery.dependencyFile = 'Cargo.toml';
      }
    } catch (err) {
      console.error(`[warn] Failed to parse Cargo.toml: ${err.message}`);
    }
  }

  return discovery;
}



