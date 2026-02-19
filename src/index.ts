import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync } from "fs";
import { homedir } from "os";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { z } from "zod";
import { expandTilde, parseCommand } from "./parser.js";
import { scoreRisk } from "./scorer.js";
import { initLogger, initLoggerWithWriter, writeLogEntry } from "./logger.js";
import { analyzeFile, analyzeDirectory } from "./static.js";
import { scanManifest, scanDependencies } from "./dep-scan.js";
import { destructiveAnalyzer } from "./analyzers/destructive.js";
import { permissionsAnalyzer } from "./analyzers/permissions.js";
import { createSensitivePathAnalyzer } from "./analyzers/sensitive-path.js";
import { createNetworkAnalyzer } from "./analyzers/network.js";
import { createPackageVulnAnalyzer } from "./analyzers/package-vuln.js";
import { codeInjectionAnalyzer } from "./analyzers/code-injection.js";
import type { Analyzer, Config } from "./types.js";

const DEFAULT_CONFIG: Config = {
  actionPolicy: {
    none: "run",
    low: "run",
    medium: "warn",
    high: "ask",
    critical: "ask",
  },
  sensitivePatterns: [],
  packageAllowlist: [],
  osvTimeout: 1500,
  safeHosts: [],
  commandAllowlist: [],
  logFile: resolve(homedir(), ".flare", "logs", "assess.jsonl"),
  logBackend: "jsonl",
};

function loadConfig(): Config {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const configPath = resolve(__dirname, "..", "config.json");
    const raw = readFileSync(configPath, "utf-8");
    const user = JSON.parse(raw);
    const merged: Config = {
      ...DEFAULT_CONFIG,
      ...user,
      actionPolicy: {
        ...DEFAULT_CONFIG.actionPolicy,
        ...(user.actionPolicy ?? {}),
      },
    };
    if (typeof merged.logFile === "string") {
      merged.logFile = expandTilde(merged.logFile);
    }
    return merged;
  } catch {
    return DEFAULT_CONFIG;
  }
}

const config = loadConfig();

// Initialize logger based on backend config
if (config.logBackend === "sqlite" && typeof config.logFile === "string") {
  try {
    const { createSqliteStore } = await import("./log-store-sqlite.js");
    const dbPath = config.logFile.replace(/\.jsonl$/, ".db");
    const store = createSqliteStore(dbPath);
    initLoggerWithWriter(store);
  } catch {
    // Fallback to JSONL if better-sqlite3 not available
    initLogger(config.logFile);
  }
} else {
  initLogger(config.logFile);
}

const analyzers: Analyzer[] = [
  destructiveAnalyzer,
  permissionsAnalyzer,
  createSensitivePathAnalyzer(config.sensitivePatterns),
  createNetworkAnalyzer(config.safeHosts),
  createPackageVulnAnalyzer(config.osvTimeout, config.packageAllowlist),
  codeInjectionAnalyzer,
];

function matchesAllowlist(command: string, allowlist: string[]): boolean {
  return allowlist.some(prefix => command.startsWith(prefix));
}

const server = new McpServer({
  name: "flare",
  version: "1.0.0",
});

server.tool(
  "assess_command",
  "Analyze a shell command for security risks before execution",
  {
    command: z.string().describe("The shell command to analyze"),
    cwd: z.string().describe("Current working directory"),
  },
  async ({ command, cwd }) => {
    const startTime = Date.now();
    try {
      // Skip analysis for allowlisted commands
      if (matchesAllowlist(command, config.commandAllowlist)) {
        const assessment = {
          risk_level: "none" as const,
          action: "run" as const,
          summary: "Command is in the allowlist.",
          details: [],
          recommendation: "Command appears safe to execute.",
        };
        writeLogEntry(command, cwd, assessment, Date.now() - startTime);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(assessment, null, 2) }],
        };
      }

      const parsed = parseCommand(command);

      const results = await Promise.all(
        analyzers.map(async (a) => {
          const result = await a.analyze(parsed, cwd);
          // Tag each finding with the analyzer that produced it
          for (const finding of result.findings) {
            finding.analyzer = a.name;
          }
          return result;
        })
      );

      const assessment = scoreRisk(results, config.actionPolicy);
      writeLogEntry(command, cwd, assessment, Date.now() - startTime, parsed);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(assessment, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const assessment = {
        risk_level: "none" as const,
        action: "run" as const,
        summary: `Analysis error: ${message}`,
        details: [],
        recommendation: "Could not analyze this command. Proceed with caution.",
      };
      writeLogEntry(command, cwd, assessment, Date.now() - startTime);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(assessment, null, 2) }],
        isError: true,
      };
    }
  }
);

// Static analysis: build analyzers without package-vuln (no OSV for static files)
const staticAnalyzers: Analyzer[] = [
  destructiveAnalyzer,
  permissionsAnalyzer,
  createSensitivePathAnalyzer(config.sensitivePatterns),
  createNetworkAnalyzer(config.safeHosts),
  codeInjectionAnalyzer,
];

server.tool(
  "analyze_file",
  "Scan a shell script, Dockerfile, or CI config for security risks without executing it",
  {
    path: z.string().describe("Absolute path to the file to analyze"),
  },
  async ({ path }) => {
    try {
      const result = await analyzeFile(path, staticAnalyzers, config.actionPolicy);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
        isError: true,
      };
    }
  }
);

server.tool(
  "analyze_directory",
  "Recursively scan a directory for shell scripts, Dockerfiles, and CI configs, analyzing each for security risks",
  {
    path: z.string().describe("Absolute path to the directory to scan"),
    patterns: z.array(z.string()).optional().describe("Glob patterns to match (defaults to *.sh, Dockerfile, CI configs)"),
  },
  async ({ path, patterns }) => {
    try {
      const result = await analyzeDirectory(path, staticAnalyzers, config.actionPolicy, patterns);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
        isError: true,
      };
    }
  }
);

server.tool(
  "analyze_dependencies",
  "Scan dependency manifests (package.json, package-lock.json, requirements.txt, Cargo.lock) for known vulnerabilities via OSV.dev",
  {
    path: z.string().describe("Absolute path to a manifest file or directory to scan recursively"),
  },
  async ({ path }) => {
    try {
      // Check if path is a file or directory
      const { stat: fsStat } = await import("fs/promises");
      const info = await fsStat(path);

      if (info.isFile()) {
        const allowSet = new Set(config.packageAllowlist.map(s => s.toLowerCase()));
        const result = await scanManifest(path, config.osvTimeout, allowSet);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      }

      const result = await scanDependencies(path, config.osvTimeout, config.packageAllowlist);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
        isError: true,
      };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Flare server error:", error);
  process.exit(1);
});
