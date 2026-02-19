import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync } from "fs";
import { homedir } from "os";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { z } from "zod";
import { expandTilde, parseCommand } from "./parser.js";
import { scoreRisk } from "./scorer.js";
import { initLogger, writeLogEntry } from "./logger.js";
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
initLogger(config.logFile);

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

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Flare server error:", error);
  process.exit(1);
});
