#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { parseCommand } from "./parser.js";
import { scoreRisk } from "./scorer.js";
import { destructiveAnalyzer } from "./analyzers/destructive.js";
import { permissionsAnalyzer } from "./analyzers/permissions.js";
import { sensitivePathAnalyzer } from "./analyzers/sensitive-path.js";
import { networkAnalyzer } from "./analyzers/network.js";
import { packageVulnAnalyzer } from "./analyzers/package-vuln.js";
import type { Analyzer } from "./types.js";

const analyzers: Analyzer[] = [
  destructiveAnalyzer,
  permissionsAnalyzer,
  sensitivePathAnalyzer,
  networkAnalyzer,
  packageVulnAnalyzer,
];

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
    try {
      const parsed = parseCommand(command);

      const results = await Promise.all(
        analyzers.map(a => a.analyze(parsed, cwd))
      );

      const assessment = scoreRisk(results);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(assessment, null, 2),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              risk_level: "none",
              summary: `Analysis error: ${message}`,
              details: [],
              recommendation: "Could not analyze this command. Proceed with caution.",
            }, null, 2),
          },
        ],
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
