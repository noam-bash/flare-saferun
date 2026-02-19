import type { Analyzer, AnalyzerResult, Finding, ParsedCommand } from "../types.js";

const NETWORK_VERBS = new Set(["curl", "wget", "nc", "netcat", "ncat", "ssh", "scp", "rsync", "ftp", "sftp"]);

const SENSITIVE_DATA_SOURCES = [
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\.ssh\//,
  /\.aws\//,
  /\.env/,
  /id_rsa/,
  /\.pem$/,
  /\.key$/,
  /credentials/,
  /secret/i,
  /token/i,
];

const SAFE_HOSTS = new Set([
  "registry.npmjs.org",
  "pypi.org",
  "crates.io",
  "github.com",
  "raw.githubusercontent.com",
  "api.github.com",
  "localhost",
  "127.0.0.1",
  "::1",
]);

export function createNetworkAnalyzer(extraSafeHosts: string[] = []): Analyzer {
  const allSafeHosts = new Set([...SAFE_HOSTS, ...extraSafeHosts]);

  return {
    name: "network",

    async analyze(parsed: ParsedCommand[]): Promise<AnalyzerResult> {
      const findings: Finding[] = [];

      for (let i = 0; i < parsed.length; i++) {
        const cmd = parsed[i];

        if (!NETWORK_VERBS.has(cmd.verb)) continue;

        // Check if sensitive data is being piped TO this network command
        if (cmd.operator === null && i > 0) {
          const prev = parsed[i - 1];
          if (prev && prev.operator === "|") {
            const prevRaw = prev.rawSegment;
            const pipesSensitive = SENSITIVE_DATA_SOURCES.some(r => r.test(prevRaw));

            if (pipesSensitive) {
              findings.push({
                category: "network",
                severity: "critical",
                description: `Piping sensitive data to \`${cmd.verb}\` — possible data exfiltration: \`${prev.rawSegment.slice(0, 40)}... | ${cmd.verb}\``,
              });
              continue;
            }
          }
        }

        // Check for data upload flags
        const uploadsData = cmd.args.some(a =>
          a === "-d" || a === "--data" || a === "--data-binary" ||
          a === "-F" || a === "--form" || a === "-T" || a === "--upload-file"
        );

        // Extract URL/host from args
        const url = cmd.args.find(a => a.startsWith("http://") || a.startsWith("https://") || a.startsWith("ftp://"));
        const host = url ? extractHost(url) : null;
        const isSafeHost = host ? allSafeHosts.has(host) : false;
        const isHttp = url?.startsWith("http://");

        if (uploadsData && !isSafeHost) {
          const dataArg = findArgValue(cmd.args, ["-d", "--data", "--data-binary", "-T", "--upload-file"]);
          const dataSensitive = dataArg && SENSITIVE_DATA_SOURCES.some(r => r.test(dataArg));

          findings.push({
            category: "network",
            severity: dataSensitive ? "critical" : "high",
            description: dataSensitive
              ? `\`${cmd.verb}\` uploading sensitive data to \`${host ?? "unknown host"}\``
              : `\`${cmd.verb}\` sending data to \`${host ?? "unknown host"}\``,
          });
        } else if (isHttp && !isSafeHost) {
          findings.push({
            category: "network",
            severity: "medium",
            description: `\`${cmd.verb}\` using unencrypted HTTP to \`${host}\``,
          });
        } else if (cmd.verb === "nc" || cmd.verb === "netcat" || cmd.verb === "ncat") {
          findings.push({
            category: "network",
            severity: "high",
            description: `\`${cmd.verb}\` — raw network connection (commonly used for data exfiltration)`,
          });
        }
      }

      // Check for piped chains ending in a network command
      if (parsed.length >= 2) {
        const last = parsed[parsed.length - 1];

        if (last && NETWORK_VERBS.has(last.verb)) {
          const isPipeChain = parsed.slice(0, -1).some(seg => seg.operator === "|");

          if (isPipeChain) {
            const anySensitive = parsed.slice(0, -1).some(seg =>
              SENSITIVE_DATA_SOURCES.some(r => r.test(seg.rawSegment))
            );

            if (anySensitive && !findings.some(f => f.severity === "critical")) {
              findings.push({
                category: "network",
                severity: "critical",
                description: `Command chain pipes sensitive data to \`${last.verb}\` — possible exfiltration`,
              });
            }
          }
        }
      }

      return { findings };
    },
  };
}

export const networkAnalyzer = createNetworkAnalyzer();

function extractHost(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function findArgValue(args: string[], flags: string[]): string | null {
  for (let i = 0; i < args.length; i++) {
    if (flags.includes(args[i]) && i + 1 < args.length) {
      return args[i + 1];
    }
    // Handle --flag=value
    for (const flag of flags) {
      if (args[i].startsWith(flag + "=")) {
        return args[i].slice(flag.length + 1);
      }
    }
  }
  return null;
}
