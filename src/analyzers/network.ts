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

export const networkAnalyzer: Analyzer = {
  name: "network",

  async analyze(parsed: ParsedCommand[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];

    for (let i = 0; i < parsed.length; i++) {
      const cmd = parsed[i];

      if (!NETWORK_VERBS.has(cmd.verb)) continue;

      // Check if sensitive data is being piped TO this network command
      if (cmd.operator === null && i > 0) {
        // This command received piped input — check what was piped
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
      const isSafeHost = host ? SAFE_HOSTS.has(host) : false;
      const isHttp = url?.startsWith("http://");

      if (uploadsData && !isSafeHost) {
        // Check if the uploaded data references sensitive files
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
        // Netcat is always suspicious
        findings.push({
          category: "network",
          severity: "high",
          description: `\`${cmd.verb}\` — raw network connection (commonly used for data exfiltration)`,
        });
      }
    }

    // Also check for piped chains ending in a network command
    // e.g., cat /etc/passwd | base64 | curl ...
    if (parsed.length >= 2) {
      const last = parsed[parsed.length - 1];
      const first = parsed[0];

      if (last && first && NETWORK_VERBS.has(last.verb) && parsed[0].operator === "|") {
        const firstRaw = first.rawSegment;
        const pipesSensitive = SENSITIVE_DATA_SOURCES.some(r => r.test(firstRaw));

        if (pipesSensitive && !findings.some(f => f.severity === "critical")) {
          findings.push({
            category: "network",
            severity: "critical",
            description: `Command chain pipes sensitive data to \`${last.verb}\` — possible exfiltration`,
          });
        }
      }
    }

    return { findings };
  },
};

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
