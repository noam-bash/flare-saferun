import type { Analyzer, AnalyzerResult, Finding, ParsedCommand } from "../types.js";
import { expandTilde } from "../parser.js";
import { homedir } from "os";

interface PathPattern {
  glob: string;
  regex: RegExp;
  label: string;
}

const WRITE_VERBS = new Set([
  "cp", "mv", "tee", "dd", "install", "rsync",
  "sed", "awk", "nano", "vim", "vi", "emacs",
]);

const READ_VERBS = new Set([
  "cat", "head", "tail", "less", "more", "bat",
  "grep", "rg", "awk", "sed", "wc", "sort", "uniq",
]);

const DEFAULT_PATTERNS: { glob: string; label: string }[] = [
  { glob: "~/.ssh/*", label: "SSH keys and configuration" },
  { glob: "~/.aws/*", label: "AWS credentials" },
  { glob: "~/.config/gcloud/*", label: "GCloud credentials" },
  { glob: "~/.claude/*", label: "Claude agent configuration" },
  { glob: ".cursorrules", label: "Cursor agent rules" },
  { glob: "CLAUDE.md", label: "Claude instructions file" },
  { glob: "/etc/passwd", label: "System user database" },
  { glob: "/etc/shadow", label: "System password hashes" },
  { glob: "/etc/sudoers", label: "Sudo configuration" },
  { glob: ".env", label: "Environment secrets" },
  { glob: "*.pem", label: "PEM certificate/key" },
  { glob: "*id_rsa*", label: "RSA private key" },
  { glob: "*.key", label: "Private key file" },
  { glob: "/usr/local/bin/*", label: "System binary directory" },
  { glob: "/usr/bin/*", label: "System binary directory" },
];

function compilePatterns(patterns: { glob: string; label: string }[]): PathPattern[] {
  return patterns.map(({ glob, label }) => ({
    glob,
    regex: globToRegex(glob),
    label,
  }));
}

function globToRegex(pattern: string): RegExp {
  // Expand tilde in the pattern for matching
  const expanded = expandTilde(pattern);

  const escaped = expanded
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "___DOUBLESTAR___")
    .replace(/\*/g, "[^/]*")
    .replace(/___DOUBLESTAR___/g, ".*")
    .replace(/\?/g, ".");

  return new RegExp(`(^|/)${escaped}$`);
}

let compiledPatterns: PathPattern[] | null = null;

function getPatterns(extraPatterns?: string[]): PathPattern[] {
  if (compiledPatterns && !extraPatterns?.length) return compiledPatterns;

  const all = [...DEFAULT_PATTERNS];
  if (extraPatterns) {
    for (const p of extraPatterns) {
      all.push({ glob: p, label: "User-defined sensitive path" });
    }
  }

  compiledPatterns = compilePatterns(all);
  return compiledPatterns;
}

function matchPath(path: string, patterns: PathPattern[]): PathPattern | null {
  const expanded = expandTilde(path);
  const home = homedir();

  for (const pattern of patterns) {
    if (pattern.regex.test(expanded)) return pattern;
    if (pattern.regex.test(path)) return pattern;
    // Also try the basename for patterns like ".env" or "*.pem"
    const basename = path.split("/").pop() ?? path;
    if (pattern.regex.test(basename)) return pattern;
    // Try with home expansion
    if (path.startsWith("~/")) {
      const withHome = home + path.slice(1);
      if (pattern.regex.test(withHome)) return pattern;
    }
  }
  return null;
}

export const sensitivePathAnalyzer: Analyzer = {
  name: "sensitive-path",

  async analyze(parsed: ParsedCommand[], cwd: string): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const patterns = getPatterns();

    for (const cmd of parsed) {
      const allPaths: { path: string; isWrite: boolean }[] = [];

      // Collect paths from args
      for (const arg of cmd.args) {
        if (arg.startsWith("-")) continue;
        const isWrite = WRITE_VERBS.has(cmd.verb);
        const isRead = READ_VERBS.has(cmd.verb);
        if (isWrite || isRead) {
          allPaths.push({ path: arg, isWrite });
        }
      }

      // Collect paths from redirects (always writes)
      for (const redirect of cmd.redirects) {
        allPaths.push({ path: redirect.target, isWrite: true });
      }

      // Also check echo/printf with redirect (write to file)
      if ((cmd.verb === "echo" || cmd.verb === "printf") && cmd.redirects.length > 0) {
        for (const redirect of cmd.redirects) {
          allPaths.push({ path: redirect.target, isWrite: true });
        }
      }

      // Match each path
      for (const { path, isWrite } of allPaths) {
        const match = matchPath(path, patterns);
        if (!match) continue;

        const action = isWrite ? "Writing to" : "Reading from";
        const isSystemAuth = ["System password hashes", "Sudo configuration"].includes(match.label);
        const isCredential = ["SSH keys and configuration", "AWS credentials", "GCloud credentials", "RSA private key", "Private key file", "PEM certificate/key"].includes(match.label);

        let severity: Finding["severity"];
        if (isWrite && (isCredential || isSystemAuth)) {
          severity = "critical";
        } else if (isWrite && match.label === "Claude agent configuration") {
          severity = "high";
        } else if (!isWrite && isSystemAuth) {
          severity = "high";
        } else if (isWrite) {
          severity = "medium";
        } else {
          severity = "medium";
        }

        findings.push({
          category: "sensitive-path",
          severity,
          description: `${action} \`${path}\` — ${match.label}`,
        });
      }
    }

    return { findings };
  },
};
