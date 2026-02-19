import type { Analyzer, AnalyzerResult, Finding, ParsedCommand } from "../types.js";
import { homedir } from "os";

const DESTRUCTIVE_VERBS = new Set(["rm", "rmdir", "truncate", "mkfs", "shred"]);

const DANGEROUS_GIT_PATTERNS = [
  { args: ["push", "-f"], description: "Force push — overwrites remote history" },
  { args: ["push", "--force"], description: "Force push — overwrites remote history" },
  { args: ["push", "--force-with-lease"], description: "Force push (with lease) — may overwrite remote history" },
  { args: ["reset", "--hard"], description: "Hard reset — discards all uncommitted changes" },
  { args: ["clean", "-f"], description: "Force clean — permanently deletes untracked files" },
];

const SQL_DESTRUCTIVE = [
  /\bDROP\s+(DATABASE|TABLE|SCHEMA|INDEX)\b/i,
  /\bTRUNCATE\s+TABLE\b/i,
  /\bDELETE\s+FROM\b.*\bWHERE\b.*=.*\bOR\b/i,
];

export const destructiveAnalyzer: Analyzer = {
  name: "destructive",

  async analyze(parsed: ParsedCommand[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];

    for (const cmd of parsed) {
      // rm with force/recursive flags
      if (cmd.verb === "rm") {
        const flags = cmd.args.filter(a => a.startsWith("-"));
        const hasForce = flags.some(a => a === "-f" || a === "-rf" || a === "-fr" || a.startsWith("--force") || (a.startsWith("-") && !a.startsWith("--") && a.includes("f")));
        const hasRecursive = flags.some(a => a === "-r" || a === "-R" || a === "-rf" || a === "-fr" || a === "-rR" || a === "-Rf" || a.startsWith("--recursive") || (a.startsWith("-") && !a.startsWith("--") && (a.includes("r") || a.includes("R"))));
        const targets = cmd.args.filter(a => !a.startsWith("-"));

        if (hasForce && hasRecursive) {
          const isRoot = targets.some(t => t === "/" || t === "/*");
          const home = homedir();
          const isHome = targets.some(t => t === "~" || t.startsWith("~/") || t === "$HOME" || t === home || t === home + "/");
          const isWildcard = targets.some(t => t === "*");

          if (isRoot) {
            findings.push({
              category: "destructive",
              severity: "critical",
              description: "`rm -rf /` — irreversible deletion of all files on the system",
            });
          } else if (isHome) {
            findings.push({
              category: "destructive",
              severity: "critical",
              description: "`rm -rf ~` — irreversible deletion of entire home directory",
            });
          } else if (isWildcard) {
            findings.push({
              category: "destructive",
              severity: "high",
              description: `\`rm -rf *\` — irreversible deletion of all files in current directory`,
            });
          } else {
            findings.push({
              category: "destructive",
              severity: "medium",
              description: `\`rm -rf ${targets.join(" ")}\` — recursive forced deletion`,
            });
          }
        } else if (hasForce || hasRecursive) {
          findings.push({
            category: "destructive",
            severity: "low",
            description: `\`rm\` with ${hasForce ? "force" : "recursive"} flag on ${targets.join(" ") || "unknown target"}`,
          });
        }
      }

      // Other destructive verbs
      if (cmd.verb === "truncate") {
        findings.push({
          category: "destructive",
          severity: "medium",
          description: `\`truncate\` — empties file contents (${cmd.args.filter(a => !a.startsWith("-")).join(" ")})`,
        });
      }

      if (cmd.verb === "mkfs") {
        findings.push({
          category: "destructive",
          severity: "critical",
          description: `\`mkfs\` — formats a filesystem, destroying all data on the device`,
        });
      }

      if (cmd.verb === "shred") {
        findings.push({
          category: "destructive",
          severity: "high",
          description: `\`shred\` — securely overwrites file(s), making data unrecoverable`,
        });
      }

      if (cmd.verb === "dd") {
        const ofTarget = cmd.args.find(a => a.startsWith("of="));
        const isDevice = ofTarget && /of=\/dev\//.test(ofTarget);
        findings.push({
          category: "destructive",
          severity: isDevice ? "critical" : "high",
          description: isDevice
            ? `\`dd\` writing directly to device (${ofTarget}) — can destroy entire disk`
            : `\`dd\` — low-level data copy, can overwrite files or devices`,
        });
      }

      // Git dangerous operations
      if (cmd.verb === "git") {
        for (const pattern of DANGEROUS_GIT_PATTERNS) {
          const matchesAll = pattern.args.every(arg =>
            cmd.args.some(a => a === arg)
          );
          if (matchesAll) {
            // Check if force push targets main/master
            if (pattern.args.includes("push") && (pattern.args.includes("-f") || pattern.args.includes("--force"))) {
              const targetsMain = cmd.args.some(a => a === "main" || a === "master" || a.endsWith("/main") || a.endsWith("/master"));
              findings.push({
                category: "destructive",
                severity: targetsMain ? "critical" : "high",
                description: pattern.description + (targetsMain ? " (targeting main/master branch)" : ""),
              });
            } else {
              findings.push({
                category: "destructive",
                severity: "high",
                description: pattern.description,
              });
            }
            break;
          }
        }
      }

      // SQL destructive patterns (check full raw segment)
      for (const regex of SQL_DESTRUCTIVE) {
        if (regex.test(cmd.rawSegment)) {
          findings.push({
            category: "destructive",
            severity: "critical",
            description: `SQL destructive operation detected: \`${cmd.rawSegment.slice(0, 80)}\``,
          });
          break;
        }
      }
    }

    return { findings };
  },
};
