import type { Analyzer, AnalyzerResult, Finding, ParsedCommand } from "../types.js";

const SENSITIVE_SYSTEM_PATHS = [
  "/etc/", "/usr/bin/", "/usr/local/bin/", "/usr/sbin/",
  "/var/log/", "/boot/", "/sys/", "/proc/",
];

const DANGEROUS_MODES = new Set(["777", "666", "o+w", "a+w", "o+rwx", "a+rwx"]);

export const permissionsAnalyzer: Analyzer = {
  name: "permissions",

  async analyze(parsed: ParsedCommand[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];

    for (const cmd of parsed) {
      // sudo detection
      if (cmd.verb === "sudo") {
        const innerVerb = cmd.args[0] ?? "unknown";
        const isSensitive = ["rm", "chmod", "chown", "mkfs", "dd", "kill", "shutdown", "reboot"].includes(innerVerb);

        findings.push({
          category: "permissions",
          severity: isSensitive ? "high" : "low",
          description: isSensitive
            ? `\`sudo ${innerVerb}\` — elevated privileges with a sensitive operation`
            : `\`sudo ${innerVerb}\` — command runs with root privileges`,
        });
      }

      // chmod detection
      if (cmd.verb === "chmod" || (cmd.verb === "sudo" && cmd.args[0] === "chmod")) {
        const args = cmd.verb === "sudo" ? cmd.args.slice(1) : cmd.args;
        const modeArg = args.find(a => !a.startsWith("-") && (a.match(/^[0-7]{3,4}$/) || a.match(/^[ugoa][+-][rwxst]+$/)));
        const targets = args.filter(a => !a.startsWith("-") && a !== modeArg);
        const isDangerous = modeArg && DANGEROUS_MODES.has(modeArg);
        const targetsSensitive = targets.some(t =>
          SENSITIVE_SYSTEM_PATHS.some(p => t.startsWith(p))
        );

        if (isDangerous && targetsSensitive) {
          findings.push({
            category: "permissions",
            severity: "critical",
            description: `\`chmod ${modeArg}\` on system path (${targets.join(", ")}) — removes all access restrictions`,
          });
        } else if (isDangerous) {
          findings.push({
            category: "permissions",
            severity: "high",
            description: `\`chmod ${modeArg}\` — makes file(s) world-writable (${targets.join(", ") || "unknown target"})`,
          });
        } else if (targetsSensitive) {
          findings.push({
            category: "permissions",
            severity: "medium",
            description: `\`chmod\` on system path: ${targets.join(", ")}`,
          });
        }
      }

      // chown detection
      if (cmd.verb === "chown" || (cmd.verb === "sudo" && cmd.args[0] === "chown")) {
        const args = cmd.verb === "sudo" ? cmd.args.slice(1) : cmd.args;
        const targets = args.filter(a => !a.startsWith("-") && !a.includes(":") && args.indexOf(a) > 0);
        const targetsSensitive = targets.some(t =>
          SENSITIVE_SYSTEM_PATHS.some(p => t.startsWith(p))
        );

        findings.push({
          category: "permissions",
          severity: targetsSensitive ? "high" : "medium",
          description: `\`chown\` — changes file ownership${targetsSensitive ? " on system path" : ""} (${targets.join(", ") || "unknown target"})`,
        });
      }
    }

    return { findings };
  },
};
