import type { Analyzer, AnalyzerResult, Finding, ParsedCommand } from "../types.js";

/**
 * Detects code injection and dynamic execution patterns:
 * - eval / exec / source with dynamic arguments
 * - Interpreter inline flags: bash -c, python -c, node -e, ruby -e, perl -e
 * - curl/wget piped to interpreter (curl | bash)
 * - Docker container escape patterns (--privileged, -v /:/host)
 */

const EVAL_VERBS = new Set(["eval", "exec", "source"]);

// Interpreter verbs and their inline-code flags
const INTERPRETER_FLAGS: Record<string, Set<string>> = {
  bash: new Set(["-c"]),
  sh: new Set(["-c"]),
  zsh: new Set(["-c"]),
  dash: new Set(["-c"]),
  python: new Set(["-c"]),
  python3: new Set(["-c"]),
  node: new Set(["-e", "--eval"]),
  ruby: new Set(["-e"]),
  perl: new Set(["-e"]),
};

const INTERPRETERS = new Set(Object.keys(INTERPRETER_FLAGS));

const NETWORK_VERBS = new Set(["curl", "wget"]);

export const codeInjectionAnalyzer: Analyzer = {
  name: "code-injection",

  async analyze(parsed: ParsedCommand[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];

    for (const cmd of parsed) {
      const verb = cmd.verb.toLowerCase();

      // --- eval / exec / source ---
      if (EVAL_VERBS.has(verb) || (verb === "." && cmd.args.length > 0)) {
        const argStr = cmd.args.join(" ");
        const hasSubshell = argStr.includes("$(") || argStr.includes("`");
        const hasCurl = /\bcurl\b|\bwget\b/i.test(argStr);

        let severity: Finding["severity"] = "medium";
        let desc = `\`${verb}\` — dynamic code execution`;

        if (hasCurl) {
          severity = "critical";
          desc = `\`${verb}\` with remote content — arbitrary code execution from network`;
        } else if (hasSubshell) {
          severity = "high";
          desc = `\`${verb}\` with subshell expansion — dynamic code execution`;
        }

        findings.push({ category: "code-injection", severity, description: desc });
      }

      // --- interpreter -c / -e inline code ---
      if (INTERPRETERS.has(verb)) {
        const flags = INTERPRETER_FLAGS[verb];
        for (let i = 0; i < cmd.args.length; i++) {
          if (flags.has(cmd.args[i]) && i + 1 < cmd.args.length) {
            const code = cmd.args.slice(i + 1).join(" ");
            const hasDangerousOps = /\brm\b|\bdel\b|\brmdir\b|\bos\.system\b|\bsubprocess\b|\bchild_process\b|\bexecSync\b|\bspawnSync\b/i.test(code);

            const severity: Finding["severity"] = hasDangerousOps ? "high" : "low";
            const desc = hasDangerousOps
              ? `\`${verb} ${cmd.args[i]}\` — inline code with potentially dangerous operations`
              : `\`${verb} ${cmd.args[i]}\` — inline code execution`;

            findings.push({ category: "code-injection", severity, description: desc });
            break;
          }
        }
      }

      // --- sudo + interpreter inline ---
      if (verb === "sudo" && cmd.args.length > 0) {
        const innerVerb = cmd.args[0].toLowerCase();
        if (INTERPRETERS.has(innerVerb)) {
          const flags = INTERPRETER_FLAGS[innerVerb];
          for (let i = 1; i < cmd.args.length; i++) {
            if (flags.has(cmd.args[i]) && i + 1 < cmd.args.length) {
              findings.push({
                category: "code-injection",
                severity: "high",
                description: `\`sudo ${innerVerb} ${cmd.args[i]}\` — elevated inline code execution`,
              });
              break;
            }
          }
        }
      }

      // --- curl/wget piped to interpreter ---
      if (NETWORK_VERBS.has(verb) && cmd.operator === "|") {
        // Check if the next command in the pipe is an interpreter
        const nextCmd = parsed[cmd.position + 1];
        if (nextCmd) {
          const nextVerb = nextCmd.verb.toLowerCase();
          const actualInterp = nextVerb === "sudo" && nextCmd.args.length > 0
            ? nextCmd.args[0].toLowerCase()
            : nextVerb;
          if (INTERPRETERS.has(actualInterp)) {
            findings.push({
              category: "code-injection",
              severity: "critical",
              description: `\`${verb}\` piped to \`${actualInterp}\` — remote code execution`,
            });
          }
        }
      }

      // --- docker container escape patterns ---
      if (verb === "docker" && cmd.args.length > 0) {
        const subCmd = cmd.args[0];
        if (subCmd === "run" || subCmd === "exec" || subCmd === "create") {
          const argStr = cmd.args.join(" ");

          if (cmd.args.includes("--privileged")) {
            findings.push({
              category: "code-injection",
              severity: "high",
              description: "`docker --privileged` — container has full host access",
            });
          }

          // -v /:/host or --volume /:/something — mounts entire host filesystem
          const volumePattern = /(?:-v|--volume)\s+\/?:\/|(?:-v|--volume)\s+\/[^:]*:\/[^:]*:?/;
          if (volumePattern.test(argStr)) {
            // Check specifically for root mount /:/
            if (/(?:-v|--volume)\s+\/?:\//i.test(argStr)) {
              findings.push({
                category: "code-injection",
                severity: "critical",
                description: "`docker -v /:/...` — host root filesystem mounted in container",
              });
            }
          }

          if (cmd.args.includes("--pid=host") || cmd.args.includes("--net=host")) {
            findings.push({
              category: "code-injection",
              severity: "high",
              description: `\`docker ${cmd.args.find(a => a.startsWith("--pid=") || a.startsWith("--net="))}\` — container shares host namespace`,
            });
          }
        }
      }
    }

    return { findings };
  },
};
