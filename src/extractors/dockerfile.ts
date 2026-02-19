import type { ExtractedCommand } from "./shell.js";

/**
 * Extract RUN instructions from Dockerfile content.
 * Handles multi-line RUN commands with backslash continuations.
 */
export function extractDockerfileCommands(content: string): ExtractedCommand[] {
  const results: ExtractedCommand[] = [];
  const lines = content.split("\n");

  let inRun = false;
  let runCommand = "";
  let runStartLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();

    // Skip comments
    if (trimmed.startsWith("#")) continue;

    if (inRun) {
      runCommand += " " + trimmed;
      if (!trimmed.endsWith("\\")) {
        // End of multi-line RUN
        inRun = false;
        emitRunCommands(runCommand, runStartLine, results);
        runCommand = "";
      } else {
        runCommand = runCommand.slice(0, -1); // Remove trailing backslash
      }
      continue;
    }

    // Match RUN instruction (case-insensitive per Dockerfile spec)
    const runMatch = trimmed.match(/^RUN\s+(.+)$/i);
    if (runMatch) {
      let cmd = runMatch[1];
      runStartLine = i + 1; // 1-indexed

      if (cmd.endsWith("\\")) {
        inRun = true;
        runCommand = cmd.slice(0, -1);
      } else {
        emitRunCommands(cmd, runStartLine, results);
      }
    }
  }

  return results;
}

/**
 * Split a RUN instruction on && and ; to get individual commands.
 * Handles shell form (RUN cmd) and exec form (RUN ["cmd"]) — only shell form yields analyzable commands.
 */
function emitRunCommands(runBody: string, line: number, out: ExtractedCommand[]): void {
  const trimmed = runBody.trim();

  // Exec form: RUN ["executable", "param1", "param2"]
  if (trimmed.startsWith("[")) return;

  // The entire RUN body is a shell command — push it as-is
  // The parser will handle && and ; splitting
  out.push({ command: trimmed, line });
}
