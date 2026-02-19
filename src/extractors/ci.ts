import type { ExtractedCommand } from "./shell.js";

/**
 * Extract run/script commands from GitHub Actions and GitLab CI YAML files.
 * Uses lightweight line-by-line parsing — no YAML dependency required.
 */
export function extractCiCommands(content: string): ExtractedCommand[] {
  const results: ExtractedCommand[] = [];
  const lines = content.split("\n");

  let inRunBlock = false;
  let runIndent = 0;
  let pendingCommand = "";
  let pendingLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();

    // Skip comments and empty lines
    if (trimmed.startsWith("#") || !trimmed) {
      if (inRunBlock && pendingCommand) {
        results.push({ command: pendingCommand.trim(), line: pendingLine });
        pendingCommand = "";
      }
      continue;
    }

    // Calculate indentation
    const indent = raw.length - raw.trimStart().length;

    // Check if we've exited the run block (dedented)
    if (inRunBlock && indent <= runIndent && !trimmed.startsWith("-")) {
      if (pendingCommand) {
        results.push({ command: pendingCommand.trim(), line: pendingLine });
        pendingCommand = "";
      }
      inRunBlock = false;
    }

    // GitHub Actions: "run: |" or "run: command" or "- run: |"
    const ghRunMatch = trimmed.match(/^-?\s*run:\s*\|?\s*(.*)$/);
    if (ghRunMatch) {
      const inlineCmd = ghRunMatch[1].trim();
      if (inlineCmd && inlineCmd !== "|") {
        results.push({ command: inlineCmd, line: i + 1 });
      } else {
        // Multi-line run block
        inRunBlock = true;
        runIndent = indent;
      }
      continue;
    }

    // GitLab CI: "script:" followed by "- command" lines
    const gitlabScriptMatch = trimmed.match(/^script:\s*$/);
    if (gitlabScriptMatch) {
      inRunBlock = true;
      runIndent = indent;
      continue;
    }

    // Inside a run/script block
    if (inRunBlock) {
      // List item: "- command"
      const listItem = trimmed.match(/^-\s+(.+)$/);
      if (listItem) {
        if (pendingCommand) {
          results.push({ command: pendingCommand.trim(), line: pendingLine });
        }
        pendingCommand = listItem[1];
        pendingLine = i + 1;
        continue;
      }

      // Continuation of multi-line run (not a list item, same or deeper indent)
      if (indent > runIndent) {
        if (!pendingCommand) {
          pendingCommand = trimmed;
          pendingLine = i + 1;
        } else {
          pendingCommand += "\n" + trimmed;
        }
        continue;
      }
    }
  }

  // Flush any remaining command
  if (pendingCommand) {
    results.push({ command: pendingCommand.trim(), line: pendingLine });
  }

  return results;
}
