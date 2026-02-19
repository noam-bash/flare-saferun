export interface ExtractedCommand {
  command: string;
  line: number;
}

/**
 * Extract commands from shell script content (.sh, .bash, .zsh files).
 * Handles line continuations, comments, and function bodies.
 */
export function extractShellCommands(content: string): ExtractedCommand[] {
  const results: ExtractedCommand[] = [];
  const lines = content.split("\n");

  let pendingLine = "";
  let pendingLineNumber = 0;
  let inHeredoc = false;
  let heredocDelim = "";

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];

    // Skip shebang
    if (i === 0 && raw.startsWith("#!")) continue;

    // Handle heredoc body — skip until delimiter
    if (inHeredoc) {
      if (raw.trim() === heredocDelim) {
        inHeredoc = false;
      }
      continue;
    }

    // Handle line continuations (trailing backslash)
    if (pendingLine) {
      pendingLine += " " + raw.trimStart();
    } else {
      pendingLine = raw;
      pendingLineNumber = i + 1; // 1-indexed
    }

    if (pendingLine.endsWith("\\")) {
      pendingLine = pendingLine.slice(0, -1);
      continue;
    }

    const trimmed = pendingLine.trim();
    pendingLine = "";

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Skip pure syntax lines (function declarations, control flow keywords alone)
    if (/^(function\s+\w+|[\w_]+\s*\(\)\s*\{|\{|\}|then|else|elif|fi|do|done|esac|;;)$/.test(trimmed)) continue;

    // Detect heredoc start — we'll skip the body
    const heredocMatch = trimmed.match(/<<-?\s*['"]?(\w+)['"]?\s*$/);
    if (heredocMatch) {
      heredocDelim = heredocMatch[1];
      inHeredoc = true;
      // The command itself (before heredoc) is still valid
      results.push({ command: trimmed, line: pendingLineNumber });
      continue;
    }

    results.push({ command: trimmed, line: pendingLineNumber });
  }

  return results;
}
