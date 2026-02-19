import type { ParsedCommand, Redirect } from "./types.js";
import { homedir } from "os";

const MAX_COMMAND_LENGTH = 10_000;

/**
 * Parse a shell command string into structured segments.
 * Handles pipes, chains (&&, ||, ;), quotes, redirects, subshells, and tilde expansion.
 */
export function parseCommand(command: string): ParsedCommand[] {
  if (command.length > MAX_COMMAND_LENGTH) {
    throw new Error(`Command too long (${command.length} chars, max ${MAX_COMMAND_LENGTH})`);
  }

  // Extract subshell/backtick contents and append them as extra segments
  // so inner commands like $(curl ...) or `rm -rf /` get analyzed
  const expanded = expandSubshells(command);
  const segments = splitByOperator(expanded);
  const results: ParsedCommand[] = [];

  for (let i = 0; i < segments.length; i++) {
    const { segment, operator } = segments[i];
    const trimmed = segment.trim();
    if (!trimmed) continue;

    const redirects = extractRedirects(trimmed);
    const cleaned = removeRedirects(trimmed);
    const tokens = tokenize(cleaned);
    const verb = tokens[0] ?? "";
    const args = tokens.slice(1).map(expandTilde);

    results.push({
      verb,
      args,
      operator,
      redirects,
      rawSegment: trimmed,
      position: results.length,
    });
  }

  return results;
}

interface Segment {
  segment: string;
  operator: string | null;
}

/**
 * Split command string by operators (|, &&, ||, ;) while respecting quotes.
 */
function splitByOperator(cmd: string): Segment[] {
  const results: Segment[] = [];
  let current = "";
  let inQuote = false;
  let quoteChar = "";

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    const next = cmd[i + 1];
    const prev = cmd[i - 1];

    // Handle escape
    if (ch === "\\" && !inQuote) {
      current += ch + (next ?? "");
      i++;
      continue;
    }

    // Handle quotes
    if ((ch === '"' || ch === "'") && prev !== "\\") {
      if (!inQuote) {
        inQuote = true;
        quoteChar = ch;
      } else if (ch === quoteChar) {
        inQuote = false;
      }
      current += ch;
      continue;
    }

    if (inQuote) {
      current += ch;
      continue;
    }

    // Two-char operators: && and ||
    if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      results.push({ segment: current, operator: ch + next });
      current = "";
      i++;
      continue;
    }

    // Single-char operators: | and ;
    if (ch === "|" || ch === ";") {
      results.push({ segment: current, operator: ch });
      current = "";
      continue;
    }

    current += ch;
  }

  if (current.trim()) {
    results.push({ segment: current, operator: null });
  }

  return results;
}

/**
 * Tokenize a single command segment into words, respecting quotes.
 */
function tokenize(segment: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inQuote = false;
  let quoteChar = "";

  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];

    // Handle escape
    if (ch === "\\" && !inQuote) {
      current += segment[i + 1] ?? "";
      i++;
      continue;
    }

    // Handle quotes
    if ((ch === '"' || ch === "'") && (i === 0 || segment[i - 1] !== "\\")) {
      if (!inQuote) {
        inQuote = true;
        quoteChar = ch;
      } else if (ch === quoteChar) {
        inQuote = false;
      } else {
        current += ch;
      }
      continue;
    }

    if (inQuote) {
      current += ch;
      continue;
    }

    // Whitespace splits tokens
    if (ch === " " || ch === "\t") {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += ch;
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

/**
 * Extract redirect targets (> file, >> file) from a command segment.
 */
function extractRedirects(segment: string): Redirect[] {
  const redirects: Redirect[] = [];
  // Match >> or > followed by optional whitespace and a filepath
  const regex = /(>>|>)\s*(\S+)/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(segment)) !== null) {
    redirects.push({
      type: match[1] as ">" | ">>",
      target: expandTilde(match[2]),
    });
  }

  return redirects;
}

/**
 * Remove redirect portions from a segment so they don't appear in args.
 */
function removeRedirects(segment: string): string {
  return segment.replace(/(>>|>)\s*\S+/g, "").trim();
}

/**
 * Extract contents of $(...) and `...` subshells and append them
 * as semicolon-separated segments so they get analyzed.
 * Also extracts process substitutions <(...) and >(...).
 */
function expandSubshells(command: string): string {
  const subshells: string[] = [];

  // Extract $(...) with balanced parentheses (handles nesting)
  extractBalancedSubshells(command, subshells);

  // Extract `...` backticks
  let match: RegExpExecArray | null;
  const backtick = /`([^`]+)`/g;
  while ((match = backtick.exec(command)) !== null) {
    subshells.push(match[1]);
  }

  // Extract process substitutions <(...) and >(...)
  extractProcessSubstitutions(command, subshells);

  // Extract heredoc bodies fed to interpreters
  extractHeredocBodies(command, subshells);

  if (subshells.length === 0) return command;

  // Append subshell contents as additional segments separated by ;
  return command + " ; " + subshells.join(" ; ");
}

/**
 * Extract $(...) subshells using balanced parenthesis counting.
 * Recurses into nested subshells like $(echo $(whoami)).
 */
function extractBalancedSubshells(command: string, out: string[]): void {
  let i = 0;
  while (i < command.length) {
    if (command[i] === "$" && command[i + 1] === "(") {
      const start = i + 2;
      let depth = 1;
      let j = start;
      while (j < command.length && depth > 0) {
        if (command[j] === "(") depth++;
        else if (command[j] === ")") depth--;
        if (depth > 0) j++;
      }
      if (depth === 0) {
        const inner = command.slice(start, j);
        out.push(inner);
        // Recurse to extract nested subshells
        extractBalancedSubshells(inner, out);
        i = j + 1;
        continue;
      }
    }
    i++;
  }
}

/**
 * Extract process substitutions <(...) and >(...).
 */
function extractProcessSubstitutions(command: string, out: string[]): void {
  let i = 0;
  while (i < command.length) {
    if ((command[i] === "<" || command[i] === ">") && command[i + 1] === "(") {
      const start = i + 2;
      let depth = 1;
      let j = start;
      while (j < command.length && depth > 0) {
        if (command[j] === "(") depth++;
        else if (command[j] === ")") depth--;
        if (depth > 0) j++;
      }
      if (depth === 0) {
        out.push(command.slice(start, j));
        i = j + 1;
        continue;
      }
    }
    i++;
  }
}

const INTERPRETER_VERBS = new Set(["bash", "sh", "zsh", "dash", "python", "python3", "node", "ruby", "perl"]);

/**
 * Detect heredocs fed to interpreter verbs (e.g. bash <<EOF ... EOF).
 * Extracts the heredoc body so its contents can be analyzed.
 */
function extractHeredocBodies(command: string, out: string[]): void {
  // Match: interpreter <<[-]?['"]?DELIM['"]? ... DELIM
  const heredocStart = /\b(\w+)\s+<<-?\s*['"]?(\w+)['"]?\s*\n([\s\S]*?)\n\s*\2\b/g;
  let match: RegExpExecArray | null;
  while ((match = heredocStart.exec(command)) !== null) {
    const verb = match[1];
    const body = match[3];
    if (INTERPRETER_VERBS.has(verb) && body.trim()) {
      out.push(body.trim());
    }
  }
}

/**
 * Expand ~ to the user's home directory.
 */
export function expandTilde(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return homedir() + path.slice(1);
  return path;
}
