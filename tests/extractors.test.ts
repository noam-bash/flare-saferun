import { describe, it, expect } from "vitest";
import { extractShellCommands } from "../src/extractors/shell.js";
import { extractDockerfileCommands } from "../src/extractors/dockerfile.js";
import { extractCiCommands } from "../src/extractors/ci.js";

describe("extractShellCommands", () => {
  it("extracts simple commands", () => {
    const content = `#!/bin/bash
echo hello
ls -la
rm -rf /tmp/data`;
    const result = extractShellCommands(content);
    expect(result).toHaveLength(3);
    expect(result[0].command).toBe("echo hello");
    expect(result[0].line).toBe(2);
    expect(result[1].command).toBe("ls -la");
    expect(result[2].command).toBe("rm -rf /tmp/data");
  });

  it("skips comments and empty lines", () => {
    const content = `#!/bin/bash

# This is a comment
echo hello

# Another comment
echo world`;
    const result = extractShellCommands(content);
    expect(result).toHaveLength(2);
    expect(result[0].command).toBe("echo hello");
    expect(result[1].command).toBe("echo world");
  });

  it("handles line continuations", () => {
    const content = `curl -X POST \\
  -H "Content-Type: json" \\
  http://example.com`;
    const result = extractShellCommands(content);
    expect(result).toHaveLength(1);
    expect(result[0].command).toContain("curl");
    expect(result[0].command).toContain("http://example.com");
    expect(result[0].line).toBe(1);
  });

  it("skips heredoc bodies", () => {
    const content = `cat <<EOF
rm -rf /
dangerous command
EOF
echo done`;
    const result = extractShellCommands(content);
    expect(result).toHaveLength(2); // cat <<EOF and echo done
    expect(result.some(r => r.command.includes("rm -rf"))).toBe(false);
  });

  it("skips function declarations and control flow", () => {
    const content = `function cleanup() {
  rm -rf /tmp/work
}
if [ -f foo ]; then
  echo found
fi`;
    const result = extractShellCommands(content);
    // Should extract rm -rf and the if/echo lines but not function/then/fi/{}
    const commands = result.map(r => r.command);
    expect(commands).toContain("rm -rf /tmp/work");
    expect(commands.some(c => c.includes("echo found"))).toBe(true);
  });

  it("handles pipe chains as single commands", () => {
    const content = `cat /etc/passwd | grep root | wc -l`;
    const result = extractShellCommands(content);
    expect(result).toHaveLength(1);
    expect(result[0].command).toContain("|");
  });
});

describe("extractDockerfileCommands", () => {
  it("extracts RUN instructions", () => {
    const content = `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
COPY . /app
RUN npm install`;
    const result = extractDockerfileCommands(content);
    expect(result).toHaveLength(2);
    expect(result[0].command).toContain("apt-get update");
    expect(result[0].line).toBe(2);
    expect(result[1].command).toBe("npm install");
  });

  it("handles multi-line RUN with backslash", () => {
    const content = `FROM node:18
RUN apt-get update \\
    && apt-get install -y \\
    curl \\
    wget
RUN echo done`;
    const result = extractDockerfileCommands(content);
    expect(result).toHaveLength(2);
    expect(result[0].command).toContain("apt-get update");
    expect(result[0].command).toContain("wget");
    expect(result[0].line).toBe(2);
  });

  it("skips comments", () => {
    const content = `# Comment
FROM ubuntu
# Another comment
RUN echo hello`;
    const result = extractDockerfileCommands(content);
    expect(result).toHaveLength(1);
    expect(result[0].command).toBe("echo hello");
  });

  it("skips exec form RUN", () => {
    const content = `FROM ubuntu
RUN ["echo", "hello"]
RUN rm -rf /tmp`;
    const result = extractDockerfileCommands(content);
    expect(result).toHaveLength(1);
    expect(result[0].command).toBe("rm -rf /tmp");
  });

  it("handles empty Dockerfile", () => {
    const result = extractDockerfileCommands("");
    expect(result).toHaveLength(0);
  });
});

describe("extractCiCommands", () => {
  it("extracts GitHub Actions run commands", () => {
    const content = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
      - run: npm test`;
    const result = extractCiCommands(content);
    expect(result).toHaveLength(2);
    expect(result[0].command).toBe("npm install");
    expect(result[1].command).toBe("npm test");
  });

  it("extracts multi-line run blocks", () => {
    const content = `jobs:
  build:
    steps:
      - run: |
          echo hello
          npm install
          npm test`;
    const result = extractCiCommands(content);
    expect(result.length).toBeGreaterThanOrEqual(1);
    const allCommands = result.map(r => r.command).join("\n");
    expect(allCommands).toContain("echo hello");
    expect(allCommands).toContain("npm install");
  });

  it("extracts GitLab CI script commands", () => {
    const content = `build:
  script:
    - npm install
    - npm run build
    - npm test`;
    const result = extractCiCommands(content);
    expect(result).toHaveLength(3);
    expect(result[0].command).toBe("npm install");
    expect(result[1].command).toBe("npm run build");
    expect(result[2].command).toBe("npm test");
  });

  it("skips comments", () => {
    const content = `# CI pipeline
jobs:
  build:
    steps:
      # Install deps
      - run: npm install`;
    const result = extractCiCommands(content);
    expect(result).toHaveLength(1);
    expect(result[0].command).toBe("npm install");
  });

  it("handles empty content", () => {
    const result = extractCiCommands("");
    expect(result).toHaveLength(0);
  });
});
