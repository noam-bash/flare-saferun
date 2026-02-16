export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export interface Redirect {
  type: ">" | ">>";
  target: string;
}

export interface ParsedCommand {
  verb: string;
  args: string[];
  operator: string | null;
  redirects: Redirect[];
  rawSegment: string;
  position: number;
}

export interface Finding {
  category: string;
  severity: RiskLevel;
  description: string;
}

export interface AnalyzerResult {
  findings: Finding[];
}

export interface Analyzer {
  name: string;
  analyze(parsed: ParsedCommand[], cwd: string): Promise<AnalyzerResult>;
}

export interface RiskAssessment {
  risk_level: RiskLevel;
  summary: string;
  details: Finding[];
  recommendation: string;
}

export interface Config {
  sensitivePatterns: string[];
  packageAllowlist: string[];
  osvTimeout: number;
}
