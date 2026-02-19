export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export type Action = "run" | "warn" | "ask";

export type ActionPolicy = Record<RiskLevel, Action>;

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
  partial?: boolean;
}

export interface Analyzer {
  name: string;
  analyze(parsed: ParsedCommand[], cwd: string): Promise<AnalyzerResult>;
}

export interface RiskAssessment {
  risk_level: RiskLevel;
  action: Action;
  summary: string;
  details: Finding[];
  recommendation: string;
  partial?: boolean;
}

export interface Config {
  actionPolicy: ActionPolicy;
  sensitivePatterns: string[];
  packageAllowlist: string[];
  osvTimeout: number;
  safeHosts: string[];
  commandAllowlist: string[];
  logFile: string | false;
}
