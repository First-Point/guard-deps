/**
 * Core type definitions for guard-deps security scanner
 */

export interface Config {
  projectsRoot: string;
  ignoreDirs: string[];
  advisorySource: string;
  cwd?: string;
  outputFile?: string;
  markdownFile?: string;
  format: 'table' | 'json' | 'md';
  strict: boolean;
  failOn: 'compromised' | 'at_risk' | 'outdated';
}

export interface PackageManager {
  name: 'npm' | 'yarn' | 'pnpm';
  lockfile: string;
}

export interface DependencyInfo {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
}

export interface ProjectInfo {
  path: string;
  packageJsonPath: string;
  lockfilePath?: string;
  manager: PackageManager;
  dependencies: DependencyInfo[];
}

export interface Advisory {
  package: string;
  badVersions: string[];
  safeVersion: string;
  advisoryId?: string;
  description?: string;
  malwareVersion?: string; // The specific compromised version to detect
}

export interface AdvisoryDatabase {
  [packageName: string]: Advisory;
}

export type RiskLevel = 'compromised' | 'at_risk' | 'outdated' | 'ok';

export interface Finding {
  package: string;
  version: string;
  lockfile?: string;
  advisoryId?: string;
  safeVersion: string;
  fix: string[];
  riskLevel: RiskLevel;
  description?: string;
}

export interface ProjectResult {
  path: string;
  manager: string;
  status: RiskLevel;
  findings: Finding[];
}

export interface ScanSummary {
  projects: number;
  compromised: number;
  at_risk: number;
  outdated: number;
  ok: number;
}

export interface ScanReport {
  scannedAt: string;
  root: string;
  projects: ProjectResult[];
  summary: ScanSummary;
}

export interface CliOptions {
  cwd?: string;
  out?: string;
  md?: string;
  format?: 'table' | 'json' | 'md';
  strict?: boolean;
  failOn?: 'compromised' | 'at_risk' | 'outdated';
  auditAll?: boolean;
}

export interface ParsedLockfile {
  dependencies: DependencyInfo[];
  manager: PackageManager;
}

export interface LockfileParser {
  canParse(lockfilePath: string): boolean;
  parse(lockfilePath: string): Promise<ParsedLockfile>;
}