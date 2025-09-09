/**
 * Dependency analysis and risk assessment
 */

import * as semver from 'semver';
import { 
  ProjectInfo, 
  DependencyInfo, 
  AdvisoryDatabase, 
  Advisory,
  Finding,
  RiskLevel,
  ProjectResult,
  ScanReport,
  ScanSummary,
  Config
} from './types';
import { parseProjectDependencies } from './lock-parser';
import { getAdvisory } from './advisory';

/**
 * Analyze all projects for security issues
 */
export async function analyzeProjects(
  projects: ProjectInfo[],
  advisories: AdvisoryDatabase,
  config: Config
): Promise<ScanReport> {
  const projectResults: ProjectResult[] = [];
  
  console.log(`Analyzing ${projects.length} projects for security issues...`);
  
  for (const project of projects) {
    try {
      const result = await analyzeProject(project, advisories, config);
      projectResults.push(result);
    } catch (error) {
      console.warn(`Failed to analyze project ${project.path}:`, error);
      
      // Add failed project with error status
      projectResults.push({
        path: project.path,
        manager: project.manager.name,
        status: 'ok', // Default to ok for failed analysis to not block other results
        findings: [],
      });
    }
  }
  
  const summary = calculateSummary(projectResults);
  
  return {
    scannedAt: new Date().toISOString(),
    root: config.projectsRoot,
    projects: projectResults,
    summary,
  };
}

/**
 * Analyze a single project for security issues
 */
export async function analyzeProject(
  project: ProjectInfo,
  advisories: AdvisoryDatabase,
  config: Config
): Promise<ProjectResult> {
  // Parse dependencies from lockfile or package.json
  const dependencies = await parseProjectDependencies(project);
  
  // Analyze each dependency
  const findings: Finding[] = [];
  
  for (const dependency of dependencies) {
    const finding = analyzeDependency(dependency, advisories, project, config);
    if (finding) {
      findings.push(finding);
    }
  }
  
  // Determine overall project status
  const status = determineProjectStatus(findings, config);
  
  return {
    path: project.path,
    manager: project.manager.name,
    status,
    findings,
  };
}

/**
 * Analyze a single dependency for security issues
 */
export function analyzeDependency(
  dependency: DependencyInfo,
  advisories: AdvisoryDatabase,
  project: ProjectInfo,
  config: Config
): Finding | null {
  const advisory = getAdvisory(advisories, dependency.name);
  if (!advisory) {
    return null; // No advisory found, dependency is ok
  }
  
  const riskLevel = assessRisk(dependency.version, advisory, config);
  if (riskLevel === 'ok') {
    return null; // No risk found
  }
  
  const fixCommands = generateFixCommands(dependency, advisory, project.manager.name);
  
  return {
    package: dependency.name,
    version: dependency.version,
    lockfile: project.lockfilePath ? project.manager.lockfile : undefined,
    advisoryId: advisory.advisoryId,
    safeVersion: advisory.safeVersion,
    fix: fixCommands,
    riskLevel,
    description: advisory.description,
  };
}

/**
 * Assess risk level for a dependency version against advisory
 */
export function assessRisk(
  currentVersion: string,
  advisory: Advisory,
  config: Config
): RiskLevel {
  // Check if current version matches any bad version patterns
  for (const badVersionPattern of advisory.badVersions) {
    if (matchesVersionPattern(currentVersion, badVersionPattern)) {
      return 'compromised';
    }
  }
  
  // Check if current version could resolve to a bad version
  if (!config.strict) {
    for (const badVersionPattern of advisory.badVersions) {
      if (couldResolveToPattern(currentVersion, badVersionPattern)) {
        return 'at_risk';
      }
    }
  }
  
  // Note: For this security model, we only flag versions HIGHER than safe versions
  // Versions LOWER than safe versions are considered OK (not a security risk)
  
  return 'ok';
}

/**
 * Check if version matches a pattern (e.g., "=1.2.3", ">1.2.3", ">=1.2.0 <2.0.0")
 */
function matchesVersionPattern(version: string, pattern: string): boolean {
  try {
    const cleanVersion = semver.coerce(version);
    if (!cleanVersion) return false;
    
    // Handle exact match pattern (=1.2.3)
    if (pattern.startsWith('=')) {
      const targetVersion = pattern.substring(1);
      return semver.eq(cleanVersion, semver.coerce(targetVersion) || targetVersion);
    }
    
    // Handle greater than pattern (>1.2.3) - versions higher than safe version are bad
    if (pattern.startsWith('>')) {
      const safeVersion = pattern.substring(1);
      const safeSemver = semver.coerce(safeVersion);
      if (!safeSemver) return false;
      return semver.gt(cleanVersion, safeSemver);
    }
    
    // Handle range patterns
    return semver.satisfies(cleanVersion, pattern);
  } catch {
    // Fallback to simple string comparison for invalid semver
    if (pattern.startsWith('=')) {
      return version === pattern.replace(/^=/, '');
    }
    if (pattern.startsWith('>')) {
      // Simple string comparison fallback for > pattern
      const safeVersion = pattern.substring(1);
      return version > safeVersion;
    }
    return false;
  }
}

/**
 * Check if a version range could resolve to match a bad pattern
 */
function couldResolveToPattern(versionRange: string, badPattern: string): boolean {
  try {
    const range = semver.validRange(versionRange);
    if (!range) return false;
    
    // Handle > pattern (versions higher than safe are bad)
    if (badPattern.startsWith('>')) {
      const safeVersion = badPattern.substring(1);
      const safeSemver = semver.coerce(safeVersion);
      if (!safeSemver) return false;
      
      // Check if the range could include versions higher than safe version
      const maxSatisfying = semver.maxSatisfying(['999.999.999'], range);
      return maxSatisfying ? semver.gt(maxSatisfying, safeSemver) : false;
    }
    
    // Handle = pattern (exact bad version)
    const badVersion = badPattern.replace(/^=/, '');
    const badVersionSemver = semver.coerce(badVersion);
    if (!badVersionSemver) return false;
    
    return semver.satisfies(badVersionSemver, range);
  } catch {
    return false;
  }
}

/**
 * Generate fix commands for a finding
 */
function generateFixCommands(
  dependency: DependencyInfo,
  advisory: Advisory,
  packageManager: string
): string[] {
  const commands: string[] = [];
  
  switch (packageManager) {
    case 'npm':
      commands.push(`npm install ${dependency.name}@${advisory.safeVersion}`);
      commands.push(`Pin ${dependency.name} to ${advisory.safeVersion} in package.json`);
      break;
    case 'yarn':
      commands.push(`yarn add ${dependency.name}@${advisory.safeVersion}`);
      commands.push(`Add resolution for ${dependency.name}@${advisory.safeVersion} to package.json`);
      break;
    case 'pnpm':
      commands.push(`pnpm add ${dependency.name}@${advisory.safeVersion}`);
      commands.push(`Add override for ${dependency.name}@${advisory.safeVersion} to package.json`);
      break;
  }
  
  return commands;
}

/**
 * Determine overall project status based on findings
 */
function determineProjectStatus(findings: Finding[], config: Config): RiskLevel {
  if (findings.length === 0) return 'ok';
  
  // Find the highest risk level
  const riskLevels: RiskLevel[] = ['compromised', 'at_risk', 'outdated', 'ok'];
  
  for (const riskLevel of riskLevels) {
    if (findings.some(f => f.riskLevel === riskLevel)) {
      return riskLevel;
    }
  }
  
  return 'ok';
}

/**
 * Calculate summary statistics from project results
 */
function calculateSummary(projectResults: ProjectResult[]): ScanSummary {
  const summary: ScanSummary = {
    projects: projectResults.length,
    compromised: 0,
    at_risk: 0,
    outdated: 0,
    ok: 0,
  };
  
  for (const project of projectResults) {
    switch (project.status) {
      case 'compromised':
        summary.compromised++;
        break;
      case 'at_risk':
        summary.at_risk++;
        break;
      case 'outdated':
        summary.outdated++;
        break;
      case 'ok':
        summary.ok++;
        break;
    }
  }
  
  return summary;
}

/**
 * Filter findings by risk level
 */
export function filterFindingsByRisk(findings: Finding[], minRiskLevel: RiskLevel): Finding[] {
  const riskOrder: { [key in RiskLevel]: number } = {
    'ok': 0,
    'outdated': 1,
    'at_risk': 2,
    'compromised': 3,
  };
  
  const minLevel = riskOrder[minRiskLevel];
  
  return findings.filter(finding => riskOrder[finding.riskLevel] >= minLevel);
}

/**
 * Get unique packages across all findings
 */
export function getUniquePackagesFromFindings(findings: Finding[]): string[] {
  const packages = new Set<string>();
  findings.forEach(f => packages.add(f.package));
  return Array.from(packages).sort();
}

/**
 * Group findings by package name
 */
export function groupFindingsByPackage(findings: Finding[]): { [packageName: string]: Finding[] } {
  const grouped: { [packageName: string]: Finding[] } = {};
  
  for (const finding of findings) {
    if (!grouped[finding.package]) {
      grouped[finding.package] = [];
    }
    grouped[finding.package].push(finding);
  }
  
  return grouped;
}