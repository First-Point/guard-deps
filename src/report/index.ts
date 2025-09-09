/**
 * Report generation coordinator
 */

import { writeFile } from 'fs/promises';
import { ScanReport, Config, RiskLevel } from '../types';
import { generateTableReport } from './table-reporter';
import { generateJsonReport } from './json-reporter';
import { generateMarkdownReport } from './markdown-reporter';

/**
 * Generate and output reports based on configuration
 */
export async function generateReports(report: ScanReport, config: Config): Promise<void> {
  // Always generate console output
  if (config.format === 'table' || !config.outputFile) {
    const tableOutput = generateTableReport(report);
    console.log(tableOutput);
  }

  // Generate JSON report if requested
  if (config.outputFile || config.format === 'json') {
    const jsonReport = generateJsonReport(report);
    
    if (config.outputFile) {
      await writeFile(config.outputFile, jsonReport, 'utf-8');
      console.log(`JSON report saved to: ${config.outputFile}`);
    } else if (config.format === 'json') {
      console.log(jsonReport);
    }
  }

  // Generate Markdown report if requested
  if (config.markdownFile || config.format === 'md') {
    const markdownReport = generateMarkdownReport(report);
    
    if (config.markdownFile) {
      await writeFile(config.markdownFile, markdownReport, 'utf-8');
      console.log(`Markdown report saved to: ${config.markdownFile}`);
    } else if (config.format === 'md') {
      console.log(markdownReport);
    }
  }
}

/**
 * Determine exit code based on scan results and configuration
 */
export function determineExitCode(report: ScanReport, config: Config): number {
  const { summary } = report;
  
  switch (config.failOn) {
    case 'compromised':
      return summary.compromised > 0 ? 10 : 0;
    case 'at_risk':
      return (summary.compromised > 0 || summary.at_risk > 0) ? 11 : 0;
    case 'outdated':
      return (summary.compromised > 0 || summary.at_risk > 0 || summary.outdated > 0) ? 11 : 0;
    default:
      return 0;
  }
}

/**
 * Print scan summary to console
 */
export function printSummary(report: ScanReport): void {
  const { summary } = report;
  const total = summary.projects;
  
  console.log('\n=== SCAN SUMMARY ===');
  console.log(`Total projects scanned: ${total}`);
  console.log(`Compromised: ${summary.compromised}`);
  console.log(`At risk: ${summary.at_risk}`);  
  console.log(`Outdated: ${summary.outdated}`);
  console.log(`OK: ${summary.ok}`);
  
  if (summary.compromised > 0) {
    console.log('\n⚠️  CRITICAL: Compromised packages detected!');
  } else if (summary.at_risk > 0) {
    console.log('\n⚠️  WARNING: At-risk packages detected!');
  } else if (summary.outdated > 0) {
    console.log('\n💡 INFO: Some packages are outdated but not compromised.');
  } else {
    console.log('\n✅ All packages appear to be safe.');
  }
}

/**
 * Get risk level color for terminal output
 */
export function getRiskColor(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case 'compromised':
      return '\x1b[31m'; // Red
    case 'at_risk':
      return '\x1b[33m'; // Yellow
    case 'outdated':
      return '\x1b[36m'; // Cyan
    case 'ok':
      return '\x1b[32m'; // Green
    default:
      return '\x1b[0m'; // Reset
  }
}

/**
 * Reset terminal color
 */
export function resetColor(): string {
  return '\x1b[0m';
}

/**
 * Format risk level for display
 */
export function formatRiskLevel(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case 'compromised':
      return 'COMPROMISED';
    case 'at_risk':
      return 'AT RISK';
    case 'outdated':
      return 'OUTDATED';
    case 'ok':
      return 'OK';
  }
}

/**
 * Truncate string to specified length
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

/**
 * Get projects with issues
 */
export function getProblemsOnly(report: ScanReport): ScanReport {
  const problematicProjects = report.projects.filter(p => p.status !== 'ok');
  
  return {
    ...report,
    projects: problematicProjects,
    summary: {
      ...report.summary,
      ok: 0, // Reset ok count since we filtered them out
    },
  };
}