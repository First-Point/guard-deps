/**
 * Table format reporter for console output
 */

import Table from 'cli-table3';
import { ScanReport, ProjectResult, Finding } from '../types';
import { formatRiskLevel, getRiskColor, resetColor, truncate } from './index';

/**
 * Generate table format report
 */
export function generateTableReport(report: ScanReport): string {
  let output = '';
  
  // Add header
  output += '='.repeat(80) + '\n';
  output += `GUARD-DEPS SECURITY SCAN REPORT\n`;
  output += `Scanned: ${new Date(report.scannedAt).toLocaleString()}\n`;
  output += `Root: ${report.root}\n`;
  output += '='.repeat(80) + '\n\n';

  // Filter projects with issues for main table
  const projectsWithIssues = report.projects.filter(p => p.findings.length > 0);

  if (projectsWithIssues.length === 0) {
    output += '✅ No security issues found in any projects!\n\n';
  } else {
    // Create main table
    const table = new Table({
      head: ['Project', 'Status', 'Package', 'Current', 'Safe', 'Action'],
      colWidths: [25, 12, 20, 12, 12, 30],
      wordWrap: true,
    });

    for (const project of projectsWithIssues) {
      if (project.findings.length === 0) continue;

      // Add first finding with project info
      const firstFinding = project.findings[0];
      const projectPath = truncate(project.path, 23);
      const statusColor = getRiskColor(project.status);
      const status = formatRiskLevel(project.status);
      
      table.push([
        projectPath,
        `${statusColor}${status}${resetColor()}`,
        truncate(firstFinding.package, 18),
        truncate(firstFinding.version, 10),
        truncate(firstFinding.safeVersion, 10),
        truncate(firstFinding.fix[0] || '', 28),
      ]);

      // Add remaining findings for this project
      for (let i = 1; i < project.findings.length; i++) {
        const finding = project.findings[i];
        table.push([
          '', // Empty project column
          '', // Empty status column
          truncate(finding.package, 18),
          truncate(finding.version, 10),
          truncate(finding.safeVersion, 10),
          truncate(finding.fix[0] || '', 28),
        ]);
      }
    }

    output += table.toString() + '\n\n';
  }

  // Add summary
  output += generateSummaryTable(report);
  
  // Add detailed findings if there are any critical issues
  const criticalFindings = getAllFindings(report).filter(f => f.riskLevel === 'compromised');
  if (criticalFindings.length > 0) {
    output += '\n' + generateDetailedFindingsTable(criticalFindings);
  }

  return output;
}

/**
 * Generate summary table
 */
function generateSummaryTable(report: ScanReport): string {
  const summaryTable = new Table({
    head: ['Status', 'Count', 'Percentage'],
  });

  const { summary } = report;
  const total = summary.projects;

  const rows = [
    ['Total Projects', total, '100%'],
    [`${getRiskColor('ok')}OK${resetColor()}`, summary.ok, `${Math.round((summary.ok / total) * 100)}%`],
    [`${getRiskColor('outdated')}Outdated${resetColor()}`, summary.outdated, `${Math.round((summary.outdated / total) * 100)}%`],
    [`${getRiskColor('at_risk')}At Risk${resetColor()}`, summary.at_risk, `${Math.round((summary.at_risk / total) * 100)}%`],
    [`${getRiskColor('compromised')}Compromised${resetColor()}`, summary.compromised, `${Math.round((summary.compromised / total) * 100)}%`],
  ];

  summaryTable.push(...rows);
  
  return 'SUMMARY:\n' + summaryTable.toString();
}

/**
 * Generate detailed findings table for critical issues
 */
function generateDetailedFindingsTable(findings: Finding[]): string {
  let output = 'CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:\n';
  
  const detailTable = new Table({
    head: ['Package', 'Version', 'Advisory ID', 'Description', 'Fix Command'],
    colWidths: [20, 12, 15, 30, 35],
    wordWrap: true,
  });

  for (const finding of findings) {
    detailTable.push([
      finding.package,
      finding.version,
      finding.advisoryId || 'N/A',
      finding.description || 'No description available',
      finding.fix.join('\n') || 'No fix available',
    ]);
  }

  return output + detailTable.toString();
}

/**
 * Generate compact table for CI/CD environments
 */
export function generateCompactTable(report: ScanReport): string {
  const projectsWithIssues = report.projects.filter(p => p.findings.length > 0);
  
  if (projectsWithIssues.length === 0) {
    return '✅ No issues found';
  }

  let output = `⚠️  Found issues in ${projectsWithIssues.length} projects:\n`;
  
  for (const project of projectsWithIssues) {
    const status = formatRiskLevel(project.status);
    const findings = project.findings.length;
    output += `  - ${project.path}: ${status} (${findings} issues)\n`;
  }
  
  return output;
}

/**
 * Get all findings from all projects
 */
function getAllFindings(report: ScanReport): Finding[] {
  const allFindings: Finding[] = [];
  
  for (const project of report.projects) {
    allFindings.push(...project.findings);
  }
  
  return allFindings;
}

/**
 * Generate ASCII art header for terminal
 */
export function generateAsciiHeader(): string {
  return `
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           GUARD-DEPS SCANNER                                 ║
║                     NPM Dependency Security Analysis                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`;
}

/**
 * Generate table with fix recommendations
 */
export function generateFixRecommendationsTable(report: ScanReport): string {
  const allFindings = getAllFindings(report);
  if (allFindings.length === 0) return '';

  const fixTable = new Table({
    head: ['Package', 'Issue', 'Recommended Action'],
    colWidths: [25, 15, 50],
    wordWrap: true,
  });

  for (const finding of allFindings) {
    fixTable.push([
      finding.package,
      formatRiskLevel(finding.riskLevel),
      finding.fix.join('\n'),
    ]);
  }

  return '\nRECOMMENDED FIXES:\n' + fixTable.toString();
}