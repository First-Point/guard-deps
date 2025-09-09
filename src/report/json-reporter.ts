/**
 * JSON format reporter
 */

import { ScanReport } from '../types';

/**
 * Generate JSON format report
 */
export function generateJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Generate compact JSON report (no formatting)
 */
export function generateCompactJsonReport(report: ScanReport): string {
  return JSON.stringify(report);
}

/**
 * Generate JSON report with only problematic projects
 */
export function generateProblemsOnlyJsonReport(report: ScanReport): string {
  const filteredReport = {
    ...report,
    projects: report.projects.filter(p => p.findings.length > 0),
  };

  // Update summary to reflect filtered results
  const filteredSummary = {
    projects: filteredReport.projects.length,
    compromised: filteredReport.projects.filter(p => p.status === 'compromised').length,
    at_risk: filteredReport.projects.filter(p => p.status === 'at_risk').length,
    outdated: filteredReport.projects.filter(p => p.status === 'outdated').length,
    ok: 0, // No OK projects in problems-only report
  };

  filteredReport.summary = filteredSummary;

  return JSON.stringify(filteredReport, null, 2);
}

/**
 * Generate JSON report with metadata
 */
export function generateMetadataJsonReport(report: ScanReport, metadata?: {
  version?: string;
  command?: string;
  options?: any;
}): string {
  const reportWithMetadata = {
    metadata: {
      toolVersion: metadata?.version || '0.1.0',
      scanCommand: metadata?.command || 'guard-deps scan',
      scanOptions: metadata?.options || {},
      nodeVersion: process.version,
      platform: process.platform,
      generatedAt: new Date().toISOString(),
    },
    ...report,
  };

  return JSON.stringify(reportWithMetadata, null, 2);
}

/**
 * Generate summary-only JSON report
 */
export function generateSummaryJsonReport(report: ScanReport): string {
  const summaryReport = {
    scannedAt: report.scannedAt,
    root: report.root,
    summary: report.summary,
    hasIssues: report.summary.compromised > 0 || report.summary.at_risk > 0,
    criticalIssues: report.summary.compromised,
    totalProjects: report.summary.projects,
  };

  return JSON.stringify(summaryReport, null, 2);
}

/**
 * Generate JSON Lines format (JSONL) for streaming
 */
export function generateJsonLinesReport(report: ScanReport): string {
  let output = '';

  // Add header line
  const header = {
    type: 'header',
    scannedAt: report.scannedAt,
    root: report.root,
    summary: report.summary,
  };
  output += JSON.stringify(header) + '\n';

  // Add each project as a line
  for (const project of report.projects) {
    const projectLine = {
      type: 'project',
      ...project,
    };
    output += JSON.stringify(projectLine) + '\n';
  }

  // Add footer line
  const footer = {
    type: 'footer',
    completedAt: new Date().toISOString(),
  };
  output += JSON.stringify(footer) + '\n';

  return output;
}

/**
 * Parse and validate JSON report
 */
export function parseJsonReport(jsonString: string): ScanReport {
  try {
    const report = JSON.parse(jsonString);
    
    // Basic validation
    if (!report.scannedAt || !report.root || !report.projects || !report.summary) {
      throw new Error('Invalid report format: missing required fields');
    }

    if (!Array.isArray(report.projects)) {
      throw new Error('Invalid report format: projects must be an array');
    }

    return report as ScanReport;
  } catch (error) {
    throw new Error(`Failed to parse JSON report: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Merge multiple JSON reports
 */
export function mergeJsonReports(...reports: ScanReport[]): ScanReport {
  if (reports.length === 0) {
    throw new Error('No reports to merge');
  }

  if (reports.length === 1) {
    return reports[0];
  }

  const merged: ScanReport = {
    scannedAt: new Date().toISOString(),
    root: 'merged',
    projects: [],
    summary: {
      projects: 0,
      compromised: 0,
      at_risk: 0,
      outdated: 0,
      ok: 0,
    },
  };

  for (const report of reports) {
    merged.projects.push(...report.projects);
    merged.summary.projects += report.summary.projects;
    merged.summary.compromised += report.summary.compromised;
    merged.summary.at_risk += report.summary.at_risk;
    merged.summary.outdated += report.summary.outdated;
    merged.summary.ok += report.summary.ok;
  }

  return merged;
}

/**
 * Convert report to CSV format (as JSON for easier parsing)
 */
export function generateCsvDataReport(report: ScanReport): any[] {
  const csvData: any[] = [];

  for (const project of report.projects) {
    if (project.findings.length === 0) {
      // Project with no issues
      csvData.push({
        project: project.path,
        manager: project.manager,
        status: project.status,
        package: '',
        version: '',
        safeVersion: '',
        advisoryId: '',
        riskLevel: 'ok',
        fix: '',
      });
    } else {
      // Project with findings
      for (const finding of project.findings) {
        csvData.push({
          project: project.path,
          manager: project.manager,
          status: project.status,
          package: finding.package,
          version: finding.version,
          safeVersion: finding.safeVersion,
          advisoryId: finding.advisoryId || '',
          riskLevel: finding.riskLevel,
          fix: finding.fix.join(' | '),
        });
      }
    }
  }

  return csvData;
}