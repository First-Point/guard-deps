/**
 * Markdown format reporter
 */

import { ScanReport, ProjectResult, Finding, RiskLevel } from '../types';
import { formatRiskLevel } from './index';

/**
 * Generate markdown format report
 */
export function generateMarkdownReport(report: ScanReport): string {
  let output = '';

  // Add header
  output += generateHeader(report);
  output += generateSummary(report);
  output += generateAffectedProjects(report);
  output += generatePackageOverview(report);
  output += generateRecommendedFixes(report);
  output += generateFooter();

  return output;
}

/**
 * Generate markdown header
 */
function generateHeader(report: ScanReport): string {
  const date = new Date(report.scannedAt).toLocaleString();
  
  return `# 🛡️ Guard-Deps Security Scan Report

**Scanned At:** ${date}  
**Root Directory:** \`${report.root}\`  
**Total Projects:** ${report.summary.projects}

---

`;
}

/**
 * Generate summary section
 */
function generateSummary(report: ScanReport): string {
  const { summary } = report;
  const total = summary.projects;
  
  let output = `## 📊 Summary

| Status | Count | Percentage |
|--------|--------|-----------|
| ✅ OK | ${summary.ok} | ${Math.round((summary.ok / total) * 100)}% |
| 📅 Outdated | ${summary.outdated} | ${Math.round((summary.outdated / total) * 100)}% |
| ⚠️ At Risk | ${summary.at_risk} | ${Math.round((summary.at_risk / total) * 100)}% |
| 🚨 Compromised | ${summary.compromised} | ${Math.round((summary.compromised / total) * 100)}% |

`;

  // Add alert based on findings
  if (summary.compromised > 0) {
    output += `> 🚨 **CRITICAL ALERT:** ${summary.compromised} project(s) contain compromised packages that require immediate attention!\n\n`;
  } else if (summary.at_risk > 0) {
    output += `> ⚠️ **WARNING:** ${summary.at_risk} project(s) contain packages that may be at risk.\n\n`;
  } else if (summary.outdated > 0) {
    output += `> 📅 **INFO:** ${summary.outdated} project(s) contain outdated packages (but not compromised).\n\n`;
  } else {
    output += `> ✅ **ALL CLEAR:** All projects appear to be using safe package versions.\n\n`;
  }

  return output;
}

/**
 * Generate affected projects section
 */
function generateAffectedProjects(report: ScanReport): string {
  const affectedProjects = report.projects.filter(p => p.findings.length > 0);
  
  if (affectedProjects.length === 0) {
    return `## 🎉 No Issues Found

All scanned projects are using safe package versions!

`;
  }

  let output = `## 🎯 Affected Projects

`;

  for (const project of affectedProjects) {
    const statusEmoji = getRiskEmoji(project.status);
    const statusText = formatRiskLevel(project.status);
    
    output += `### ${statusEmoji} \`${project.path}\` - ${statusText}

**Package Manager:** ${project.manager}  
**Issues Found:** ${project.findings.length}

| Package | Current Version | Safe Version | Risk Level | Advisory ID |
|---------|----------------|--------------|------------|-------------|
`;

    for (const finding of project.findings) {
      const riskEmoji = getRiskEmoji(finding.riskLevel);
      output += `| \`${finding.package}\` | ${finding.version} | ${finding.safeVersion} | ${riskEmoji} ${formatRiskLevel(finding.riskLevel)} | ${finding.advisoryId || 'N/A'} |\n`;
    }

    output += '\n';

    // Add fix commands
    if (project.findings.length > 0) {
      output += `**Recommended Actions:**\n\n`;
      for (const finding of project.findings) {
        output += `- **${finding.package}:**\n`;
        for (const fix of finding.fix) {
          output += `  - \`${fix}\`\n`;
        }
        output += '\n';
      }
    }
  }

  return output;
}

/**
 * Generate package overview section
 */
function generatePackageOverview(report: ScanReport): string {
  const allFindings = getAllFindings(report);
  
  if (allFindings.length === 0) {
    return '';
  }

  // Group findings by package name
  const packageGroups = groupFindingsByPackage(allFindings);
  const packageNames = Object.keys(packageGroups).sort();

  let output = `## 📦 Package Overview

The following packages have been identified with security concerns:

| Package | Projects Affected | Highest Risk | Safe Version |
|---------|------------------|--------------|--------------|
`;

  for (const packageName of packageNames) {
    const findings = packageGroups[packageName];
    const projectCount = findings.length;
    const highestRisk = getHighestRiskLevel(findings.map(f => f.riskLevel));
    const riskEmoji = getRiskEmoji(highestRisk);
    const safeVersion = findings[0].safeVersion; // Assume all have same safe version
    
    output += `| \`${packageName}\` | ${projectCount} | ${riskEmoji} ${formatRiskLevel(highestRisk)} | ${safeVersion} |\n`;
  }

  output += '\n';

  return output;
}

/**
 * Generate recommended fixes section
 */
function generateRecommendedFixes(report: ScanReport): string {
  const allFindings = getAllFindings(report);
  
  if (allFindings.length === 0) {
    return '';
  }

  let output = `## 🔧 Recommended Fixes

### Critical Issues (Immediate Action Required)

`;

  const criticalFindings = allFindings.filter(f => f.riskLevel === 'compromised');
  if (criticalFindings.length === 0) {
    output += '*No critical issues found.*\n\n';
  } else {
    for (const finding of criticalFindings) {
      output += `#### 🚨 \`${finding.package}\` (${finding.version} → ${finding.safeVersion})

`;
      if (finding.description) {
        output += `**Description:** ${finding.description}\n\n`;
      }
      if (finding.advisoryId) {
        output += `**Advisory ID:** ${finding.advisoryId}\n\n`;
      }
      output += `**Fix Commands:**\n`;
      for (const fix of finding.fix) {
        output += `\`\`\`bash\n${fix}\n\`\`\`\n`;
      }
      output += '\n';
    }
  }

  // Add other risk levels
  const atRiskFindings = allFindings.filter(f => f.riskLevel === 'at_risk');
  if (atRiskFindings.length > 0) {
    output += `### At-Risk Packages\n\n`;
    for (const finding of atRiskFindings) {
      output += `- **\`${finding.package}\`**: ${finding.version} → ${finding.safeVersion}\n`;
    }
    output += '\n';
  }

  const outdatedFindings = allFindings.filter(f => f.riskLevel === 'outdated');
  if (outdatedFindings.length > 0) {
    output += `### Outdated Packages\n\n`;
    for (const finding of outdatedFindings) {
      output += `- **\`${finding.package}\`**: ${finding.version} → ${finding.safeVersion}\n`;
    }
    output += '\n';
  }

  return output;
}

/**
 * Generate footer
 */
function generateFooter(): string {
  const timestamp = new Date().toISOString();
  
  return `---

*Report generated by Guard-Deps v0.1.0 on ${timestamp}*

**Next Steps:**
1. Review and prioritize critical issues first
2. Update compromised packages immediately  
3. Test your applications after updates
4. Consider implementing automated dependency scanning in your CI/CD pipeline

**Need Help?**
- Check the [Guard-Deps documentation](https://github.com/your-org/guard-deps)
- Report false positives or issues on our GitHub repository
`;
}

/**
 * Get emoji for risk level
 */
function getRiskEmoji(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case 'compromised':
      return '🚨';
    case 'at_risk':
      return '⚠️';
    case 'outdated':
      return '📅';
    case 'ok':
      return '✅';
    default:
      return '❓';
  }
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
 * Group findings by package name
 */
function groupFindingsByPackage(findings: Finding[]): { [packageName: string]: Finding[] } {
  const groups: { [packageName: string]: Finding[] } = {};
  
  for (const finding of findings) {
    if (!groups[finding.package]) {
      groups[finding.package] = [];
    }
    groups[finding.package].push(finding);
  }
  
  return groups;
}

/**
 * Get highest risk level from array
 */
function getHighestRiskLevel(riskLevels: RiskLevel[]): RiskLevel {
  const priority: { [key in RiskLevel]: number } = {
    'ok': 0,
    'outdated': 1,
    'at_risk': 2,
    'compromised': 3,
  };

  let highest: RiskLevel = 'ok';
  let highestPriority = 0;

  for (const level of riskLevels) {
    const levelPriority = priority[level];
    if (levelPriority > highestPriority) {
      highest = level;
      highestPriority = levelPriority;
    }
  }

  return highest;
}

/**
 * Generate executive summary for stakeholders
 */
export function generateExecutiveSummary(report: ScanReport): string {
  const { summary } = report;
  const criticalIssues = summary.compromised;
  const totalIssues = summary.compromised + summary.at_risk + summary.outdated;
  
  let output = `# 📋 Executive Summary

## Security Status: ${criticalIssues > 0 ? '🚨 CRITICAL' : totalIssues > 0 ? '⚠️ ATTENTION NEEDED' : '✅ SECURE'}

**Key Findings:**
- **${summary.projects}** total projects scanned
- **${criticalIssues}** projects with critical security vulnerabilities
- **${totalIssues}** total security issues identified
- **${Math.round((summary.ok / summary.projects) * 100)}%** of projects are secure

`;

  if (criticalIssues > 0) {
    output += `## 🚨 Immediate Action Required

${criticalIssues} project(s) contain compromised packages that pose immediate security risks to your organization. These require urgent attention and should be patched as soon as possible.

`;
  }

  if (summary.at_risk > 0) {
    output += `## ⚠️ Risk Assessment

${summary.at_risk} project(s) contain packages that may be vulnerable. While not immediately compromised, these should be updated as part of your regular maintenance schedule.

`;
  }

  output += `## 📈 Recommendations

1. **Immediate:** Address all compromised packages within 24-48 hours
2. **Short-term:** Update at-risk packages within 1-2 weeks  
3. **Long-term:** Implement automated dependency scanning in CI/CD pipeline
4. **Process:** Establish regular security review meetings

---

*For technical details, see the full security report.*
`;

  return output;
}