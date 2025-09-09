#!/usr/bin/env node

/**
 * Guard-Deps CLI - NPM Dependency Security Scanner
 */

import { Command } from 'commander';
import { loadConfig, validateConfig, getOutputPath } from './env';
import { discoverProjects } from './discover';
import { loadAdvisories } from './advisory';
import { analyzeProjects } from './analyze';
import { generateReports, determineExitCode, printSummary } from './report';
import { fixCompromisedPackages, printFixReport, FixOptions } from './fix';
import { CliOptions, ProjectInfo } from './types';
import { exec } from 'child_process';
import { promisify } from 'util';
import { join } from 'path';

const execAsync = promisify(exec);

const program = new Command();

// Package info
const packageJson = require('../package.json');

program
  .name('guard-deps')
  .description('NPM Dependency Security Scanner - Detect compromised packages and suggest fixes')
  .version(packageJson.version);

// Main scan command
program
  .command('scan')
  .description('Scan for compromised NPM dependencies')
  .option('--cwd <dir>', 'Scan a single project directory')
  .option('--out <file>', 'Output JSON report to file')
  .option('--md <file>', 'Output Markdown report to file')
  .option('--format <type>', 'Output format: table, json, md', 'table')
  .option('--strict', 'Only fail on confirmed compromised versions')
  .option('--fail-on <level>', 'Fail on: compromised, at_risk, outdated', 'compromised')
  .action(async (options: CliOptions) => {
    try {
      await runScan(options);
    } catch (error) {
      console.error('❌ Scan failed:', error instanceof Error ? error.message : error);
      process.exit(2); // Configuration error
    }
  });

// Version command (already handled by commander, but we can add more info)
program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(`Guard-Deps v${packageJson.version}`);
    console.log(`Node.js ${process.version}`);
    console.log(`Platform: ${process.platform}`);
  });

// Info command to show configuration
program
  .command('info')
  .description('Show current configuration')
  .action(() => {
    try {
      const config = loadConfig();
      console.log('Current Configuration:');
      console.log(`  Projects Root: ${config.projectsRoot}`);
      console.log(`  Advisory Source: ${config.advisorySource}`);
      console.log(`  Ignore Directories: ${config.ignoreDirs.join(', ')}`);
      console.log(`  Format: ${config.format}`);
      console.log(`  Strict Mode: ${config.strict}`);
      console.log(`  Fail On: ${config.failOn}`);
    } catch (error) {
      console.error('❌ Configuration error:', error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

// Fix command to automatically fix compromised packages
program
  .command('fix')
  .description('Automatically fix compromised packages by downgrading to safe versions')
  .option('--cwd <dir>', 'Fix packages in specific directory')
  .option('--dry-run', 'Show what would be fixed without making changes')
  .option('--no-force', 'Disable force installation and overrides')
  .option('--skip-node-modules', 'Skip removing node_modules directory')
  .option('--no-backup', 'Skip creating backup of package.json')
  .option('--no-rescan', 'Skip automatic re-scan after fix')
  .action(async (options: CliOptions & { 
    dryRun?: boolean; 
    force?: boolean; 
    skipNodeModules?: boolean; 
    backup?: boolean; 
    rescan?: boolean; 
  }) => {
    try {
      await runFix(options);
    } catch (error) {
      console.error('❌ Fix failed:', error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

// List command to show discovered projects without scanning
program
  .command('list')
  .description('List all discovered Node.js projects')
  .option('--cwd <dir>', 'List projects in specific directory')
  .action(async (options: CliOptions) => {
    try {
      const config = loadConfig(options);
      validateConfig(config);
      
      console.log('🔍 Discovering Node.js projects...');
      const projects = await discoverProjects(config);
      
      console.log(`\nFound ${projects.length} Node.js projects:\n`);
      
      for (const project of projects) {
        const lockfileStatus = project.lockfilePath ? '✓' : '✗';
        console.log(`  ${lockfileStatus} ${project.path} (${project.manager.name})`);
      }
      
      if (projects.length === 0) {
        console.log('  No Node.js projects found');
        process.exit(1);
      }
    } catch (error) {
      console.error('❌ Discovery failed:', error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

/**
 * Main scan logic
 */
async function runScan(options: CliOptions): Promise<void> {
  const startTime = Date.now();
  
  // Load and validate configuration
  console.log('📋 Loading configuration...');
  const config = loadConfig(options);
  validateConfig(config);
  
  // Load advisory database
  console.log('🔒 Loading security advisories...');
  const advisories = await loadAdvisories(config.advisorySource);
  const advisoryCount = Object.keys(advisories).length;
  console.log(`   Loaded ${advisoryCount} security advisories`);
  
  if (advisoryCount === 0) {
    console.warn('⚠️  Warning: No security advisories loaded. All packages will appear safe.');
  }
  
  // Discover projects
  console.log('🔍 Discovering Node.js projects...');
  const projects = await discoverProjects(config);
  
  if (projects.length === 0) {
    console.log('✅ No Node.js projects found to scan');
    return;
  }
  
  // Analyze projects for security issues
  console.log('🔍 Analyzing dependencies for security issues...');
  const report = await analyzeProjects(projects, advisories, config);
  
  // Run npm audit on projects to get additional vulnerability info
  console.log('🔍 Running npm audit for additional vulnerability detection...');
  await runAuditOnProjects(projects);
  
  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);
  
  // Generate and output reports
  await generateReports(report, config);
  
  // Print summary
  printSummary(report);
  console.log(`\n⏱️  Scan completed in ${duration}s`);
  
  // Determine exit code based on findings
  const exitCode = determineExitCode(report, config);
  
  if (exitCode > 0) {
    const level = config.failOn;
    console.log(`\n💥 Exiting with code ${exitCode} due to ${level} issues found`);
  }
  
  process.exit(exitCode);
}

/**
 * Main fix logic
 */
async function runFix(options: CliOptions & { 
  dryRun?: boolean; 
  force?: boolean; 
  skipNodeModules?: boolean; 
  backup?: boolean; 
  rescan?: boolean; 
}): Promise<void> {
  const startTime = Date.now();
  
  // Load and validate configuration
  console.log('📋 Loading configuration...');
  const config = loadConfig(options);
  validateConfig(config);
  
  // Load advisory database
  console.log('🔒 Loading security advisories...');
  const advisories = await loadAdvisories(config.advisorySource);
  const advisoryCount = Object.keys(advisories).length;
  console.log(`   Loaded ${advisoryCount} security advisories`);
  
  if (advisoryCount === 0) {
    console.log('❌ Error: No security advisories loaded. Cannot fix packages without advisory data.');
    process.exit(2);
  }
  
  // Discover and analyze projects first
  console.log('🔍 Scanning for compromised packages...');
  const projects = await discoverProjects(config);
  
  if (projects.length === 0) {
    console.log('✅ No Node.js projects found to fix');
    return;
  }
  
  const scanReport = await analyzeProjects(projects, advisories, config);
  const compromisedProjects = scanReport.projects.filter(p => p.findings.length > 0);
  
  if (compromisedProjects.length === 0) {
    console.log('✅ No compromised packages found. Nothing to fix!');
    return;
  }
  
  console.log(`\n🎯 Found ${compromisedProjects.length} projects with compromised packages`);
  
  // Prepare fix options
  const fixOptions: FixOptions = {
    dryRun: options.dryRun || false,
    force: options.force !== false, // Default to true unless --no-force
    skipNodeModules: options.skipNodeModules || false,
    backup: options.backup !== false, // Default to true unless --no-backup
  };
  
  // Execute fixes
  const fixReport = await fixCompromisedPackages(compromisedProjects, config, fixOptions);
  
  // Print fix results
  printFixReport(fixReport);
  
  // Re-scan if requested and fixes were applied
  if (options.rescan !== false && !options.dryRun && fixReport.fixedProjects > 0) {
    console.log('\n🔍 Re-scanning to verify fixes...');
    
    const newScanReport = await analyzeProjects(projects, advisories, config);
    const remainingIssues = newScanReport.projects.filter(p => p.findings.length > 0);
    
    if (remainingIssues.length === 0) {
      console.log('✅ All issues have been resolved!');
    } else {
      console.log(`⚠️  ${remainingIssues.length} projects still have issues:`);
      for (const project of remainingIssues) {
        console.log(`   - ${project.path || 'root'}: ${project.findings.length} issues`);
      }
    }
    
    // Generate updated reports
    printSummary(newScanReport);
  }
  
  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);
  console.log(`\n⏱️  Fix process completed in ${duration}s`);
  
  // Exit with appropriate code
  if (options.dryRun) {
    console.log('💡 This was a dry run. Use without --dry-run to apply fixes.');
    process.exit(0);
  } else if (fixReport.failedProjects > 0) {
    console.log(`💥 Some fixes failed. Check the errors above.`);
    process.exit(1);
  } else {
    process.exit(0);
  }
}

/**
 * Run npm audit on discovered projects for additional vulnerability info
 */
async function runAuditOnProjects(projects: ProjectInfo[]): Promise<void> {
  // Only run audit on actual project roots (not inside node_modules)
  const rootProjects = projects.filter(p => !p.path.includes('node_modules'));
  
  console.log(`   Running audit on ${rootProjects.length} root projects...`);
  
  for (const project of rootProjects.slice(0, 3)) { // Limit to first 3 projects to avoid long delays
    const projectPath = join(process.cwd(), project.path);
    const auditCommand = project.manager.name === 'yarn' ? 'yarn audit' : 
                        project.manager.name === 'pnpm' ? 'pnpm audit' : 'npm audit';
    
    try {
      const { stdout } = await execAsync(auditCommand, { 
        cwd: projectPath,
        timeout: 30000 // 30 second timeout per project
      });
      
      // Parse audit results for high/critical vulnerabilities
      if (stdout.includes('high') || stdout.includes('critical')) {
        console.log(`   ⚠️  ${project.path || 'root'}: Found high/critical vulnerabilities in audit`);
      } else {
        console.log(`   ✅ ${project.path || 'root'}: No critical vulnerabilities found in audit`);
      }
    } catch (error) {
      // Audit often returns non-zero exit codes even for warnings
      const errorOutput = (error as any).stdout || (error as any).stderr || '';
      if (errorOutput.includes('high') || errorOutput.includes('critical')) {
        console.log(`   ⚠️  ${project.path || 'root'}: Found vulnerabilities in audit`);
      } else {
        console.log(`   💡 ${project.path || 'root'}: Audit completed (no critical issues)`);
      }
    }
  }
  
  if (rootProjects.length > 3) {
    console.log(`   💡 Audited first 3 projects. Use 'npm audit' manually for others if needed.`);
  }
}

/**
 * Handle unhandled errors
 */
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(3); // Parse error
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(3); // Parse error
});

// Add help examples
program.addHelpText('after', `

Examples:
  $ guard-deps scan                           # Scan all projects from PROJECTS_ROOT
  $ guard-deps scan --cwd ./my-project        # Scan single project
  $ guard-deps scan --out report.json        # Save JSON report
  $ guard-deps scan --md report.md           # Save Markdown report
  $ guard-deps scan --format json            # Output JSON to console
  $ guard-deps scan --strict                 # Only fail on confirmed compromised
  $ guard-deps scan --fail-on at_risk        # Fail on at-risk packages too
  $ guard-deps fix                           # Automatically fix compromised packages
  $ guard-deps fix --dry-run                 # Preview fixes without applying them
  $ guard-deps fix --cwd ./my-project        # Fix single project
  $ guard-deps fix --no-force                # Fix without force overrides
  $ guard-deps fix --skip-node-modules       # Fix without clearing node_modules
  $ guard-deps fix --no-backup               # Fix without creating backups
  $ guard-deps fix --no-rescan               # Fix without re-scanning after
  $ guard-deps list                          # List discovered projects
  $ guard-deps info                          # Show configuration

Environment Variables:
  PROJECTS_ROOT          Root directory to scan (required)
  IGNORE_DIRS           Comma-separated directories to ignore
  ADVISORY_SOURCE       Advisory source (file:./advisories.json or URL)

Configuration File:
  Create .env file in current directory with:
    PROJECTS_ROOT=/path/to/projects
    IGNORE_DIRS=node_modules,dist,build
    ADVISORY_SOURCE=file:./malicious-packages.txt

Exit Codes:
  0   No issues found
  10  Compromised packages found
  11  At-risk packages found (with --fail-on at_risk)
  2   Configuration error
  3   Parse error
`);

// Parse command line arguments
if (require.main === module) {
  program.parse();
}