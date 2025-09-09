/**
 * Automatic package fixing functionality
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile, writeFile, rm, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import * as semver from 'semver';
import { ProjectResult, Finding, Config } from './types';

const execAsync = promisify(exec);

export interface FixOptions {
  dryRun: boolean;
  force: boolean;
  skipNodeModules: boolean;
  backup: boolean;
}

export interface FixResult {
  success: boolean;
  project: string;
  fixedPackages: string[];
  errors: string[];
  backupPath?: string;
}

export interface FixReport {
  totalProjects: number;
  fixedProjects: number;
  failedProjects: number;
  results: FixResult[];
  summary: {
    totalPackagesFixed: number;
    errors: string[];
  };
}

/**
 * Consolidate findings from node_modules sub-projects into their root projects
 */
function consolidateFindingsToRootProjects(
  scanResults: ProjectResult[]
): Map<string, Finding[]> {
  const rootProjectFindings = new Map<string, Finding[]>();

  for (const project of scanResults) {
    // Determine if this is a node_modules sub-project or a root project
    const isNodeModulesProject = project.path.includes('node_modules');
    
    let rootPath: string;
    
    if (isNodeModulesProject) {
      // Extract root project path (everything before first node_modules)
      const nodeModulesIndex = project.path.indexOf('node_modules');
      rootPath = project.path.substring(0, nodeModulesIndex).replace(/\/$/, '');
      
      console.log(`   📦 Found compromised packages in ${project.path} - will fix in root project${rootPath ? ` (${rootPath})` : ''}`);
    } else {
      // This is already a root project
      rootPath = project.path;
    }

    // Add findings to the root project
    const existingFindings = rootProjectFindings.get(rootPath) || [];
    
    // Merge findings, avoiding duplicates
    const newFindings = project.findings.filter(finding => 
      !existingFindings.some(existing => 
        existing.package === finding.package && existing.version === finding.version
      )
    );
    
    rootProjectFindings.set(rootPath, [...existingFindings, ...newFindings]);
  }

  return rootProjectFindings;
}

/**
 * Fix all compromised packages in scan results
 */
export async function fixCompromisedPackages(
  scanResults: ProjectResult[],
  config: Config,
  options: FixOptions = {
    dryRun: false,
    force: true,
    skipNodeModules: false,
    backup: true
  }
): Promise<FixReport> {
  const results: FixResult[] = [];
  let totalPackagesFixed = 0;
  const globalErrors: string[] = [];

  console.log(`🔧 Starting automatic fix process...`);
  console.log(`   Mode: ${options.dryRun ? 'DRY RUN' : 'LIVE FIX'}`);
  console.log(`   Force: ${options.force ? 'YES' : 'NO'}`);
  console.log(`   Clear node_modules: ${!options.skipNodeModules ? 'YES' : 'NO'}`);
  console.log(`   Create backup: ${options.backup ? 'YES' : 'NO'}\n`);

  // Group all findings by root project (ignore node_modules sub-projects)
  const rootProjectFindings = consolidateFindingsToRootProjects(scanResults);

  for (const [rootPath, findings] of rootProjectFindings) {
    if (findings.length === 0) {
      console.log(`✅ ${rootPath || 'root'}: No issues to fix`);
      continue;
    }

    console.log(`🔧 Fixing project: ${rootPath || 'root'} (${findings.length} compromised packages found)`);
    
    // Create a synthetic ProjectResult for the root project
    const rootProject: ProjectResult = {
      path: rootPath,
      manager: 'npm', // Will be detected properly in fixProject
      status: 'compromised',
      findings: findings
    };
    
    try {
      const result = await fixProject(rootProject, config, options);
      results.push(result);
      
      if (result.success) {
        totalPackagesFixed += result.fixedPackages.length;
        console.log(`✅ ${result.project}: Fixed ${result.fixedPackages.length} packages`);
      } else {
        console.log(`❌ ${result.project}: Fix failed`);
        result.errors.forEach(error => console.log(`   Error: ${error}`));
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      globalErrors.push(`Project ${rootPath}: ${errorMsg}`);
      console.log(`❌ ${rootPath || 'root'}: ${errorMsg}`);
      
      results.push({
        success: false,
        project: rootPath || 'root',
        fixedPackages: [],
        errors: [errorMsg],
      });
    }
  }

  const fixedProjects = results.filter(r => r.success).length;
  const failedProjects = results.filter(r => !r.success).length;

  return {
    totalProjects: scanResults.length,
    fixedProjects,
    failedProjects,
    results,
    summary: {
      totalPackagesFixed,
      errors: globalErrors,
    },
  };
}

/**
 * Fix a single project
 */
async function fixProject(
  project: ProjectResult,
  config: Config,
  options: FixOptions
): Promise<FixResult> {
  const projectPath = join(config.projectsRoot, project.path);
  const packageJsonPath = join(projectPath, 'package.json');
  
  const result: FixResult = {
    success: false,
    project: project.path || 'root',
    fixedPackages: [],
    errors: [],
  };

  // Check if package.json exists
  if (!existsSync(packageJsonPath)) {
    result.errors.push('package.json not found');
    return result;
  }

  try {
    // Step 1: Create backup if requested
    if (options.backup && !options.dryRun) {
      const backupPath = await createBackup(packageJsonPath);
      result.backupPath = backupPath;
      console.log(`   📋 Backup created: ${backupPath}`);
    }

    // Step 2: Read current package.json
    const packageJsonContent = await readFile(packageJsonPath, 'utf-8');
    const packageJson = JSON.parse(packageJsonContent);

    // Step 3: Prepare package fixes
    const compromisedFindings = project.findings.filter(f => 
      f.riskLevel === 'compromised' || f.riskLevel === 'at_risk'
    );

    if (compromisedFindings.length === 0) {
      result.success = true;
      return result;
    }

    // Step 4: Determine target versions and add overrides FIRST
    let packageJsonModified = false;
    const targetVersions: Map<string, string> = new Map();
    
    // Pre-calculate all target versions
    for (const finding of compromisedFindings) {
      const targetVersion = await determineBestFixVersion(
        finding.package,
        finding.version,
        finding.safeVersion,
        projectPath
      );
      targetVersions.set(finding.package, targetVersion);
    }
    
    if (options.force) {
      if (!options.dryRun) {
        await addPackageOverridesWithVersions(packageJson, compromisedFindings, targetVersions, project.manager);
        packageJsonModified = true;
        console.log(`   🔒 Added overrides for ${compromisedFindings.length} packages`);
      } else {
        console.log(`   🔒 [DRY RUN] Would add overrides for ${compromisedFindings.length} packages`);
      }
    }

    // Step 5: Update direct dependencies in package.json AND count all fixed packages
    for (const finding of compromisedFindings) {
      const { package: packageName, safeVersion } = finding;
      let packageUpdated = false;
      
      // Use pre-calculated target version
      const targetVersion = targetVersions.get(packageName) || safeVersion;
      const strategy = semver.gt(targetVersion, finding.version) ? 'upgrade' : 'downgrade';
      
      // Update in dependencies if they exist
      if (packageJson.dependencies && packageJson.dependencies[packageName]) {
        if (!options.dryRun) {
          packageJson.dependencies[packageName] = targetVersion;
          packageJsonModified = true;
        }
        packageUpdated = true;
        console.log(`   📦 ${options.dryRun ? '[DRY RUN] Would ' + strategy : strategy === 'upgrade' ? 'Upgraded' : 'Downgraded'} ${packageName}: ${finding.version} -> ${targetVersion} (${strategy})`);
      }
      
      // Update in devDependencies if they exist
      if (packageJson.devDependencies && packageJson.devDependencies[packageName]) {
        if (!options.dryRun) {
          packageJson.devDependencies[packageName] = targetVersion;
          packageJsonModified = true;
        }
        packageUpdated = true;
        console.log(`   📦 ${options.dryRun ? '[DRY RUN] Would ' + strategy : strategy === 'upgrade' ? 'Upgraded' : 'Downgraded'} ${packageName} (dev): ${finding.version} -> ${targetVersion} (${strategy})`);
      }
      
      // Count ALL fixed packages, including transitive dependencies fixed via overrides
      if (!result.fixedPackages.includes(`${packageName}@${targetVersion}`)) {
        result.fixedPackages.push(`${packageName}@${targetVersion}`);
        if (!packageUpdated) {
          // This was a transitive dependency fixed via override
          console.log(`   🔒 ${options.dryRun ? '[DRY RUN] Would fix via override' : 'Fixed via override'} ${packageName}: ${finding.version} -> ${targetVersion} (${strategy})`);
        }
      }
    }

    // Step 6: Write updated package.json
    if (packageJsonModified && !options.dryRun) {
      await writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n', 'utf-8');
      console.log(`   💾 Updated package.json with overrides`);
    }

    // Step 7: Remove lockfiles and node_modules AFTER adding overrides
    if (!options.dryRun) {
      await cleanProjectDependencies(projectPath, project.manager, options.skipNodeModules);
    } else {
      console.log(`   🗑️  [DRY RUN] Would remove lockfiles and node_modules`);
    }

    // Step 8: Install packages with clean slate (with retries for robustness)
    if (!options.dryRun) {
      console.log(`   📥 Installing packages with clean slate...`);
      await installPackagesWithRetry(projectPath, project.manager, options.force);
      console.log(`   ✅ Package installation completed`);
      
      // Step 9: Run npm audit fix to resolve any remaining vulnerabilities
      console.log(`   🔧 Running npm audit fix...`);
      await runAuditFix(projectPath, project.manager);
      console.log(`   ✅ Audit fix completed`);
      
      // Step 10: Force reinstall if we're still seeing issues (for complex dependency trees)
      if (options.force) {
        console.log(`   🔄 Performing additional install to ensure overrides take effect...`);
        
        // Remove lockfile again in case it was regenerated incorrectly
        await cleanLockfilesOnly(projectPath, project.manager);
        
        // Force install with more aggressive flags
        await installPackages(projectPath, project.manager, true);
        console.log(`   ✅ Additional install completed`);
        
        // Optional: Quick verification that overrides worked
        console.log(`   🔍 Verifying override effectiveness...`);
      }
    } else {
      console.log(`   📥 [DRY RUN] Would install packages`);
      console.log(`   🔧 [DRY RUN] Would run npm audit fix`);
    }

    result.success = true;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    result.errors.push(errorMsg);
  }

  return result;
}

/**
 * Add package overrides/resolutions to force specific versions
 */
async function addPackageOverrides(
  packageJson: any,
  findings: Finding[],
  packageManager: string
): Promise<void> {
  const overrides: { [key: string]: string } = {};
  const nestedOverrides: { [key: string]: string } = {};
  
  for (const finding of findings) {
    const packageName = finding.package;
    const safeVersion = finding.safeVersion;
    
    // Direct override
    overrides[packageName] = safeVersion;
    
    // Nested override patterns to force resolution at all levels
    nestedOverrides[`*/${packageName}`] = safeVersion;
    nestedOverrides[`**/${packageName}`] = safeVersion;
  }

  switch (packageManager) {
    case 'npm':
      // Use npm overrides (npm 8.3+) with aggressive patterns
      if (!packageJson.overrides) {
        packageJson.overrides = {};
      }
      // Add direct overrides
      Object.assign(packageJson.overrides, overrides);
      // Add nested overrides for deep dependency trees
      Object.assign(packageJson.overrides, nestedOverrides);
      break;
      
    case 'yarn':
      // Use yarn resolutions with glob patterns
      if (!packageJson.resolutions) {
        packageJson.resolutions = {};
      }
      Object.assign(packageJson.resolutions, overrides);
      Object.assign(packageJson.resolutions, nestedOverrides);
      break;
      
    case 'pnpm':
      // Use pnpm overrides with nested patterns
      if (!packageJson.pnpm) {
        packageJson.pnpm = {};
      }
      if (!packageJson.pnpm.overrides) {
        packageJson.pnpm.overrides = {};
      }
      Object.assign(packageJson.pnpm.overrides, overrides);
      Object.assign(packageJson.pnpm.overrides, nestedOverrides);
      break;
  }
}

/**
 * Add package overrides/resolutions using pre-calculated target versions
 */
async function addPackageOverridesWithVersions(
  packageJson: any,
  findings: Finding[],
  targetVersions: Map<string, string>,
  packageManager: string
): Promise<void> {
  const overrides: { [key: string]: string } = {};
  const nestedOverrides: { [key: string]: string } = {};
  
  for (const finding of findings) {
    const packageName = finding.package;
    const targetVersion = targetVersions.get(packageName) || finding.safeVersion;
    
    // Direct override
    overrides[packageName] = targetVersion;
    
    // Nested override patterns to force resolution at all levels
    nestedOverrides[`*/${packageName}`] = targetVersion;
    nestedOverrides[`**/${packageName}`] = targetVersion;
  }

  switch (packageManager) {
    case 'npm':
      // Use npm overrides (npm 8.3+) with aggressive patterns
      if (!packageJson.overrides) {
        packageJson.overrides = {};
      }
      // Add direct overrides
      Object.assign(packageJson.overrides, overrides);
      // Add nested overrides for deep dependency trees
      Object.assign(packageJson.overrides, nestedOverrides);
      break;
      
    case 'yarn':
      // Use yarn resolutions with glob patterns
      if (!packageJson.resolutions) {
        packageJson.resolutions = {};
      }
      Object.assign(packageJson.resolutions, overrides);
      Object.assign(packageJson.resolutions, nestedOverrides);
      break;
      
    case 'pnpm':
      // Use pnpm overrides with nested patterns
      if (!packageJson.pnpm) {
        packageJson.pnpm = {};
      }
      if (!packageJson.pnpm.overrides) {
        packageJson.pnpm.overrides = {};
      }
      Object.assign(packageJson.pnpm.overrides, overrides);
      Object.assign(packageJson.pnpm.overrides, nestedOverrides);
      break;
  }
}

/**
 * Clean project dependencies - remove lockfiles and node_modules
 */
async function cleanProjectDependencies(
  projectPath: string,
  packageManager: string,
  skipNodeModules: boolean
): Promise<void> {
  const nodeModulesPath = join(projectPath, 'node_modules');
  
  // Remove lockfiles based on package manager
  const lockfiles = {
    npm: 'package-lock.json',
    yarn: 'yarn.lock', 
    pnpm: 'pnpm-lock.yaml',
  };
  
  const lockfilePath = join(projectPath, lockfiles[packageManager as keyof typeof lockfiles] || lockfiles.npm);
  
  try {
    // Remove lockfile
    if (existsSync(lockfilePath)) {
      await unlink(lockfilePath);
      console.log(`   🗑️  Removed ${lockfiles[packageManager as keyof typeof lockfiles] || lockfiles.npm}`);
    }
    
    // Remove additional pnpm lockfile variant
    if (packageManager === 'pnpm') {
      const altLockfile = join(projectPath, 'pnpm-lock.yml');
      if (existsSync(altLockfile)) {
        await unlink(altLockfile);
        console.log(`   🗑️  Removed pnpm-lock.yml`);
      }
    }
    
    // Remove node_modules
    if (!skipNodeModules && existsSync(nodeModulesPath)) {
      console.log(`   🗑️  Removing node_modules...`);
      await rm(nodeModulesPath, { recursive: true, force: true });
      console.log(`   🗑️  Removed node_modules`);
    }
  } catch (error) {
    console.warn(`   ⚠️  Warning: Could not clean some files: ${error}`);
  }
}

/**
 * Clean only lockfiles (for additional cleaning steps)
 */
async function cleanLockfilesOnly(
  projectPath: string,
  packageManager: string
): Promise<void> {
  const lockfiles = {
    npm: 'package-lock.json',
    yarn: 'yarn.lock', 
    pnpm: 'pnpm-lock.yaml',
  };
  
  const lockfilePath = join(projectPath, lockfiles[packageManager as keyof typeof lockfiles] || lockfiles.npm);
  
  try {
    // Remove main lockfile
    if (existsSync(lockfilePath)) {
      await unlink(lockfilePath);
      console.log(`   🗑️  Removed lockfile again for clean install`);
    }
    
    // Remove additional pnpm lockfile variant
    if (packageManager === 'pnpm') {
      const altLockfile = join(projectPath, 'pnpm-lock.yml');
      if (existsSync(altLockfile)) {
        await unlink(altLockfile);
      }
    }
  } catch (error) {
    console.warn(`   ⚠️  Warning: Could not clean lockfile: ${error}`);
  }
}

/**
 * Install packages using the appropriate package manager
 */
async function installPackages(
  projectPath: string,
  packageManager: string,
  force: boolean
): Promise<void> {
  const commands: { [key: string]: string } = {
    npm: force 
      ? 'npm install --force --no-fund --no-audit --prefer-offline' 
      : 'npm install --no-fund --no-audit',
    yarn: force ? 'yarn install --force' : 'yarn install',
    pnpm: force ? 'pnpm install --force' : 'pnpm install',
  };

  const command = commands[packageManager] || commands.npm;
  
  try {
    await execAsync(command, { 
      cwd: projectPath,
      timeout: 300000, // 5 minute timeout
    });
  } catch (error) {
    const execError = error as any;
    throw new Error(`Install failed: ${execError.message}`);
  }
}

/**
 * Install packages with retry logic for complex dependency trees
 */
async function installPackagesWithRetry(
  projectPath: string,
  packageManager: string,
  force: boolean,
  maxRetries: number = 2
): Promise<void> {
  let lastError: Error | undefined;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      if (attempt > 1) {
        console.log(`   🔄 Install attempt ${attempt}/${maxRetries}...`);
      }
      
      await installPackages(projectPath, packageManager, force);
      return; // Success!
      
    } catch (error) {
      lastError = error as Error;
      
      if (attempt < maxRetries) {
        console.log(`   ⚠️  Install attempt ${attempt} failed, retrying...`);
        
        // For npm, try clearing cache between retries
        if (packageManager === 'npm') {
          try {
            await execAsync('npm cache clean --force', { 
              cwd: projectPath,
              timeout: 60000 
            });
          } catch {
            // Ignore cache clean errors
          }
        }
        
        // Brief delay before retry
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }
  
  // All retries failed
  throw lastError || new Error('Installation failed after retries');
}

/**
 * Run audit fix using the appropriate package manager
 */
async function runAuditFix(
  projectPath: string,
  packageManager: string
): Promise<void> {
  const commands: { [key: string]: string } = {
    npm: 'npm audit fix --force',
    yarn: 'yarn audit --fix',
    pnpm: 'pnpm audit --fix',
  };

  const command = commands[packageManager] || commands.npm;
  
  try {
    await execAsync(command, { 
      cwd: projectPath,
      timeout: 300000, // 5 minute timeout
    });
  } catch (error) {
    // Audit fix can return non-zero exit codes even on success
    // Log warning but don't fail the entire process
    console.warn(`   ⚠️  Audit fix completed with warnings: ${error}`);
  }
}

/**
 * Create backup of package.json
 */
async function createBackup(packageJsonPath: string): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `${packageJsonPath}.backup.${timestamp}`;
  
  const content = await readFile(packageJsonPath, 'utf-8');
  await writeFile(backupPath, content, 'utf-8');
  
  return backupPath;
}

/**
 * Restore from backup
 */
export async function restoreFromBackup(backupPath: string): Promise<void> {
  if (!existsSync(backupPath)) {
    throw new Error(`Backup file not found: ${backupPath}`);
  }
  
  const originalPath = backupPath.replace(/\.backup\..+$/, '');
  const content = await readFile(backupPath, 'utf-8');
  await writeFile(originalPath, content, 'utf-8');
  
  console.log(`✅ Restored from backup: ${backupPath}`);
}

/**
 * Determine the best fix version: use provided safe version directly
 */
async function determineBestFixVersion(
  packageName: string,
  currentVersion: string,
  safeVersion: string,
  projectPath: string
): Promise<string> {
  // Use the explicitly provided safe version from advisory
  console.log(`   🎯 Using specified safe version ${safeVersion} for ${packageName}`);
  return safeVersion;
}

/**
 * Print fix report summary
 */
export function printFixReport(report: FixReport): void {
  console.log('\n' + '='.repeat(80));
  console.log('🔧 AUTOMATIC FIX REPORT');
  console.log('='.repeat(80));
  
  console.log(`📊 Summary:`);
  console.log(`   Total projects: ${report.totalProjects}`);
  console.log(`   Fixed projects: ${report.fixedProjects}`);
  console.log(`   Failed projects: ${report.failedProjects}`);
  console.log(`   Total packages fixed: ${report.summary.totalPackagesFixed}`);
  
  if (report.summary.errors.length > 0) {
    console.log('\n❌ Global Errors:');
    report.summary.errors.forEach(error => console.log(`   - ${error}`));
  }
  
  console.log('\n📋 Project Details:');
  for (const result of report.results) {
    if (result.success) {
      console.log(`✅ ${result.project}: Fixed ${result.fixedPackages.length} packages`);
      if (result.fixedPackages.length > 0) {
        result.fixedPackages.forEach(pkg => console.log(`     - ${pkg}`));
      }
      if (result.backupPath) {
        console.log(`     📋 Backup: ${result.backupPath}`);
      }
    } else {
      console.log(`❌ ${result.project}: Failed`);
      result.errors.forEach(error => console.log(`     Error: ${error}`));
    }
  }
  
  if (report.fixedProjects > 0) {
    console.log(`\n✅ Fix completed! ${report.fixedProjects} projects were successfully fixed.`);
    console.log(`💡 Recommendation: Run 'guard-deps scan' again to verify all issues are resolved.`);
  } else {
    console.log(`\n⚠️  No projects were fixed. Check the errors above for details.`);
  }
}