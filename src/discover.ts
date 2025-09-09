/**
 * Project discovery - recursively find Node.js projects
 */

import { readdir, stat, access } from 'fs/promises';
import { join, relative, dirname } from 'path';
import { existsSync } from 'fs';
import { ProjectInfo, PackageManager, Config } from './types';

/**
 * Package manager detection based on lockfile presence
 */
const PACKAGE_MANAGERS: PackageManager[] = [
  { name: 'pnpm', lockfile: 'pnpm-lock.yaml' },
  { name: 'yarn', lockfile: 'yarn.lock' },
  { name: 'npm', lockfile: 'package-lock.json' },
];

/**
 * Check if a directory should be ignored
 */
function shouldIgnoreDirectory(dirName: string, ignoreDirs: string[]): boolean {
  return ignoreDirs.includes(dirName) || 
         dirName.startsWith('.') && !dirName.includes('package.json');
}

/**
 * Detect package manager for a project
 */
function detectPackageManager(projectPath: string): PackageManager {
  for (const manager of PACKAGE_MANAGERS) {
    const lockfilePath = join(projectPath, manager.lockfile);
    if (existsSync(lockfilePath)) {
      return manager;
    }
  }
  
  // Default to npm if no lockfile found
  return { name: 'npm', lockfile: 'package-lock.json' };
}

/**
 * Discover a single project from a directory
 */
async function discoverProject(
  projectPath: string,
  packageJsonPath: string,
  config: Config
): Promise<ProjectInfo> {
  const manager = detectPackageManager(projectPath);
  const lockfilePath = join(projectPath, manager.lockfile);
  
  const project: ProjectInfo = {
    path: relative(config.projectsRoot, projectPath),
    packageJsonPath,
    manager,
    dependencies: [], // Will be populated by lock parser
  };

  // Add lockfile path if it exists
  if (existsSync(lockfilePath)) {
    project.lockfilePath = lockfilePath;
  }

  return project;
}

/**
 * Recursively scan directory for package.json files
 */
async function scanDirectory(
  dirPath: string,
  config: Config,
  projects: ProjectInfo[] = [],
  depth: number = 0
): Promise<ProjectInfo[]> {
  // Prevent infinite recursion
  if (depth > 20) {
    return projects;
  }

  try {
    const entries = await readdir(dirPath, { withFileTypes: true });
    
    // Check if this directory has a package.json
    const packageJsonPath = join(dirPath, 'package.json');
    if (existsSync(packageJsonPath)) {
      try {
        const project = await discoverProject(dirPath, packageJsonPath, config);
        projects.push(project);
      } catch (error) {
        console.warn(`Warning: Could not process project at ${dirPath}:`, error);
      }
    }

    // Recursively scan subdirectories
    const subdirs = entries.filter(entry => 
      entry.isDirectory() && 
      !shouldIgnoreDirectory(entry.name, config.ignoreDirs)
    );

    for (const subdir of subdirs) {
      const subdirPath = join(dirPath, subdir.name);
      await scanDirectory(subdirPath, config, projects, depth + 1);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EACCES') {
      console.warn(`Warning: Could not scan directory ${dirPath}:`, error);
    }
  }

  return projects;
}

/**
 * Discover all Node.js projects under the specified root
 */
export async function discoverProjects(config: Config): Promise<ProjectInfo[]> {
  const rootPath = config.cwd || config.projectsRoot;
  
  try {
    await access(rootPath);
  } catch {
    throw new Error(`Cannot access directory: ${rootPath}`);
  }

  console.log(`Scanning for Node.js projects in: ${rootPath}`);
  
  const projects = await scanDirectory(rootPath, config);
  
  console.log(`Found ${projects.length} Node.js projects`);
  
  return projects;
}

/**
 * Discover a single project (for --cwd option)
 */
export async function discoverSingleProject(projectPath: string): Promise<ProjectInfo> {
  const packageJsonPath = join(projectPath, 'package.json');
  
  if (!existsSync(packageJsonPath)) {
    throw new Error(`No package.json found in ${projectPath}`);
  }

  const config: Config = {
    projectsRoot: dirname(projectPath),
    ignoreDirs: [],
    advisorySource: '',
    format: 'table',
    strict: false,
    failOn: 'compromised'
  };

  return discoverProject(projectPath, packageJsonPath, config);
}

/**
 * Filter projects based on criteria (for testing/debugging)
 */
export function filterProjects(
  projects: ProjectInfo[],
  filter: {
    hasLockfile?: boolean;
    manager?: string;
    pathContains?: string;
  }
): ProjectInfo[] {
  return projects.filter(project => {
    if (filter.hasLockfile !== undefined) {
      const hasLockfile = Boolean(project.lockfilePath && existsSync(project.lockfilePath));
      if (hasLockfile !== filter.hasLockfile) return false;
    }
    
    if (filter.manager && project.manager.name !== filter.manager) {
      return false;
    }
    
    if (filter.pathContains && !project.path.includes(filter.pathContains)) {
      return false;
    }
    
    return true;
  });
}