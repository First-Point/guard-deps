/**
 * Lockfile parser coordinator
 */

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { DependencyInfo, LockfileParser, ParsedLockfile, ProjectInfo } from '../types';
import { NpmParser } from './npm-parser';
import { YarnParser } from './yarn-parser';
import { PnpmParser } from './pnpm-parser';
import { PackageJsonParser } from './package-json-parser';

/**
 * Registry of all available parsers
 */
const PARSERS: LockfileParser[] = [
  new PnpmParser(),
  new YarnParser(), 
  new NpmParser(),
  new PackageJsonParser(), // Fallback parser
];

/**
 * Parse project dependencies using the appropriate lockfile parser
 */
export async function parseProjectDependencies(project: ProjectInfo): Promise<DependencyInfo[]> {
  // Try to use lockfile if available
  if (project.lockfilePath && existsSync(project.lockfilePath)) {
    for (const parser of PARSERS) {
      if (parser.canParse(project.lockfilePath)) {
        try {
          const result = await parser.parse(project.lockfilePath);
          return result.dependencies;
        } catch (error) {
          console.warn(`Warning: Failed to parse ${project.lockfilePath} with ${parser.constructor.name}:`, error instanceof Error ? error.message : 'Unknown error');
        }
      }
    }
  }

  // Fallback to package.json
  const packageJsonParser = new PackageJsonParser();
  try {
    const result = await packageJsonParser.parse(project.packageJsonPath);
    return result.dependencies;
  } catch (error) {
    console.warn(`Warning: Failed to parse ${project.packageJsonPath}:`, error instanceof Error ? error.message : 'Unknown error');
    return [];
  }
}

/**
 * Parse a specific lockfile
 */
export async function parseLockfile(lockfilePath: string): Promise<ParsedLockfile> {
  if (!existsSync(lockfilePath)) {
    throw new Error(`Lockfile not found: ${lockfilePath}`);
  }

  for (const parser of PARSERS) {
    if (parser.canParse(lockfilePath)) {
      return parser.parse(lockfilePath);
    }
  }

  throw new Error(`No parser available for lockfile: ${lockfilePath}`);
}

/**
 * Extract version from dependency string
 * Handles various formats: "^1.2.3", "~1.2.3", "1.2.3", ">=1.2.3"
 */
export function normalizeVersion(versionString: string): string {
  if (!versionString) return '';
  
  // Remove common prefixes
  return versionString
    .replace(/^[\^~>=<]/, '')
    .replace(/\s.*$/, '') // Remove everything after first space
    .trim();
}

/**
 * Check if a file is a supported lockfile
 */
export function isLockfile(filePath: string): boolean {
  const lockfileNames = [
    'package-lock.json',
    'yarn.lock', 
    'pnpm-lock.yaml',
    'pnpm-lock.yml'
  ];
  
  const fileName = filePath.split('/').pop() || '';
  return lockfileNames.includes(fileName);
}

/**
 * Get all dependencies from a project including dev dependencies
 */
export async function getAllProjectDependencies(project: ProjectInfo): Promise<{
  dependencies: DependencyInfo[];
  devDependencies: DependencyInfo[];
  all: DependencyInfo[];
}> {
  const allDeps = await parseProjectDependencies(project);
  
  // Read package.json to identify dev dependencies
  let devDepNames: Set<string> = new Set();
  
  try {
    const packageJsonContent = await readFile(project.packageJsonPath, 'utf-8');
    const packageJson = JSON.parse(packageJsonContent);
    
    if (packageJson.devDependencies) {
      devDepNames = new Set(Object.keys(packageJson.devDependencies));
    }
  } catch (error) {
    console.warn(`Warning: Could not read or parse package.json at ${project.packageJsonPath}:`, error instanceof Error ? error.message : 'Unknown error');
  }

  const dependencies = allDeps.filter(dep => !devDepNames.has(dep.name));
  const devDependencies = allDeps.filter(dep => devDepNames.has(dep.name));

  return {
    dependencies,
    devDependencies,
    all: allDeps
  };
}