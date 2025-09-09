/**
 * Package.json fallback parser (when no lockfile exists)
 */

import { readFile } from 'fs/promises';
import { DependencyInfo, LockfileParser, ParsedLockfile, PackageManager } from '../types';
import { normalizeVersion } from './index';

interface PackageJsonData {
  name?: string;
  version?: string;
  dependencies?: { [name: string]: string };
  devDependencies?: { [name: string]: string };
  peerDependencies?: { [name: string]: string };
  optionalDependencies?: { [name: string]: string };
}

export class PackageJsonParser implements LockfileParser {
  canParse(packageJsonPath: string): boolean {
    return packageJsonPath.endsWith('package.json');
  }

  async parse(packageJsonPath: string): Promise<ParsedLockfile> {
    const content = await readFile(packageJsonPath, 'utf-8');
    let packageData: PackageJsonData;
    
    try {
      packageData = JSON.parse(content);
    } catch (error) {
      throw new Error(`Invalid JSON in ${packageJsonPath}: ${error instanceof Error ? error.message : 'Parse error'}`);
    }

    // Default to npm manager when parsing package.json
    const manager: PackageManager = { name: 'npm', lockfile: 'package-lock.json' };
    const dependencies: DependencyInfo[] = [];

    // Extract all types of dependencies
    const depSections = [
      packageData.dependencies || {},
      packageData.devDependencies || {},
      packageData.peerDependencies || {},
      packageData.optionalDependencies || {},
    ];

    const seenPackages = new Set<string>();

    for (const depSection of depSections) {
      for (const [name, versionRange] of Object.entries(depSection)) {
        if (seenPackages.has(name)) continue;
        seenPackages.add(name);

        dependencies.push({
          name,
          version: normalizeVersion(versionRange),
        });
      }
    }

    return { dependencies, manager };
  }

  /**
   * Parse only production dependencies from package.json
   */
  async parseProductionDependencies(packageJsonPath: string): Promise<DependencyInfo[]> {
    const content = await readFile(packageJsonPath, 'utf-8');
    let packageData: PackageJsonData;
    
    try {
      packageData = JSON.parse(content);
    } catch (error) {
      throw new Error(`Invalid JSON in ${packageJsonPath}: ${error instanceof Error ? error.message : 'Parse error'}`);
    }

    const dependencies: DependencyInfo[] = [];
    const deps = packageData.dependencies || {};

    for (const [name, versionRange] of Object.entries(deps)) {
      dependencies.push({
        name,
        version: normalizeVersion(versionRange),
      });
    }

    return dependencies;
  }

  /**
   * Parse only development dependencies from package.json
   */
  async parseDevDependencies(packageJsonPath: string): Promise<DependencyInfo[]> {
    const content = await readFile(packageJsonPath, 'utf-8');
    let packageData: PackageJsonData;
    
    try {
      packageData = JSON.parse(content);
    } catch (error) {
      throw new Error(`Invalid JSON in ${packageJsonPath}: ${error instanceof Error ? error.message : 'Parse error'}`);
    }

    const dependencies: DependencyInfo[] = [];
    const devDeps = packageData.devDependencies || {};

    for (const [name, versionRange] of Object.entries(devDeps)) {
      dependencies.push({
        name,
        version: normalizeVersion(versionRange),
      });
    }

    return dependencies;
  }

  /**
   * Get package metadata from package.json
   */
  async getPackageInfo(packageJsonPath: string): Promise<{
    name: string;
    version: string;
    hasLockfile: boolean;
  }> {
    const content = await readFile(packageJsonPath, 'utf-8');
    let packageData: PackageJsonData;
    
    try {
      packageData = JSON.parse(content);
    } catch (error) {
      throw new Error(`Invalid JSON in ${packageJsonPath}: ${error instanceof Error ? error.message : 'Parse error'}`);
    }

    return {
      name: packageData.name || 'unknown',
      version: packageData.version || '0.0.0',
      hasLockfile: false, // This parser is used when no lockfile exists
    };
  }
}