/**
 * NPM package-lock.json parser
 */

import { readFile } from 'fs/promises';
import { DependencyInfo, LockfileParser, ParsedLockfile, PackageManager } from '../types';
import { normalizeVersion } from './index';

interface NpmLockfileV1 {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  dependencies?: {
    [name: string]: {
      version: string;
      resolved?: string;
      integrity?: string;
      dev?: boolean;
      optional?: boolean;
      dependencies?: any;
    };
  };
}

interface NpmLockfileV2 {
  name?: string;
  version?: string;
  lockfileVersion: number;
  packages: {
    [path: string]: {
      version?: string;
      resolved?: string;
      integrity?: string;
      dev?: boolean;
      optional?: boolean;
      dependencies?: { [name: string]: string };
      devDependencies?: { [name: string]: string };
    };
  };
}

export class NpmParser implements LockfileParser {
  canParse(lockfilePath: string): boolean {
    return lockfilePath.endsWith('package-lock.json');
  }

  async parse(lockfilePath: string): Promise<ParsedLockfile> {
    const content = await readFile(lockfilePath, 'utf-8');
    const lockfile = JSON.parse(content);

    const manager: PackageManager = { name: 'npm', lockfile: 'package-lock.json' };
    
    if (lockfile.lockfileVersion === 1) {
      return this.parseV1(lockfile as NpmLockfileV1, manager);
    } else if (lockfile.lockfileVersion >= 2) {
      return this.parseV2(lockfile as NpmLockfileV2, manager);
    }

    throw new Error(`Unsupported package-lock.json version: ${lockfile.lockfileVersion}`);
  }

  private parseV1(lockfile: NpmLockfileV1, manager: PackageManager): ParsedLockfile {
    const dependencies: DependencyInfo[] = [];

    if (lockfile.dependencies) {
      this.extractDependenciesV1(lockfile.dependencies, dependencies);
    }

    return { dependencies, manager };
  }

  private extractDependenciesV1(deps: any, result: DependencyInfo[], prefix = ''): void {
    for (const [name, info] of Object.entries(deps)) {
      const dep = info as any;
      
      result.push({
        name: prefix ? `${prefix}/${name}` : name,
        version: normalizeVersion(dep.version),
        resolved: dep.resolved,
        integrity: dep.integrity,
      });

      // Recursively process nested dependencies
      if (dep.dependencies) {
        this.extractDependenciesV1(dep.dependencies, result, prefix ? `${prefix}/${name}` : name);
      }
    }
  }

  private parseV2(lockfile: NpmLockfileV2, manager: PackageManager): ParsedLockfile {
    const dependencies: DependencyInfo[] = [];

    for (const [path, info] of Object.entries(lockfile.packages)) {
      // Skip root package
      if (path === '' || path === '.') continue;
      
      // Extract package name from path
      const name = this.extractPackageName(path);
      if (!name || !info.version) continue;

      dependencies.push({
        name,
        version: normalizeVersion(info.version),
        resolved: info.resolved,
        integrity: info.integrity,
      });
    }

    return { dependencies, manager };
  }

  private extractPackageName(path: string): string {
    // Handle paths like "node_modules/package-name" or "node_modules/@scope/package"
    const parts = path.split('/');
    
    // Remove "node_modules" from the beginning
    const nodeModulesIndex = parts.lastIndexOf('node_modules');
    if (nodeModulesIndex === -1) return '';
    
    const nameStartIndex = nodeModulesIndex + 1;
    
    // Handle scoped packages (@scope/package)
    if (parts[nameStartIndex]?.startsWith('@') && parts[nameStartIndex + 1]) {
      return `${parts[nameStartIndex]}/${parts[nameStartIndex + 1]}`;
    }
    
    return parts[nameStartIndex] || '';
  }
}