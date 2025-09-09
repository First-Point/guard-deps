/**
 * PNPM pnpm-lock.yaml parser
 */

import { readFile } from 'fs/promises';
import { DependencyInfo, LockfileParser, ParsedLockfile, PackageManager } from '../types';
import { normalizeVersion } from './index';

interface PnpmLockfile {
  lockfileVersion?: string | number;
  dependencies?: { [name: string]: string };
  devDependencies?: { [name: string]: string };
  packages?: {
    [path: string]: {
      resolution: {
        integrity?: string;
        tarball?: string;
      };
      dependencies?: { [name: string]: string };
      devDependencies?: { [name: string]: string };
      dev?: boolean;
      optional?: boolean;
    };
  };
}

export class PnpmParser implements LockfileParser {
  canParse(lockfilePath: string): boolean {
    return lockfilePath.endsWith('pnpm-lock.yaml') || lockfilePath.endsWith('pnpm-lock.yml');
  }

  async parse(lockfilePath: string): Promise<ParsedLockfile> {
    const content = await readFile(lockfilePath, 'utf-8');
    
    const manager: PackageManager = { name: 'pnpm', lockfile: 'pnpm-lock.yaml' };
    const dependencies: DependencyInfo[] = [];
    
    // Simple YAML parser for pnpm lockfile
    // Note: This is a simplified parser. For production, consider using a proper YAML library
    const lockfile = this.parseSimpleYaml(content);
    
    if (lockfile.packages) {
      for (const [path, info] of Object.entries(lockfile.packages)) {
        const packageName = this.extractPackageName(path);
        const version = this.extractVersion(path);
        
        if (!packageName || !version) continue;

        dependencies.push({
          name: packageName,
          version: normalizeVersion(version),
          resolved: info.resolution?.tarball,
          integrity: info.resolution?.integrity,
        });
      }
    }

    // Also add dependencies from root level
    if (lockfile.dependencies) {
      for (const [name, versionSpec] of Object.entries(lockfile.dependencies)) {
        const version = this.extractVersionFromSpec(versionSpec);
        if (version && !dependencies.find(d => d.name === name)) {
          dependencies.push({
            name,
            version: normalizeVersion(version),
          });
        }
      }
    }

    return { dependencies, manager };
  }

  private parseSimpleYaml(content: string): PnpmLockfile {
    const result: PnpmLockfile = {};
    const lines = content.split('\n');
    
    let currentSection = '';
    let currentPackage = '';
    let indentLevel = 0;
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      const indent = line.length - line.trimLeft().length;
      
      // Top-level sections
      if (indent === 0 && trimmed.endsWith(':')) {
        currentSection = trimmed.slice(0, -1);
        if (currentSection === 'packages') {
          result.packages = {};
        } else if (currentSection === 'dependencies') {
          result.dependencies = {};
        } else if (currentSection === 'devDependencies') {
          result.devDependencies = {};
        }
        continue;
      }
      
      // Package entries under packages section
      if (currentSection === 'packages' && result.packages) {
        if (indent === 2 && trimmed.endsWith(':')) {
          currentPackage = trimmed.slice(0, -1);
          result.packages[currentPackage] = { resolution: {} };
        } else if (currentPackage && indent === 4) {
          const [key, ...valueParts] = trimmed.split(': ');
          const value = valueParts.join(': ');
          
          if (key === 'resolution') {
            // Skip, will be handled in next level
          } else if (key === 'integrity' && result.packages[currentPackage]) {
            result.packages[currentPackage].resolution.integrity = value;
          }
        }
      }
      
      // Dependencies section
      if (currentSection === 'dependencies' && result.dependencies) {
        if (indent === 2 && trimmed.includes(': ')) {
          const [key, value] = trimmed.split(': ', 2);
          result.dependencies[key] = value;
        }
      }
    }
    
    return result;
  }

  private extractPackageName(packagePath: string): string {
    // Handle paths like "/package-name/1.2.3" or "/@scope/package-name/1.2.3"
    if (!packagePath.startsWith('/')) return '';
    
    const parts = packagePath.split('/').filter(p => p);
    
    if (parts.length < 2) return '';
    
    // Handle scoped packages
    if (parts[0].startsWith('@')) {
      if (parts.length < 3) return '';
      return `${parts[0]}/${parts[1]}`;
    }
    
    return parts[0];
  }

  private extractVersion(packagePath: string): string {
    // Extract version from paths like "/package-name/1.2.3"
    const parts = packagePath.split('/').filter(p => p);
    
    if (parts.length < 2) return '';
    
    // Version is always the last part
    const versionPart = parts[parts.length - 1];
    
    // Handle version strings that might have extra info
    return versionPart.split('_')[0]; // Remove pnpm-specific suffixes
  }

  private extractVersionFromSpec(versionSpec: string): string {
    // Handle version specs like "1.2.3(dependencies)" or just "1.2.3"
    const version = versionSpec.split('(')[0];
    return normalizeVersion(version);
  }
}