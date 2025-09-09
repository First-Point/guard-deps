/**
 * Yarn yarn.lock parser
 */

import { readFile } from 'fs/promises';
import { DependencyInfo, LockfileParser, ParsedLockfile, PackageManager } from '../types';
import { normalizeVersion } from './index';

interface YarnLockEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  dependencies?: { [name: string]: string };
}

export class YarnParser implements LockfileParser {
  canParse(lockfilePath: string): boolean {
    return lockfilePath.endsWith('yarn.lock');
  }

  async parse(lockfilePath: string): Promise<ParsedLockfile> {
    const content = await readFile(lockfilePath, 'utf-8');
    
    const manager: PackageManager = { name: 'yarn', lockfile: 'yarn.lock' };
    const dependencies: DependencyInfo[] = [];
    
    const entries = this.parseYarnLock(content);
    
    for (const [keyPattern, info] of entries) {
      const packageName = this.extractPackageName(keyPattern);
      if (!packageName) continue;

      dependencies.push({
        name: packageName,
        version: normalizeVersion(info.version),
        resolved: info.resolved,
        integrity: info.integrity,
      });
    }

    return { dependencies, manager };
  }

  private parseYarnLock(content: string): Map<string, YarnLockEntry> {
    const entries = new Map<string, YarnLockEntry>();
    const lines = content.split('\n');
    let currentKey = '';
    let currentEntry: Partial<YarnLockEntry> = {};
    let inEntry = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Skip comments and empty lines
      if (!line || line.startsWith('#')) {
        continue;
      }

      // Check if this is a new entry (key line)
      if (line.includes('@') && line.endsWith(':')) {
        // Save previous entry if exists
        if (currentKey && currentEntry.version) {
          entries.set(currentKey, currentEntry as YarnLockEntry);
        }

        currentKey = line.slice(0, -1).trim(); // Remove trailing ':'
        currentEntry = {};
        inEntry = true;
        continue;
      }

      if (inEntry && line.includes(' ')) {
        const [key, ...valueParts] = line.split(' ');
        const value = valueParts.join(' ').replace(/^"/, '').replace(/"$/, ''); // Remove quotes

        switch (key) {
          case 'version':
            currentEntry.version = value;
            break;
          case 'resolved':
            currentEntry.resolved = value;
            break;
          case 'integrity':
            currentEntry.integrity = value;
            break;
        }
      }

      // End of entry (empty line or end of file)
      if (!line || i === lines.length - 1) {
        if (currentKey && currentEntry.version) {
          entries.set(currentKey, currentEntry as YarnLockEntry);
        }
        inEntry = false;
        currentKey = '';
        currentEntry = {};
      }
    }

    return entries;
  }

  private extractPackageName(keyPattern: string): string {
    // Handle patterns like "package@^1.0.0" or "@scope/package@^1.0.0"
    // Split by comma first (for multiple version ranges)
    const firstPattern = keyPattern.split(',')[0].trim();
    
    // Remove quotes if present
    const cleanPattern = firstPattern.replace(/^"/, '').replace(/"$/, '');
    
    // Find the last @ that separates name from version
    const lastAtIndex = cleanPattern.lastIndexOf('@');
    if (lastAtIndex <= 0) return ''; // No @ or @ at start (scoped package)
    
    let packageName = cleanPattern.substring(0, lastAtIndex);
    
    // Handle scoped packages - if name starts with @, we need to find the second @
    if (packageName.startsWith('@')) {
      const secondAtIndex = cleanPattern.indexOf('@', 1);
      if (secondAtIndex > 0) {
        packageName = cleanPattern.substring(0, secondAtIndex);
      }
    }
    
    return packageName;
  }
}