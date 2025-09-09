/**
 * Advisory database management for guard-deps
 */

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { Advisory, AdvisoryDatabase } from './types';
import { resolveAdvisorySource } from './env';

/**
 * Load advisory database from various sources
 */
export async function loadAdvisories(advisorySource: string): Promise<AdvisoryDatabase> {
  // Handle built-in advisories
  if (advisorySource === 'built-in') {
    return getBuiltInAdvisories();
  }
  
  const resolvedSource = resolveAdvisorySource(advisorySource);
  
  if (resolvedSource.startsWith('http://') || resolvedSource.startsWith('https://')) {
    return loadRemoteAdvisories(resolvedSource);
  } else {
    return loadLocalAdvisories(resolvedSource);
  }
}

/**
 * Load advisories from local file
 */
export async function loadLocalAdvisories(filePath: string): Promise<AdvisoryDatabase> {
  if (!existsSync(filePath)) {
    console.warn(`Advisory file not found: ${filePath}`);
    return {};
  }

  try {
    // Check file extension to determine format
    if (filePath.endsWith('.json')) {
      return loadJsonAdvisories(filePath);
    } else if (filePath.endsWith('.txt')) {
      return loadTextAdvisories(filePath);
    } else {
      // Try to auto-detect format
      const content = await readFile(filePath, 'utf-8');
      if (content.trim().startsWith('{')) {
        return parseJsonAdvisories(content);
      } else {
        return parseTextAdvisories(content);
      }
    }
  } catch (error) {
    console.error(`Error loading advisory file ${filePath}:`, error);
    return {};
  }
}

/**
 * Load advisories from remote URL
 */
export async function loadRemoteAdvisories(url: string): Promise<AdvisoryDatabase> {
  try {
    // Note: In a real implementation, you would use a proper HTTP client
    // For now, this is a placeholder that would be implemented with fetch or axios
    console.warn(`Remote advisory loading not implemented yet for: ${url}`);
    return {};
  } catch (error) {
    console.error(`Error loading remote advisories from ${url}:`, error);
    return {};
  }
}

/**
 * Load JSON format advisories
 */
async function loadJsonAdvisories(filePath: string): Promise<AdvisoryDatabase> {
  const content = await readFile(filePath, 'utf-8');
  return parseJsonAdvisories(content);
}

/**
 * Parse JSON advisories content
 */
function parseJsonAdvisories(content: string): AdvisoryDatabase {
  const data = JSON.parse(content);
  
  // Convert to standard format if needed
  const advisories: AdvisoryDatabase = {};
  
  for (const [packageName, advisory] of Object.entries(data)) {
    const advisoryData = advisory as any;
    
    advisories[packageName] = {
      package: packageName,
      badVersions: Array.isArray(advisoryData.bad) ? advisoryData.bad : [advisoryData.bad],
      safeVersion: advisoryData.safe,
      advisoryId: advisoryData.advisoryId,
      description: advisoryData.description,
    };
  }
  
  return advisories;
}

/**
 * Load text format advisories (like malicious-packages.txt)
 */
async function loadTextAdvisories(filePath: string): Promise<AdvisoryDatabase> {
  const content = await readFile(filePath, 'utf-8');
  return parseTextAdvisories(content);
}

/**
 * Parse text advisories in format: "package > safe_version" or "package version -> safe_version"
 */
function parseTextAdvisories(content: string): AdvisoryDatabase {
  const advisories: AdvisoryDatabase = {};
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Parse new format: "package > safe_version" (versions higher than safe are bad)
    const greaterThanMatch = trimmed.match(/^(.+?)\s+>\s+(.+?)$/);
    if (greaterThanMatch) {
      const [, packageName, safeVersion] = greaterThanMatch;
      
      advisories[packageName.trim()] = {
        package: packageName.trim(),
        badVersions: [`>${safeVersion.trim()}`], // Use > to indicate "higher than"
        safeVersion: safeVersion.trim(),
      };
      continue;
    }
    
    // Parse old format: "package version -> safe_version" (for backwards compatibility)
    const arrowMatch = trimmed.match(/^(.+?)\s+(.+?)\s+->\s+(.+?)$/);
    if (arrowMatch) {
      const [, packageName, badVersion, safeVersion] = arrowMatch;
      
      if (!advisories[packageName]) {
        advisories[packageName] = {
          package: packageName,
          badVersions: [],
          safeVersion: safeVersion.trim(),
        };
      }
      
      // Add bad version to the list (exact match format)
      const badVersionTrimmed = badVersion.trim();
      advisories[packageName].badVersions.push(`=${badVersionTrimmed}`);
      continue;
    }
    
    console.warn(`Invalid advisory line format: ${trimmed}`);
  }
  
  return advisories;
}

/**
 * Get advisory for a specific package
 */
export function getAdvisory(advisories: AdvisoryDatabase, packageName: string): Advisory | undefined {
  return advisories[packageName];
}

/**
 * Check if package has any advisories
 */
export function hasAdvisory(advisories: AdvisoryDatabase, packageName: string): boolean {
  return packageName in advisories;
}

/**
 * Get all package names with advisories
 */
export function getAdvisoryPackages(advisories: AdvisoryDatabase): string[] {
  return Object.keys(advisories);
}

/**
 * Merge multiple advisory databases
 */
export function mergeAdvisories(...databases: AdvisoryDatabase[]): AdvisoryDatabase {
  const merged: AdvisoryDatabase = {};
  
  for (const db of databases) {
    for (const [packageName, advisory] of Object.entries(db)) {
      if (merged[packageName]) {
        // Merge bad versions and keep the most recent safe version
        const existing = merged[packageName];
        existing.badVersions = [...new Set([...existing.badVersions, ...advisory.badVersions])];
        // Keep the advisory with an ID if available
        if (advisory.advisoryId && !existing.advisoryId) {
          existing.advisoryId = advisory.advisoryId;
          existing.description = advisory.description;
        }
      } else {
        merged[packageName] = { ...advisory };
      }
    }
  }
  
  return merged;
}

/**
 * Get built-in advisory database when no external file is available
 */
function getBuiltInAdvisories(): AdvisoryDatabase {
  // Parse the built-in advisory data (same as malicious-packages.txt)
  const builtInData = `# Safe Package Versions - Downgrade if higher
# Format: {package name} > {safe version}
# Any version higher than the safe version should be flagged

# Color and styling packages (known compromised)
chalk > 5.3.0
strip-ansi > 7.1.0
color-convert > 2.0.1
color-name > 1.1.4
is-core-module > 2.13.1
error-ex > 1.3.2
has-ansi > 5.0.1`;

  return parseTextAdvisories(builtInData);
}

/**
 * Validate advisory database structure
 */
export function validateAdvisoryDatabase(advisories: AdvisoryDatabase): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  for (const [packageName, advisory] of Object.entries(advisories)) {
    if (!advisory.package || advisory.package !== packageName) {
      errors.push(`Advisory for ${packageName}: package name mismatch`);
    }
    
    if (!advisory.badVersions || !Array.isArray(advisory.badVersions) || advisory.badVersions.length === 0) {
      errors.push(`Advisory for ${packageName}: missing or empty badVersions`);
    }
    
    if (!advisory.safeVersion) {
      errors.push(`Advisory for ${packageName}: missing safeVersion`);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}