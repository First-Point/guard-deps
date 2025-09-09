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
 * Parse text advisories in format: "package > malware_version"
 * This means the malware_version is compromised and we should:
 * 1. Try to upgrade to newer safe version if available
 * 2. If no upgrade available, downgrade to safe version (y.z.[x-1])
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
    
    // Parse format: "package > malware_version"
    const greaterThanMatch = trimmed.match(/^(.+?)\s+>\s+(.+?)$/);
    if (greaterThanMatch) {
      const [, packageName, malwareVersion] = greaterThanMatch;
      const cleanPackageName = packageName.trim();
      const cleanMalwareVersion = malwareVersion.trim();
      
      // Calculate safe version (malware version - 1 patch)
      const safeVersion = calculateSafeVersion(cleanMalwareVersion);
      
      advisories[cleanPackageName] = {
        package: cleanPackageName,
        badVersions: [`=${cleanMalwareVersion}`], // Only the specific malware version is bad
        safeVersion: safeVersion,
        malwareVersion: cleanMalwareVersion, // Store the specific malware version
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
 * Calculate safe version by decrementing patch version from malware version
 * Format: y.z.[x-1]
 */
function calculateSafeVersion(malwareVersion: string): string {
  try {
    const parts = malwareVersion.split('.');
    if (parts.length >= 3) {
      const major = parts[0];
      const minor = parts[1];
      const patch = parseInt(parts[2]);
      
      if (patch > 0) {
        // Decrement patch version
        return `${major}.${minor}.${patch - 1}`;
      } else if (parts.length > 3) {
        // Handle pre-release versions by removing them
        return `${major}.${minor}.0`;
      }
    }
    
    // Fallback: return the malware version (user will need to investigate manually)
    return malwareVersion;
  } catch (error) {
    console.warn(`Could not calculate safe version for ${malwareVersion}:`, error);
    return malwareVersion;
  }
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
  const builtInData = `# Malware Package Detection
# Format: {package name} > {malware version}
# If malware version detected, try upgrade first, then downgrade to safe version (y.z.[x-1])

# Color and styling packages (known compromised)
ansi-regex > 6.2.1
ansi-styles > 6.2.2
backslash > 0.2.1
chalk > 5.6.1
chalk-template > 1.1.1
color > 5.0.1
color-convert > 3.1.1
color-name > 2.0.1
color-string > 2.1.1
error-ex > 1.3.3
has-ansi > 6.0.1
is-arrayish > 0.3.3
simple-swizzle > 0.2.3
slice-ansi > 7.1.1
strip-ansi > 7.1.1
supports-color > 10.2.1
supports-hyperlinks > 4.1.1
wrap-ansi > 9.0.1`;

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