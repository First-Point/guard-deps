/**
 * Environment configuration management for guard-deps
 */

import { existsSync } from 'fs';
import { resolve, join } from 'path';
import { Config, CliOptions } from './types';

/**
 * Get the bundled advisory file path
 */
function getBundledAdvisoryPath(): string {
  // Try to find the advisory file relative to the current module
  const possiblePaths = [
    // When running from built dist/
    join(__dirname, '../malicious-packages.txt'),
    // When running from src/
    join(__dirname, '../malicious-packages.txt'),
    // When running as global package
    join(__dirname, '../../malicious-packages.txt'),
    // Fallback to package root
    join(process.cwd(), 'malicious-packages.txt'),
  ];
  
  for (const path of possiblePaths) {
    if (existsSync(path)) {
      return `file:${path}`;
    }
  }
  
  // If no bundled file found, create a default in-memory advisory
  return 'built-in';
}

/**
 * Default configuration values
 */
const DEFAULT_CONFIG: Partial<Config> = {
  ignoreDirs: ['node_modules', 'dist', 'build', '.git', '.next', 'coverage', '.nyc_output'],
  advisorySource: getBundledAdvisoryPath(),
  format: 'table',
  strict: false,
  failOn: 'compromised',
};

/**
 * Load configuration from environment variables and CLI options
 */
export function loadConfig(options: CliOptions = {}): Config {
  const projectsRoot = options.cwd || process.env.PROJECTS_ROOT || process.cwd();
  
  // Validate projects root exists
  if (!existsSync(projectsRoot)) {
    throw new Error(`PROJECTS_ROOT directory does not exist: ${projectsRoot}`);
  }

  const ignoreDirs = process.env.IGNORE_DIRS 
    ? process.env.IGNORE_DIRS.split(',').map(d => d.trim())
    : DEFAULT_CONFIG.ignoreDirs!;

  const advisorySource = process.env.ADVISORY_SOURCE || DEFAULT_CONFIG.advisorySource!;

  return {
    projectsRoot: resolve(projectsRoot),
    ignoreDirs,
    advisorySource,
    cwd: options.cwd,
    outputFile: options.out,
    markdownFile: options.md,
    format: options.format || DEFAULT_CONFIG.format!,
    strict: options.strict || DEFAULT_CONFIG.strict!,
    failOn: options.failOn || DEFAULT_CONFIG.failOn!,
  };
}

/**
 * Resolve advisory source path
 */
export function resolveAdvisorySource(advisorySource: string): string {
  if (advisorySource.startsWith('http://') || advisorySource.startsWith('https://')) {
    return advisorySource;
  }
  
  if (advisorySource.startsWith('file:')) {
    const filePath = advisorySource.replace('file:', '');
    return resolve(filePath);
  }
  
  // Default to file path
  return resolve(advisorySource);
}

/**
 * Validate configuration
 */
export function validateConfig(config: Config): void {
  if (!config.projectsRoot) {
    throw new Error('PROJECTS_ROOT is required');
  }

  if (!existsSync(config.projectsRoot)) {
    throw new Error(`PROJECTS_ROOT directory does not exist: ${config.projectsRoot}`);
  }

  if (!['table', 'json', 'md'].includes(config.format)) {
    throw new Error(`Invalid format: ${config.format}. Must be one of: table, json, md`);
  }

  if (!['compromised', 'at_risk', 'outdated'].includes(config.failOn)) {
    throw new Error(`Invalid failOn: ${config.failOn}. Must be one of: compromised, at_risk, outdated`);
  }
}

/**
 * Get absolute path for output files
 */
export function getOutputPath(filename: string | undefined, cwd: string = process.cwd()): string | undefined {
  if (!filename) return undefined;
  
  if (filename.startsWith('/')) {
    return filename;
  }
  
  return join(cwd, filename);
}