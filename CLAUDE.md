# CLAUDE.md - guard-deps Project Configuration

## Project Overview
This is a defensive security tool for scanning NPM dependencies for known compromised packages. The tool identifies malicious versions and provides remediation suggestions.

## Architecture
- **Language**: Node.js ≥ 18
- **Type**: CLI security scanner (npx guard-deps)
- **Purpose**: Defensive security - detect and report compromised NPM packages

## Core Modules Structure
```
src/
├── env.ts           # Environment configuration (.env handling)
├── discover.ts      # Project discovery (recursive package.json scan)
├── lock-parser/     # Lockfile parsers (npm, yarn, pnpm)
├── advisory.ts      # Advisory list management
├── analyze.ts       # Dependency analysis and risk assessment
├── report/          # Output formatters (table, JSON, markdown)
└── cli.ts          # Command-line interface
```

## Development Standards

### Security Requirements
- **CRITICAL**: This is a defensive security tool - never introduce vulnerabilities
- No automatic package modifications - only suggest fixes
- Read-only file operations for scanning
- Safe parsing of lockfiles and package.json
- Input validation for all CLI parameters and file paths

### Code Quality
- Use TypeScript with strict mode
- Implement comprehensive error handling
- Include JSDoc for public APIs
- Follow Node.js best practices for CLI tools

### Testing Strategy
- Unit tests for parsers and analysis logic
- Integration tests for CLI commands
- Test with various lockfile formats
- Validate against known advisory datasets

### Performance Requirements
- Handle 1000+ projects within ~60 seconds
- Use parallel processing for directory traversal
- Streaming parsers for large lockfiles
- Memory-efficient advisory matching

## Key Features to Implement

### Core Functionality
1. **Project Discovery**: Recursive scan for package.json files
2. **Lockfile Parsing**: Support npm, yarn, pnpm lockfiles
3. **Advisory Matching**: Cross-reference against known bad versions
4. **Risk Classification**: compromised | at_risk | outdated | ok
5. **Multi-format Reporting**: Console table, JSON, Markdown

### CLI Interface
```bash
npx guard-deps scan [options]
  --cwd <dir>           # Single project scan
  --out <report.json>   # JSON output
  --md <report.md>      # Markdown output
  --format table|json|md
  --strict              # Only fail on confirmed compromised
  --fail-on compromised|at_risk|outdated
```

### Configuration
- Environment variable support for PROJECTS_ROOT, IGNORE_DIRS, ADVISORY_SOURCE
- Local and remote advisory sources
- Configurable ignore patterns

## Error Codes
- `0`: No issues found
- `10`: Compromised packages detected
- `11`: At-risk packages found (with --fail-on at_risk)
- `2`: Configuration error
- `3`: Parse error

## Advisory Format
```text
# Malware Package Detection
# Format: {package name} > {malware version} > {safe version}
# If malware version detected, use the specified safe version for upgrade/downgrade

chalk > 5.6.1 > 5.6.2
ansi-styles > 6.2.2 > 6.2.3
color-convert > 3.1.1 > 3.1.0
```

## Output Examples

### JSON Report Structure
```json
{
  "scannedAt": "ISO timestamp",
  "root": "/scan/path",
  "projects": [{
    "path": "relative/path",
    "manager": "npm|yarn|pnpm",
    "status": "compromised|at_risk|outdated|ok",
    "findings": [{
      "package": "name",
      "version": "current",
      "safeVersion": "recommended",
      "fix": ["npm i package@version"]
    }]
  }],
  "summary": {
    "projects": 0,
    "compromised": 0,
    "at_risk": 0,
    "outdated": 0,
    "ok": 0
  }
}
```

## Commands to Run
- `npm test` - Run test suite
- `npm run build` - Build TypeScript
- `npm run lint` - ESLint check
- `npm run typecheck` - TypeScript validation

## Development Notes
- Prioritize security and accuracy over speed
- Handle edge cases in lockfile parsing gracefully  
- Provide clear, actionable fix recommendations
- Support both local advisory files and remote sources
- Consider semver complexity when matching versions

## Roadmap Awareness
- v0.1: MVP with core scanning and JSON/table output
- v0.2: Markdown reports and fix suggestions
- v0.3: Remote advisory synchronization
- v1.0: CI/CD integration and SBOM export