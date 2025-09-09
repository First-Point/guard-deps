# 🛡️ Guard-Deps - NPM Dependency Security Scanner

**Guard-Deps** is a lightweight, defensive security tool that scans Node.js projects for compromised NPM packages and automatically fixes them by downgrading to safe versions.

Following the recent NPM supply-chain attacks that compromised popular packages like `chalk`, `debug`, `simple-swizzle`, and others, Guard-Deps helps protect your projects by identifying packages with versions higher than known-safe baselines and providing automated remediation.

## ✨ Features

- 🔍 **Recursive Project Discovery**: Automatically finds all Node.js projects under a root directory
- 📋 **Multi-Format Lockfile Support**: Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and fallback to `package.json`
- 🎯 **Smart Security Analysis**: Identifies packages with versions higher than safe baselines
- 🔧 **Automatic Fix**: Removes compromised packages, clears `node_modules`, downgrades to safe versions
- 📊 **Multiple Output Formats**: Console tables, JSON reports, and Markdown reports
- ⚡ **Fast & Scalable**: Handles 1000+ projects within ~60 seconds
- 🔒 **Safe Operations**: Read-only scanning with optional automated fixes

## 🚀 Quick Start

### Installation

```bash
# Clone and build
git clone <repository-url>
cd guard-deps
npm install
npm run build

# Or install globally
npm install -g .
```

### Basic Usage

```bash
# Scan all projects from PROJECTS_ROOT
node dist/cli.js scan

# Scan single project
node dist/cli.js scan --cwd ./my-project

# Automatically fix compromised packages
node dist/cli.js fix --cwd ./my-project

# Preview fixes without applying them
node dist/cli.js fix --dry-run --cwd ./my-project
```

## 📋 Configuration

Create a `.env` file in your project directory:

```env
# Root directory to scan for Node.js projects (required)
PROJECTS_ROOT=/path/to/your/projects

# Comma-separated directories to ignore during scanning
IGNORE_DIRS=node_modules,dist,build,.git,.next,coverage

# Advisory source - local file or remote URL
ADVISORY_SOURCE=file:./malicious-packages.txt
```

## 🎯 Commands

### `scan` - Security Scanning

Scan for compromised NPM dependencies:

```bash
# Basic scan
node dist/cli.js scan

# Scan specific directory
node dist/cli.js scan --cwd ./project

# Output formats
node dist/cli.js scan --out report.json          # JSON report
node dist/cli.js scan --md report.md             # Markdown report
node dist/cli.js scan --format json              # JSON to console
node dist/cli.js scan --format table             # Table to console (default)

# Risk levels
node dist/cli.js scan --strict                   # Only confirmed compromised
node dist/cli.js scan --fail-on compromised      # Fail on compromised (default)
node dist/cli.js scan --fail-on at_risk          # Fail on at-risk packages
node dist/cli.js scan --fail-on outdated         # Fail on outdated packages
```

### `fix` - Automatic Remediation 🆕

Automatically fix compromised packages:

```bash
# Basic fix
node dist/cli.js fix --cwd ./project

# Preview changes without applying
node dist/cli.js fix --dry-run --cwd ./project

# Fix options
node dist/cli.js fix --no-force                  # Disable force overrides
node dist/cli.js fix --skip-node-modules         # Keep node_modules
node dist/cli.js fix --no-backup                 # Skip backup creation
node dist/cli.js fix --no-rescan                 # Skip post-fix verification
```

The fix command:
1. 🗑️ **Removes `node_modules`** (unless `--skip-node-modules`)
2. 📋 **Creates backup** of `package.json` (unless `--no-backup`)
3. 📦 **Updates package versions** to safe versions in `package.json`
4. 🔒 **Adds overrides/resolutions** to force specific versions
5. 💾 **Installs packages** with force flag
6. 🔍 **Re-scans** to verify fixes (unless `--no-rescan`)

### Other Commands

```bash
# List discovered projects
node dist/cli.js list
node dist/cli.js list --cwd /specific/path

# Show configuration
node dist/cli.js info

# Show version
node dist/cli.js version

# Help
node dist/cli.js --help
node dist/cli.js scan --help
node dist/cli.js fix --help
```

## 🔒 Security Model

Guard-Deps uses a **safe baseline** approach:

- **`malicious-packages.txt`** contains known-safe versions for packages
- **Packages with versions HIGHER than safe versions** are flagged for downgrade
- **Packages with versions LOWER than safe versions** are considered safe

### Example Advisory Format

```text
# Safe Package Versions - Downgrade if higher
# Format: {package name} > {safe version}

chalk > 5.3.0
strip-ansi > 7.1.0
color-convert > 2.0.1
color-name > 1.1.4
is-core-module > 2.13.1
picocolors > 1.0.0
```

### Risk Levels

- 🚨 **COMPROMISED**: Version higher than safe baseline - requires immediate downgrade
- ⚠️ **AT_RISK**: Version range could resolve to compromised version
- 📅 **OUTDATED**: Legacy classification (not used in current model)
- ✅ **OK**: Version is safe or lower than baseline

## 📊 Output Examples

### Console Table Output
```
================================================================================
GUARD-DEPS SECURITY SCAN REPORT
================================================================================

┌─────────────────────┬─────────────┬─────────────────┬─────────────┬──────────────┐
│ Project             │ Status      │ Package         │ Current     │ Safe         │
├─────────────────────┼─────────────┼─────────────────┼─────────────┼──────────────┤
│ my-app              │ COMPROMISED │ picocolors      │ 1.1.1       │ 1.0.0        │
└─────────────────────┴─────────────┴─────────────────┴─────────────┴──────────────┘

SUMMARY:
┌──────────────┬───────┬────────────┐
│ Status       │ Count │ Percentage │
├──────────────┼───────┼────────────┤
│ Compromised  │ 1     │ 100%       │
└──────────────┴───────┴────────────┘
```

### JSON Report
```json
{
  "scannedAt": "2025-09-09T10:10:05.847Z",
  "root": "/path/to/projects",
  "projects": [
    {
      "path": "my-app",
      "manager": "npm",
      "status": "compromised",
      "findings": [
        {
          "package": "picocolors",
          "version": "1.1.1",
          "safeVersion": "1.0.0",
          "riskLevel": "compromised",
          "fix": [
            "npm install picocolors@1.0.0",
            "Pin picocolors to 1.0.0 in package.json"
          ]
        }
      ]
    }
  ],
  "summary": {
    "projects": 1,
    "compromised": 1,
    "at_risk": 0,
    "outdated": 0,
    "ok": 0
  }
}
```

## 🔧 Package Manager Support

| Package Manager | Lockfile | Overrides Support |
|----------------|----------|-------------------|
| **NPM** | `package-lock.json` | `overrides` field |
| **Yarn** | `yarn.lock` | `resolutions` field |
| **PNPM** | `pnpm-lock.yaml` | `pnpm.overrides` field |
| **Fallback** | `package.json` | Direct dependency updates |

## 🎯 Exit Codes

- **0**: No issues found / successful fix
- **10**: Compromised packages found
- **11**: At-risk packages found (with `--fail-on at_risk`)
- **2**: Configuration error
- **3**: Parse error

## 🔄 Typical Workflow

### 1. Initial Scan
```bash
# Discover security issues
node dist/cli.js scan --out initial-scan.json
```

### 2. Preview Fix
```bash
# See what would be fixed
node dist/cli.js fix --dry-run
```

### 3. Apply Fix
```bash
# Automatically fix issues
node dist/cli.js fix
```

### 4. Verify
```bash
# Confirm all issues resolved
node dist/cli.js scan
```

## 🏗️ Architecture

```
src/
├── types.ts           # TypeScript interfaces
├── env.ts            # Environment configuration (.env handling)
├── discover.ts       # Project discovery (recursive scan)
├── lock-parser/      # Lockfile parsers (npm, yarn, pnpm)
├── advisory.ts       # Advisory database management
├── analyze.ts        # Security analysis and risk assessment
├── fix.ts           # Automatic remediation logic
├── report/          # Output formatters (table, JSON, markdown)
└── cli.ts           # Command-line interface
```

## 🔒 Security & Performance

- **Safe**: Only reads files during scanning; writes only during explicit fix operations
- **Fast**: Parallel directory traversal and lockfile parsing
- **Scalable**: Handles 1000+ projects within ~60 seconds
- **Defensive**: Comprehensive error handling and input validation

## 📈 Roadmap

- **v0.1**: ✅ MVP (scan + advisory check + JSON/table outputs + fix command)
- **v0.2**: Markdown reporting, enhanced fix suggestions
- **v0.3**: Remote advisory sync (Socket.dev, Aikido integration)  
- **v1.0**: CI/CD examples, Git hooks, SBOM export

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `npm test`
5. Build the project: `npm run build`
6. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

---

**Guard-Deps v0.1.0** | Defensive Security for Node.js Dependencies | Built with TypeScript

*Protect your supply chain. Scan your dependencies. Stay secure.*