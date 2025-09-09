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

#### Option 1: Global Installation (Recommended)
```bash
# Clone and build
git clone <repository-url>
cd guard-deps
npm install
npm run build

# Install globally for system-wide access
npm install -g .

# Now use anywhere!
guard-deps scan
guard-deps fix --dry-run
```

#### Option 2: Development Link (Best for Active Development)
```bash
# Clone and build
git clone <repository-url>
cd guard-deps
npm install
npm run build

# Link globally (one-time setup)
npm link

# Now use anywhere - updates automatically when you rebuild!
guard-deps scan
guard-deps fix --dry-run

# After making code changes, just rebuild:
npm run build  # Global command uses latest code automatically
```

#### Option 3: Local Usage (No Global Install)
```bash
# Clone and build
git clone <repository-url>
cd guard-deps
npm install
npm run build

# Use with node directly
node dist/cli.js scan
node dist/cli.js fix --dry-run
```

### Basic Usage

```bash
# After global installation, use these commands anywhere:

# Scan all projects in current directory
guard-deps scan

# Scan specific directory
guard-deps scan --cwd ./my-project

# Automatically fix compromised packages (preview first!)
guard-deps fix --dry-run
guard-deps fix

# Scan all projects under a root directory
PROJECTS_ROOT=/Users/yourname/Projects guard-deps scan
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
# Basic scan (scans current directory)
guard-deps scan

# Scan specific directory
guard-deps scan --cwd ./my-project

# Scan all projects under a root directory
guard-deps scan --cwd /Users/yourname/Projects

# Output formats
guard-deps scan --out report.json          # Save JSON report
guard-deps scan --md report.md             # Save Markdown report
guard-deps scan --format json              # Output JSON to console
guard-deps scan --format table             # Table to console (default)
guard-deps scan --format md                # Markdown to console

# Risk level configuration
guard-deps scan --strict                   # Only confirmed compromised packages
guard-deps scan --fail-on compromised      # Exit code 10 on compromised (default)
guard-deps scan --fail-on at_risk          # Exit code 11 on at-risk packages  
guard-deps scan --fail-on outdated         # Exit code 11 on outdated packages

# Combined example
guard-deps scan --cwd ~/Projects --out security-report.json --md security-report.md --fail-on at_risk
```

### `fix` - Automatic Remediation 🆕

Automatically fix compromised packages by updating root package.json files:

```bash
# Always preview first! (RECOMMENDED)
guard-deps fix --dry-run

# Basic fix (current directory)
guard-deps fix

# Fix specific project
guard-deps fix --cwd ./my-project

# Fix options
guard-deps fix --dry-run                    # Preview without applying changes
guard-deps fix --no-force                  # Disable force npm install & overrides
guard-deps fix --skip-node-modules         # Don't remove node_modules (faster)
guard-deps fix --no-backup                 # Skip package.json backup creation
guard-deps fix --no-rescan                 # Skip automatic verification scan

# Combined example
guard-deps fix --cwd ~/Projects/my-app --dry-run --no-backup
```

**Fix Process:**
1. 🔍 Scans for compromised packages (including in node_modules)
2. 🔒 Adds overrides to root package.json (forces safe versions)
3. 🗑️ Removes package-lock.json and node_modules
4. 📥 Runs npm install (installs with overrides)
5. 🔧 Runs npm audit fix (resolves remaining vulnerabilities)
6. 🔍 Re-scans to verify fixes worked

The fix command:
1. 🗑️ **Removes `node_modules`** (unless `--skip-node-modules`)
2. 📋 **Creates backup** of `package.json` (unless `--no-backup`)
3. 📦 **Updates package versions** to safe versions in `package.json`
4. 🔒 **Adds overrides/resolutions** to force specific versions
5. 💾 **Installs packages** with force flag
6. 🔍 **Re-scans** to verify fixes (unless `--no-rescan`)

### Other Commands

```bash
# List discovered projects (without scanning)
guard-deps list                             # List projects in current directory
guard-deps list --cwd /Users/yourname/Projects

# Show current configuration
guard-deps info

# Show version information  
guard-deps version

# Get help
guard-deps --help                           # General help
guard-deps scan --help                      # Scan command help
guard-deps fix --help                       # Fix command help
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

### 1. Install Globally
```bash
# One-time setup (production usage)
git clone <repository-url>
cd guard-deps
npm install && npm run build && npm install -g .

# OR for development (recommended for contributors)
git clone <repository-url>
cd guard-deps
npm install && npm run build && npm link
```

### 2. Initial Scan
```bash
# Discover security issues across all your projects
cd ~/Projects
guard-deps scan --out security-report.json --md security-report.md
```

### 3. Preview Fixes
```bash
# See what would be fixed (ALWAYS do this first!)
guard-deps fix --dry-run
```

### 4. Apply Fixes
```bash
# Automatically fix compromised packages
guard-deps fix
```

### 5. Verify Results
```bash
# Confirm all issues resolved
guard-deps scan
```

### 6. Individual Project Fixes
```bash
# Fix specific projects one by one if needed
guard-deps fix --cwd ./my-critical-app --dry-run
guard-deps fix --cwd ./my-critical-app
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

## 🛠️ Development

### Development Workflow
```bash
# Initial setup
git clone <repository-url>
cd guard-deps
npm install

# Development workflow
npm run build    # Build TypeScript
npm link         # Link globally (one-time)

# After code changes
npm run build    # Rebuild - global command updates automatically!

# Test your changes
guard-deps scan --dry-run
guard-deps fix --dry-run

# Code quality
npm run typecheck  # TypeScript validation
npm test          # Run tests (when available)
```

### Key Points
- ✅ **Use `npm link`** for development instead of `npm install -g`
- ✅ **Only rebuild** after code changes - no need to reinstall
- ✅ **Global command updates automatically** when you rebuild
- ✅ **Clean up** with `npm unlink` when done

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

## 🎯 Real-World Usage Examples

### Enterprise Security Audit
```bash
# Scan all company projects and generate comprehensive reports
guard-deps scan --cwd /company/repos --out audit-2024.json --md audit-report.md --fail-on at_risk

# Preview fixes across all projects
guard-deps fix --dry-run --cwd /company/repos

# Apply fixes with careful verification
guard-deps fix --cwd /company/repos --no-skip-node-modules
```

### CI/CD Integration
```bash
# Add to your CI pipeline
guard-deps scan --strict --fail-on compromised --format json > security-scan.json

# Exit codes: 0=safe, 10=compromised found, 2=config error
echo $? # Check exit status
```

### Developer Daily Workflow  
```bash
# Quick daily security check
guard-deps scan --cwd .

# Safe preview and fix for current project
guard-deps fix --dry-run --cwd .
guard-deps fix --cwd . --backup  # Creates backup before changes
```

### Automated Security Monitoring
```bash
# Weekly scheduled scan with email reports
guard-deps scan --cwd ~/AllProjects --md weekly-security.md
# (integrate with cron and email the markdown report)

# Emergency response - fix critical issues immediately
guard-deps fix --dry-run  # Review first
guard-deps fix           # Apply fixes
```

## 🚀 Installation & Global Usage

After global installation, guard-deps automatically:
- ✅ **Loads built-in security advisories** (no config files needed)
- ✅ **Scans transitive dependencies** in node_modules
- ✅ **Consolidates fixes** to root package.json files
- ✅ **Works from any directory** on your system

```bash
# One-time global installation
npm install -g guard-deps

# Now works everywhere!
cd ~/Documents/my-app && guard-deps scan
cd ~/Desktop/client-project && guard-deps fix --dry-run
cd /company/backend && guard-deps scan --out security.json
```

## 📄 License

MIT License - see LICENSE file for details.

---

**Guard-Deps v0.1.0** | Defensive Security for Node.js Dependencies | Built with TypeScript

*Protect your supply chain. Scan your dependencies. Stay secure.*