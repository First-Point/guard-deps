# 🛡️ Guard-Deps - NPM Dependency Security Scanner

**Guard-Deps** is a lightweight, defensive security tool that scans Node.js projects for compromised NPM packages and automatically fixes them using intelligent remediation (upgrade first, downgrade when needed).

Following the recent NPM supply-chain attacks that compromised popular packages like `chalk`, `debug`, `simple-swizzle`, and others, Guard-Deps helps protect your projects by detecting known malware versions and providing intelligent remediation (upgrade first, downgrade if needed).

## ✨ Features

- 🔍 **Recursive Project Discovery**: Automatically finds all Node.js projects under a root directory
- 📋 **Multi-Format Lockfile Support**: Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and fallback to `package.json`
- 🎯 **Smart Security Analysis**: Detects known malware versions and intelligently remediates
- 🔧 **Automatic Fix**: Intelligent remediation - upgrades first, downgrades only when needed
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

# Additional vulnerability scanning
guard-deps scan --audit-all                # Run npm audit on all projects (not just first 3)

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
├── env.ts            # Environment configuration
├── discover.ts       # Project discovery (recursive scan)
├── lock-parser/      # Lockfile parsers (npm, yarn, pnpm)
├── advisory.ts       # Advisory database management
├── analyze.ts        # Security analysis and risk assessment
├── fix.ts           # Automatic remediation logic
├── report/          # Output formatters (table, JSON, markdown)
└── cli.ts           # Command-line interface
```


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


## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `npm test`
5. Build the project: `npm run build`
6. Submit a pull request



## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Guard-Deps v0.1.0** | Defensive Security for Node.js Dependencies | Built with TypeScript

*Protect your supply chain. Scan your dependencies. Stay secure.*