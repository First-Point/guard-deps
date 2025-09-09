# 🛡️ Guard-Deps - NPM Dependency Security Scanner

**Guard-Deps** is a lightweight, defensive security tool that scans Node.js projects for compromised NPM packages and automatically fixes them using intelligent remediation (upgrade first, downgrade when needed).

Following recent NPM supply-chain attacks that compromised popular packages like `chalk`, `debug`, `simple-swizzle`, and others, Guard-Deps helps protect your projects by detecting known malware versions and providing intelligent remediation.

## ✨ Features

- 🔍 **Recursive Project Discovery**: Automatically finds all Node.js projects under a root directory
- 📋 **Multi-Format Lockfile Support**: Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and fallback to `package.json`
- 🎯 **Smart Security Analysis**: Detects known malware versions and intelligently remediates
- 🔧 **Automatic Fix**: Intelligent remediation - upgrades first, downgrades only when needed
- 📊 **Multiple Output Formats**: Console tables, JSON reports, and Markdown reports
- ⚡ **Fast & Scalable**: Handles 1000+ projects within ~60 seconds
- 🔒 **Safe Operations**: Read-only scanning with optional automated fixes

## 🚀 Installation

### Global Installation (Recommended for Production)
```bash
git clone <repository-url>
cd guard-deps
npm install
npm run build
npm install -g .
```

### Development Link (Best for Contributors)
```bash
git clone <repository-url>
cd guard-deps
npm install
npm run build
npm link

# After making code changes, just rebuild:
npm run build  # Global command uses latest code automatically
```

### Local Usage (No Global Install)
```bash
git clone <repository-url>
cd guard-deps
npm install
npm run build

# Use with node directly
node dist/cli.js scan
node dist/cli.js fix --dry-run
```

## 🎯 Commands

### `scan` - Security Scanning

```bash
# Basic scanning
guard-deps scan                             # Scan current directory
guard-deps scan --cwd ./my-project         # Scan specific directory
guard-deps scan --cwd /Users/name/Projects # Scan all projects under root

# Output formats
guard-deps scan --out report.json          # Save JSON report
guard-deps scan --md report.md             # Save Markdown report
guard-deps scan --format json              # Output JSON to console
guard-deps scan --format table             # Table to console (default)

# Risk level configuration
guard-deps scan --strict                   # Only confirmed compromised packages
guard-deps scan --fail-on compromised      # Exit code 10 on compromised (default)
guard-deps scan --fail-on at_risk          # Exit code 11 on at-risk packages  
guard-deps scan --audit-all                # Run npm audit on all projects
```

### `fix` - Automatic Remediation

**Always preview first with `--dry-run`!**

```bash
# Preview fixes (RECOMMENDED first step)
guard-deps fix --dry-run

# Apply fixes
guard-deps fix                              # Fix current directory
guard-deps fix --cwd ./my-project          # Fix specific project

# Fix options
guard-deps fix --no-force                  # Disable force npm install & overrides
guard-deps fix --skip-node-modules         # Don't remove node_modules (faster)
guard-deps fix --no-backup                 # Skip package.json backup creation
guard-deps fix --no-rescan                 # Skip automatic verification scan
```

**Fix Process:**
1. 🔍 Scans for compromised packages (including in node_modules)
2. 🗑️ Removes `node_modules` and `package-lock.json`
3. 📋 Creates backup of `package.json` 
4. 📦 Updates package versions to safe versions
5. 🔒 Adds overrides/resolutions to force specific versions
6. 💾 Runs npm install with force flag
7. 🔍 Re-scans to verify fixes worked

### Other Commands

```bash
guard-deps list                             # List discovered projects
guard-deps info                             # Show current configuration
guard-deps version                          # Show version information  
guard-deps --help                           # Get help for any command
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
# Clone and install globally
git clone <repository-url>
cd guard-deps
npm install && npm run build && npm install -g .

# OR for development (recommended for contributors)
git clone <repository-url>
cd guard-deps
npm install && npm run build && npm link
```

### 2. Scan Projects
```bash
cd ~/Projects
guard-deps scan --out security-report.json --md security-report.md
```

### 3. Preview & Apply Fixes
```bash
guard-deps fix --dry-run    # Preview changes
guard-deps fix              # Apply fixes
guard-deps scan             # Verify results
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

```bash
# Setup
git clone <repository-url>
cd guard-deps
npm install

# Development workflow
npm run build    # Build TypeScript
npm link         # Link globally (one-time)

# After code changes
npm run build    # Rebuild - global command updates automatically

# Code quality
npm run typecheck  # TypeScript validation
npm test          # Run tests
```

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