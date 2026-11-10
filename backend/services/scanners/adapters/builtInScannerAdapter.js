const fs = require('fs');
const path = require('path');

// Rule definitions for Static Application Security Testing (SAST) & Secret Leaks
// Evaluated per line for high performance, predictable memory, and exact line reporting
const SAST_RULES = [
  // 1. Secrets & Credentials
  {
    id: 'SEC-001',
    title: 'Exposed AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
    severity: 'critical',
    cwe: 'CWE-798',
    description: 'A hardcoded AWS Access Key ID was discovered in source code.',
    recommendation: 'Remove AWS credentials immediately. Invalidate the key in AWS IAM and use IAM roles or environment variables.'
  },
  {
    id: 'SEC-002',
    title: 'Exposed Private Cryptographic Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
    cwe: 'CWE-798',
    description: 'An unencrypted private key is embedded directly within the repository.',
    recommendation: 'Never commit private keys. Remove the key, rotate associated certificates, and store keys in a secure key vault.'
  },
  {
    id: 'SEC-003',
    title: 'Hardcoded Database Connection String with Credentials',
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.~%+-]+@[a-zA-Z0-9_.-]+/,
    severity: 'critical',
    cwe: 'CWE-798',
    description: 'A database connection URI containing plaintext user credentials was detected.',
    recommendation: 'Store database URIs in environment variables (.env) and add .env to .gitignore.'
  },
  {
    id: 'SEC-004',
    title: 'Exposed GitHub Personal Access Token',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/,
    severity: 'critical',
    cwe: 'CWE-798',
    description: 'A GitHub Personal Access Token is hardcoded in the codebase.',
    recommendation: 'Revoke this token immediately on GitHub and use environment secrets or GitHub Actions secrets.'
  },
  {
    id: 'SEC-005',
    title: 'Exposed Slack Incoming Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]{8,12}\/B[0-9A-Za-z_]{8,12}\/[0-9A-Za-z_]{24}/,
    severity: 'high',
    cwe: 'CWE-798',
    description: 'A Slack webhook URL was found hardcoded.',
    recommendation: 'Revoke the webhook in Slack App settings and supply it via an environment variable.'
  },

  // 2. Injection Vulnerabilities
  {
    id: 'INJ-001',
    title: 'Potential SQL Injection via String Concatenation',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE).*?(?:FROM|WHERE|VALUES).*?(?:\+|(?:\$\{[^}]+\}))/i,
    severity: 'high',
    cwe: 'CWE-89',
    description: 'Dynamic SQL query constructed using string concatenation or template literals detected.',
    recommendation: 'Use parameterized queries or prepared statements (e.g., db.query("SELECT * FROM users WHERE id = $1", [id])).'
  },
  {
    id: 'INJ-002',
    title: 'Potential Command Injection Vulnerability',
    regex: /(?:child_process\.(?:exec|execSync)|os\.system|subprocess\.(?:Popen|call)\(.*shell\s*=\s*True)\s*\(/,
    severity: 'critical',
    cwe: 'CWE-78',
    description: 'Execution of OS commands using a shell interpreter. If untrusted input reaches this call, arbitrary commands can be executed.',
    recommendation: 'Avoid shell execution. Use child_process.execFile() or pass arguments as an array without shell invocation.'
  },
  {
    id: 'INJ-003',
    title: 'Unsafe Dynamic Code Evaluation (eval / Function)',
    regex: /(?:\beval\s*\(|new\s+Function\s*\(|window\.execScript\s*\()/,
    severity: 'high',
    cwe: 'CWE-95',
    description: 'Dynamic JavaScript code execution via eval() or the Function constructor can lead to remote code execution.',
    recommendation: 'Refactor code to avoid eval(). Use JSON.parse() for data serialization.'
  },

  // 3. Cross-Site Scripting (XSS)
  {
    id: 'XSS-001',
    title: 'Dangerous DOM Manipulation / Cross-Site Scripting (XSS)',
    regex: /(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:)/,
    severity: 'high',
    cwe: 'CWE-79',
    description: 'Direct insertion of raw HTML into the DOM without sanitization can enable Cross-Site Scripting attacks.',
    recommendation: 'Use textContent, innerText, or sanitize HTML using a trusted library like DOMPurify before rendering.'
  },

  // 4. Insecure Configuration & Cryptography
  {
    id: 'CRY-001',
    title: 'Use of Broken or Weak Cryptographic Hash (MD5 / SHA-1)',
    regex: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\()/i,
    severity: 'medium',
    cwe: 'CWE-328',
    description: 'MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.',
    recommendation: 'Upgrade to modern hashing algorithms such as SHA-256, SHA-512, or bcrypt / argon2 for passwords.'
  },
  {
    id: 'CFG-001',
    title: 'Disabled TLS/SSL Certificate Verification',
    regex: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|verify\s*=\s*False)/,
    severity: 'high',
    cwe: 'CWE-295',
    description: 'Disabling SSL/TLS certificate validation exposes network traffic to Man-in-the-Middle (MitM) attacks.',
    recommendation: 'Always enforce valid SSL/TLS certificate validation in production environments.'
  },
  {
    id: 'CFG-002',
    title: 'Hardcoded Weak Secret Key in JWT Signing',
    regex: /jwt\.sign\s*\([^,]+,\s*['"][^'"]{1,16}['"]/,
    severity: 'high',
    cwe: 'CWE-330',
    description: 'JSON Web Token signed with a short or hardcoded secret string.',
    recommendation: 'Sign JWTs with a strong, cryptographically generated secret stored in environment variables (process.env.JWT_SECRET).'
  }
];

// High-risk known vulnerable dependency list for SCA
const KNOWN_VULNERABLE_PACKAGES = [
  { name: 'event-stream', badVersion: '3.3.6', cwe: 'CWE-506', title: 'Malicious Flatmap-Stream Backdoor' },
  { name: 'flatmap-stream', badVersion: '*', cwe: 'CWE-506', title: 'Known Malicious Crypto Stealer' },
  { name: 'log4j', badVersion: '<=2.14.1', cwe: 'CWE-502', title: 'Log4Shell Remote Code Execution' }
];

/**
 * Native Built-In Security Scanning Engine
 * @param {string} targetDir
 * @returns {Promise<{ name: string, status: string, findings: Array }>}
 */
const runBuiltInScanner = async (targetDir) => {
  const findings = [];
  const scannedExtensions = new Set([
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.py', '.java', '.php', '.html', '.htm',
    '.json', '.env', '.yml', '.yaml', '.xml'
  ]);

  const scanDirectory = (currentDir) => {
    if (!fs.existsSync(currentDir)) return;
    const items = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      const relPath = path.relative(targetDir, fullPath).replace(/\\/g, '/');

      if (item.isDirectory()) {
        const lower = item.name.toLowerCase();
        if (
          lower === 'node_modules' ||
          lower === '.git' ||
          lower === 'dist' ||
          lower === 'build' ||
          lower === '__pycache__'
        ) {
          continue;
        }
        scanDirectory(fullPath);
      } else if (item.isFile()) {
        const ext = path.extname(item.name).toLowerCase();

        // 1. Check Dependency Manifests for SCA
        if (item.name === 'package.json') {
          try {
            const pkg = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
            const deps = { ...pkg.dependencies, ...pkg.devDependencies };
            for (const bad of KNOWN_VULNERABLE_PACKAGES) {
              if (deps[bad.name]) {
                findings.push({
                  title: `Vulnerable Dependency: ${bad.name} (${bad.title})`,
                  description: `Package "${bad.name}" contains known severe security vulnerabilities.`,
                  severity: 'critical',
                  affectedFile: relPath,
                  lineNumber: 1,
                  cwe: bad.cwe,
                  detectionSource: 'aegisor-sca',
                  codeSnippet: `"${bad.name}": "${deps[bad.name]}"`,
                  recommendation: `Remove or replace package ${bad.name} immediately.`
                });
              }
            }
          } catch {
            // Ignore parse errors
          }
        }

        // 2. Line-by-line SAST scanning on code files
        if (scannedExtensions.has(ext) || item.name.startsWith('.env')) {
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > 2 * 1024 * 1024) continue; // Skip huge files

            const content = fs.readFileSync(fullPath, 'utf8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              if (!line || line.length > 2000) continue; // Skip overly long lines (e.g. minified)

              for (const rule of SAST_RULES) {
                const match = rule.regex.exec(line);
                if (match) {
                  const lineNumber = i + 1;
                  let cleanSnippet = line.trim();

                  // Redact matched secret in snippet if rule is secret-related
                  if (rule.cwe === 'CWE-798' && match[0].length > 6) {
                    const masked = match[0].substring(0, 3) + '...' + match[0].substring(match[0].length - 3);
                    cleanSnippet = cleanSnippet.replace(match[0], masked);
                  }

                  findings.push({
                    title: rule.title,
                    description: rule.description,
                    severity: rule.severity,
                    affectedFile: relPath,
                    lineNumber,
                    cwe: rule.cwe,
                    detectionSource: 'aegisor-sast',
                    codeSnippet: cleanSnippet.length > 200 ? cleanSnippet.substring(0, 197) + '...' : cleanSnippet,
                    recommendation: rule.recommendation
                  });
                }
              }
            }
          } catch {
            // Skip unreadable files
          }
        }
      }
    }
  };

  scanDirectory(targetDir);

  return {
    name: 'AEGISOR Native Engine (SAST & Secret Scanner)',
    status: 'completed',
    findings
  };
};

module.exports = { runBuiltInScanner };
