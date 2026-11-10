const fs = require('fs');
const path = require('path');

// Extension to language mapping
const EXTENSION_MAP = {
  '.js': 'JavaScript',
  '.jsx': 'JavaScript (React)',
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript (React)',
  '.py': 'Python',
  '.java': 'Java',
  '.c': 'C',
  '.h': 'C/C++ Header',
  '.cpp': 'C++',
  '.cc': 'C++',
  '.hpp': 'C++ Header',
  '.php': 'PHP',
  '.html': 'HTML',
  '.htm': 'HTML',
  '.css': 'CSS',
  '.scss': 'SCSS',
  '.go': 'Go',
  '.rs': 'Rust',
  '.rb': 'Ruby',
  '.sh': 'Shell',
  '.sql': 'SQL'
};

const MANIFEST_NAMES = [
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'requirements.txt',
  'Pipfile',
  'Pipfile.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'composer.json',
  'composer.lock',
  'Cargo.toml',
  'Cargo.lock',
  'go.mod',
  'go.sum'
];

const ENTRY_POINT_CANDIDATES = [
  'server.js',
  'index.js',
  'app.js',
  'main.js',
  'server.ts',
  'index.ts',
  'app.ts',
  'main.py',
  'app.py',
  'wsgi.py',
  'asgi.py',
  'index.html',
  'App.jsx',
  'App.tsx',
  'main.go',
  'main.rs',
  'index.php'
];

/**
 * Recursively scans project directory and detects languages, manifests, frameworks, entry points
 * @param {string} projectDir
 * @returns {Promise<object>}
 */
const detectProjectMetadata = async (projectDir) => {
  const languageCounts = {};
  const manifestFiles = [];
  const entryPoints = [];
  const frameworks = new Set();
  let totalFiles = 0;
  let totalLines = 0;

  const traverse = (currentDir) => {
    if (!fs.existsSync(currentDir)) return;
    const items = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      const relPath = path.relative(projectDir, fullPath).replace(/\\/g, '/');

      // Ignore common non-source directories
      if (item.isDirectory()) {
        const lowerName = item.name.toLowerCase();
        if (
          lowerName === 'node_modules' ||
          lowerName === '.git' ||
          lowerName === 'dist' ||
          lowerName === 'build' ||
          lowerName === '__pycache__' ||
          lowerName === '.venv' ||
          lowerName === 'vendor'
        ) {
          continue;
        }
        traverse(fullPath);
      } else if (item.isFile()) {
        totalFiles++;
        const ext = path.extname(item.name).toLowerCase();
        const baseName = item.name.toLowerCase();

        // Language detection
        if (EXTENSION_MAP[ext]) {
          const lang = EXTENSION_MAP[ext];
          languageCounts[lang] = (languageCounts[lang] || 0) + 1;
        }

        // Manifest detection
        if (MANIFEST_NAMES.includes(item.name)) {
          manifestFiles.push(relPath);

          // Deep framework detection from package.json
          if (item.name === 'package.json') {
            try {
              const content = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
              const allDeps = {
                ...content.dependencies,
                ...content.devDependencies
              };
              if (allDeps.express) frameworks.add('Express.js');
              if (allDeps.react) frameworks.add('React');
              if (allDeps.next) frameworks.add('Next.js');
              if (allDeps.vue) frameworks.add('Vue');
              if (allDeps['@angular/core']) frameworks.add('Angular');
              if (allDeps['@nestjs/core']) frameworks.add('NestJS');
              if (allDeps.fastify) frameworks.add('Fastify');
              if (allDeps.mongodb || allDeps.mongoose) frameworks.add('MongoDB/Mongoose');
              if (allDeps.prisma) frameworks.add('Prisma ORM');
              if (allDeps.sequelize) frameworks.add('Sequelize');
            } catch {
              // Ignore JSON parse errors in user files
            }
          }

          // Framework detection from requirements.txt
          if (item.name === 'requirements.txt') {
            try {
              const text = fs.readFileSync(fullPath, 'utf8').toLowerCase();
              if (text.includes('django')) frameworks.add('Django');
              if (text.includes('flask')) frameworks.add('Flask');
              if (text.includes('fastapi')) frameworks.add('FastAPI');
              if (text.includes('tornado')) frameworks.add('Tornado');
            } catch {
              // Ignore read errors
            }
          }
        }

        // Entry point detection
        if (ENTRY_POINT_CANDIDATES.includes(item.name)) {
          entryPoints.push(relPath);
        }

        // Lines of code count (sample readable text files under 2MB)
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size < 2 * 1024 * 1024 && EXTENSION_MAP[ext]) {
            const content = fs.readFileSync(fullPath, 'utf8');
            totalLines += content.split('\n').length;
          }
        } catch {
          // Skip binary or locked files
        }
      }
    }
  };

  traverse(projectDir);

  // Sort detected languages by file count
  const sortedLanguages = Object.entries(languageCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([lang]) => lang);

  return {
    programmingLanguages: sortedLanguages,
    frameworks: Array.from(frameworks),
    manifestFiles,
    entryPoints,
    fileCount: totalFiles,
    totalLinesOfCode: totalLines
  };
};

module.exports = {
  detectProjectMetadata
};

