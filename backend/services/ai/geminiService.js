const { GoogleGenAI } = require('@google/genai');

/**
 * Redacts potential credentials, keys, and tokens from code snippets before sending to AI
 * @param {string} text
 * @returns {string}
 */
const redactSensitiveContext = (text) => {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(/(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, '[REDACTED_AWS_KEY]')
    .replace(/gh[pousr]_[A-Za-z0-9_]{36,255}/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^@\s]+@[^\s"']+/g, '[REDACTED_DB_URI]')
    .replace(/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/(?:password|secret|apiKey|api_key|token)\s*[:=]\s*['"][^'"]+['"]/gi, '$1: "[REDACTED]"');
};

/**
 * Checks whether the Gemini API key is configured
 * @returns {boolean}
 */
const isGeminiConfigured = () => {
  const key = process.env.GEMINI_API_KEY;
  return Boolean(key && key !== 'your_gemini_api_key_here' && key.trim().length > 10);
};

/**
 * Initialize Gemini client safely
 */
const getGeminiClient = () => {
  if (!isGeminiConfigured()) return null;
  return new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
};

/**
 * Generates an AI-powered beginner-friendly explanation of a security vulnerability
 * @param {object} vuln - Vulnerability model document
 * @param {string} codeSnippet - Optional code context
 * @returns {Promise<object>}
 */
const explainVulnerability = async (vuln, codeSnippet = '') => {
  if (!isGeminiConfigured()) {
    return {
      available: false,
      explanation: `[AI Explanation Unavailable] Set GEMINI_API_KEY in your backend/.env to unlock AI-assisted security breakdowns. Finding: ${vuln.title} (${vuln.cwe || 'Security Defect'}). Recommendation: ${vuln.recommendation}`
    };
  }

  try {
    const ai = getGeminiClient();
    const sanitizedSnippet = redactSensitiveContext(codeSnippet || vuln.codeSnippet || '');

    const prompt = `You are a friendly, senior application security mentor on the AEGISOR platform.
Explain this security finding to a developer in clear, beginner-friendly terms.

FINDING DETAILS:
- Title: ${vuln.title}
- Severity: ${vuln.severity}
- CWE: ${vuln.cwe || 'N/A'}
- Affected File: ${vuln.affectedFile}:${vuln.lineNumber || 1}
- Code Context:
\`\`\`
${sanitizedSnippet.substring(0, 2000)}
\`\`\`

PROVIDE A CONCISE RESPONSE (3-4 paragraphs max) with:
1. What this vulnerability means in simple terms.
2. Why it is dangerous and what an attacker could do (impact).
3. The exact, secure way to fix it with a practical code example.`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt
    });

    return {
      available: true,
      explanation: response.text
    };
  } catch (error) {
    console.error(`[AEGISOR Gemini Error] explainVulnerability: ${error.message}`);
    return {
      available: false,
      explanation: `[AI Explanation Error] Could not generate AI explanation: ${error.message}. Refer to standard recommendation: ${vuln.recommendation}`
    };
  }
};

/**
 * Generates an AI fix preview with before/after diff without touching original files
 * @param {object} vuln - Vulnerability model document
 * @param {string} fileContext - Surrounding source code
 * @returns {Promise<object>}
 */
const generateFixPreview = async (vuln, fileContext = '') => {
  if (!isGeminiConfigured()) {
    return {
      available: false,
      explanation: 'AI Fix Preview requires GEMINI_API_KEY. Default recommendation provided.',
      originalCode: vuln.codeSnippet || 'Original code snippet',
      suggestedFix: `// Remediation:\n// ${vuln.recommendation}`,
      unifiedDiff: `--- a/${vuln.affectedFile}\n+++ b/${vuln.affectedFile}\n@@ -${vuln.lineNumber || 1} +${vuln.lineNumber || 1} @@\n- ${vuln.codeSnippet || 'Vulnerable code'}\n+ // Recommended fix: ${vuln.recommendation}`
    };
  }

  try {
    const ai = getGeminiClient();
    const sanitizedContext = redactSensitiveContext(fileContext || vuln.codeSnippet || '');

    const prompt = `You are an automated code remediation assistant for the AEGISOR security platform.
Generate a safe, targeted code fix for the following security vulnerability.
DO NOT execute code. Return ONLY valid JSON matching this schema:
{
  "explanation": "Brief 1-2 sentence description of the fix",
  "originalCode": "The vulnerable code snippet",
  "suggestedFix": "The corrected secure code snippet",
  "unifiedDiff": "Standard unified diff syntax (--- a/file +++ b/file ...)"
}

Vulnerability: ${vuln.title} (${vuln.cwe || 'N/A'})
Severity: ${vuln.severity}
File: ${vuln.affectedFile} Line: ${vuln.lineNumber || 1}
Code context:
\`\`\`
${sanitizedContext.substring(0, 3000)}
\`\`\``;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json'
      }
    });

    const parsed = JSON.parse(response.text);
    return {
      available: true,
      ...parsed
    };
  } catch (error) {
    console.error(`[AEGISOR Gemini Error] generateFixPreview: ${error.message}`);
    return {
      available: false,
      explanation: `AI fix preview failed: ${error.message}`,
      originalCode: vuln.codeSnippet || '',
      suggestedFix: `// Follow recommendation: ${vuln.recommendation}`,
      unifiedDiff: null
    };
  }
};

/**
 * Generates an executive AI scan summary for an audited project
 * @param {object} scan
 * @param {object} project
 * @param {Array} topVulns
 * @returns {Promise<string>}
 */
const generateScanSummary = async (scan, project, topVulns = []) => {
  if (!isGeminiConfigured()) {
    return `Automated Audit Summary for ${project.name}: Security Score is ${scan.securityScore}/100. Discovered ${scan.totalVulnerabilities} total findings across ${project.programmingLanguages.join(', ') || 'project files'}. Configure GEMINI_API_KEY in .env for comprehensive AI narrative analysis.`;
  }

  try {
    const ai = getGeminiClient();
    const vulnList = topVulns
      .slice(0, 10)
      .map((v, i) => `${i + 1}. [${v.severity.toUpperCase()}] ${v.title} in ${v.affectedFile}:${v.lineNumber || 1}`)
      .join('\n');

    const prompt = `You are the chief security auditor for the AEGISOR platform.
Summarize the security audit results for project "${project.name}".

AUDIT METRICS:
- Security Score: ${scan.securityScore}/100
- Total Findings: ${scan.totalVulnerabilities}
- Critical: ${scan.severityBreakdown?.critical || 0}
- High: ${scan.severityBreakdown?.high || 0}
- Medium: ${scan.severityBreakdown?.medium || 0}
- Low: ${scan.severityBreakdown?.low || 0}
- Languages: ${project.programmingLanguages.join(', ')}

TOP VULNERABILITIES DETECTED:
${vulnList || 'No critical vulnerabilities detected.'}

Generate an executive 2-paragraph audit summary covering:
1. The project's overall security posture based on findings.
2. The top 3 prioritized action items for the development team.`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt
    });

    return response.text;
  } catch (error) {
    console.error(`[AEGISOR Gemini Error] generateScanSummary: ${error.message}`);
    return `Security Audit completed with Score ${scan.securityScore}/100 and ${scan.totalVulnerabilities} findings.`;
  }
};

module.exports = {
  isGeminiConfigured,
  redactSensitiveContext,
  explainVulnerability,
  generateFixPreview,
  generateScanSummary
};

