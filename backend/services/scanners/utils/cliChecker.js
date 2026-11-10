const { execSync } = require('child_process');

/**
 * Checks whether a command-line tool is installed and available in PATH
 * @param {string} commandName
 * @returns {boolean}
 */
const isCommandAvailable = (commandName) => {
  try {
    const isWindows = process.platform === 'win32';
    const checkCmd = isWindows ? `where ${commandName}` : `which ${commandName}`;
    execSync(checkCmd, { stdio: 'ignore', timeout: 3000 });
    return true;
  } catch {
    return false;
  }
};

module.exports = { isCommandAvailable };

