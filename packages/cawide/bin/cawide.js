#!/usr/bin/env node

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const childProcess = require("node:child_process");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "cawide-darwin-arm64",
  "darwin-x64": "cawide-darwin-x64",
  "linux-x64": "cawide-linux-x64",
  "linux-arm64": "cawide-linux-arm64",
  "win32-x64": "cawide-win32-x64",
  "win32-arm64": "cawide-win32-x64",
};

const SIGNAL_EXIT_CODES = { SIGINT: 130, SIGTERM: 143 };

function executableName() {
  return process.platform === "win32" ? "cawide.exe" : "cawide";
}

function platformKey() {
  return `${process.platform}-${process.arch}`;
}

function platformPackageName() {
  const packageName = PLATFORM_PACKAGES[platformKey()];
  if (!packageName) {
    throw new Error(
      `${platformKey()} is not supported yet (supported: macOS, Linux, and Windows on x64/arm64).`
    );
  }
  return packageName;
}

function resolvePlatformBinary() {
  const packageName = platformPackageName();

  let packageJsonPath;
  try {
    packageJsonPath = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    if (error.code === "MODULE_NOT_FOUND") {
      throw new Error(
        `Cawide could not find the "${packageName}" platform package for ${platformKey()}.\nThis usually happens when the package was installed with --no-optional/--omit=optional, npm skipped optional dependencies, or the platform is unsupported.\nTry reinstalling without skipping optional dependencies: npm install -g cawide`
      );
    }
    throw error;
  }

  const binaryPath = path.join(path.dirname(packageJsonPath), "bin", executableName());
  if (!fs.existsSync(binaryPath)) {
    throw new Error(
      `The "${packageName}" platform package is installed but is missing its binary at ${binaryPath}. Try reinstalling: npm install -g cawide`
    );
  }
  return binaryPath;
}

function run(binaryPath) {
  const result = childProcess.spawnSync(binaryPath, process.argv.slice(2), { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.signal) {
    const signalCode =
      SIGNAL_EXIT_CODES[result.signal] ||
      (os.constants?.signals?.[result.signal]
        ? 128 + os.constants.signals[result.signal]
        : 1);
    process.exit(signalCode);
  }
  let status = result.status ?? 0;
  // On Windows, 0xC000013A (STATUS_CONTROL_C_EXIT) is reported as -1073741510 or 3221225786
  if (status === -1073741510 || status === 3221225786) {
    status = 130;
  }
  process.exit(status);
}

function main() {
  run(resolvePlatformBinary());
}

try {
  main();
} catch (error) {
  process.stderr.write(`cawide: ${error.message}\n`);
  process.exit(1);
}
