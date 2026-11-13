#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");

const ROOT_DIR = path.resolve(__dirname, "..");
const PACKAGES_DIR = path.join(ROOT_DIR, "packages", "cawide");
const PLATFORMS_DIR = path.join(PACKAGES_DIR, "platforms");

const TARGET_MAP = {
  "aarch64-apple-darwin": { pkg: "cawide-darwin-arm64", exe: "cawide" },
  "x86_64-apple-darwin": { pkg: "cawide-darwin-x64", exe: "cawide" },
  "x86_64-unknown-linux-gnu": { pkg: "cawide-linux-x64", exe: "cawide" },
  "aarch64-unknown-linux-gnu": { pkg: "cawide-linux-arm64", exe: "cawide" },
  "x86_64-pc-windows-msvc": { pkg: "cawide-win32-x64", exe: "cawide.exe" },
};

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    version: null,
    artifacts: null,
    fromRelease: null,
    local: false,
    publish: false,
    pack: false,
    dryRun: false,
    otp: null,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--version=")) {
      options.version = arg.slice(10).replace(/^v/, "");
    } else if (arg === "--version" && i + 1 < args.length) {
      options.version = args[++i].replace(/^v/, "");
    } else if (arg.startsWith("--artifacts=")) {
      options.artifacts = path.resolve(arg.slice(12));
    } else if (arg === "--artifacts" && i + 1 < args.length) {
      options.artifacts = path.resolve(args[++i]);
    } else if (arg.startsWith("--from-release=")) {
      options.fromRelease = arg.slice(15);
    } else if (arg === "--from-release" && i + 1 < args.length) {
      options.fromRelease = args[++i];
    } else if (arg === "--local") {
      options.local = true;
    } else if (arg === "--publish") {
      options.publish = true;
    } else if (arg === "--pack") {
      options.pack = true;
    } else if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg.startsWith("--otp=")) {
      options.otp = arg.slice(6);
    } else if (arg === "--otp" && i + 1 < args.length) {
      options.otp = args[++i];
    } else if (arg === "--help" || arg === "-h") {
      console.log(
        "Usage: node scripts/package-npm.js [--version <semver>] [--local] [--from-release <tag>] [--artifacts <dir>] [--pack] [--publish] [--dry-run]"
      );
      process.exit(0);
    }
  }
  return options;
}

function stampVersions(version) {
  if (!version) return;
  const cleanVersion = version.replace(/^v/, "");
  console.log(`==> Stamping version ${cleanVersion} across npm manifests...`);

  const rootPkgPath = path.join(PACKAGES_DIR, "package.json");
  const rootPkg = JSON.parse(fs.readFileSync(rootPkgPath, "utf8"));
  rootPkg.version = cleanVersion;
  if (rootPkg.optionalDependencies) {
    for (const key of Object.keys(rootPkg.optionalDependencies)) {
      rootPkg.optionalDependencies[key] = cleanVersion;
    }
  }
  fs.writeFileSync(rootPkgPath, `${JSON.stringify(rootPkg, null, 2)}\n`);

  for (const info of Object.values(TARGET_MAP)) {
    const platPkgPath = path.join(PLATFORMS_DIR, info.pkg, "package.json");
    if (fs.existsSync(platPkgPath)) {
      const platPkg = JSON.parse(fs.readFileSync(platPkgPath, "utf8"));
      platPkg.version = cleanVersion;
      fs.writeFileSync(platPkgPath, `${JSON.stringify(platPkg, null, 2)}\n`);
    }
  }
}

function populateFromArtifacts(artifactsDir) {
  console.log(`==> Populating platform packages from artifacts: ${artifactsDir}`);
  for (const [target, info] of Object.entries(TARGET_MAP)) {
    const tarball = path.join(artifactsDir, `cawide-${target}.tar.gz`);
    const targetBinDir = path.join(PLATFORMS_DIR, info.pkg, "bin");
    fs.mkdirSync(targetBinDir, { recursive: true });

    if (fs.existsSync(tarball)) {
      console.log(`  Extracting ${target} -> ${info.pkg}...`);
      childProcess.execFileSync("tar", ["-xzf", tarball, "-C", targetBinDir], {
        stdio: "inherit",
      });
      const destBinary = path.join(targetBinDir, info.exe);
      if (fs.existsSync(destBinary)) {
        fs.chmodSync(destBinary, 0o755);
      }
    } else {
      console.warn(`  Warning: artifact not found: ${tarball}`);
    }
  }
}

function populateFromRelease(tag) {
  console.log(`==> Downloading release tarballs for tag ${tag} using gh release download...`);
  const tmpDir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "cawide-release-"));
  try {
    for (const [target, info] of Object.entries(TARGET_MAP)) {
      const pattern = `cawide-${target}.tar.gz`;
      console.log(`  Downloading ${pattern}...`);
      childProcess.execFileSync(
        "gh",
        ["release", "download", tag, "--pattern", pattern, "--dir", tmpDir, "--clobber"],
        { stdio: "inherit" }
      );
      const tarball = path.join(tmpDir, pattern);
      const targetBinDir = path.join(PLATFORMS_DIR, info.pkg, "bin");
      fs.mkdirSync(targetBinDir, { recursive: true });
      childProcess.execFileSync("tar", ["-xzf", tarball, "-C", targetBinDir], {
        stdio: "inherit",
      });
      const destBinary = path.join(targetBinDir, info.exe);
      if (fs.existsSync(destBinary)) {
        fs.chmodSync(destBinary, 0o755);
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function populateLocalBinary() {
  const currentPlatform = `${process.platform}-${process.arch}`;
  const reverseMap = {
    "darwin-arm64": TARGET_MAP["aarch64-apple-darwin"],
    "darwin-x64": TARGET_MAP["x86_64-apple-darwin"],
    "linux-x64": TARGET_MAP["x86_64-unknown-linux-gnu"],
    "linux-arm64": TARGET_MAP["aarch64-unknown-linux-gnu"],
  };

  const targetInfo = reverseMap[currentPlatform];
  if (!targetInfo) {
    throw new Error(`Unsupported current platform: ${currentPlatform}`);
  }

  const exeName = targetInfo.exe;
  const localCandidates = [
    path.join(ROOT_DIR, "target", "release", exeName),
    path.join(ROOT_DIR, "target", "debug", exeName),
  ];

  const candidate = localCandidates.find((c) => fs.existsSync(c));
  if (!candidate) {
    throw new Error(
      `No local cawide binary found in target/release or target/debug. Run: cargo build -p cawide-host --release`
    );
  }

  console.log(`==> Copying local binary ${candidate} -> ${targetInfo.pkg}...`);
  const destDir = path.join(PLATFORMS_DIR, targetInfo.pkg, "bin");
  fs.mkdirSync(destDir, { recursive: true });
  const dest = path.join(destDir, exeName);
  fs.copyFileSync(candidate, dest);
  fs.chmodSync(dest, 0o755);
}

function getNpmArgs(command) {
  const npmCli = [
    path.join(path.dirname(process.execPath), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ].find((p) => fs.existsSync(p));

  if (npmCli) {
    return { bin: process.execPath, prefixArgs: [npmCli] };
  }
  return { bin: "npm", prefixArgs: [] };
}

function runNpmIn(dir, command, dryRun) {
  console.log(`  [${path.basename(dir)}] npm ${command}`);
  if (dryRun) return;
  const { bin, prefixArgs } = getNpmArgs(command);
  const cmdStr = prefixArgs.length > 0 ? `"${bin}" "${prefixArgs[0]}" ${command}` : `npm ${command}`;
  childProcess.execSync(cmdStr, { cwd: dir, stdio: "inherit", env: process.env });
}

function isPublished(name, version) {
  try {
    const { bin, prefixArgs } = getNpmArgs();
    const args = [...prefixArgs, "view", `${name}@${version}`, "version"];
    const result = childProcess.spawnSync(bin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.status === 0 && result.stdout.trim() === version) {
      return true;
    }
  } catch {
    // Treat error as not published
  }
  return false;
}

function copyLicenses() {
  const licenseSrc = path.join(ROOT_DIR, "LICENSE");
  if (!fs.existsSync(licenseSrc)) return;
  fs.copyFileSync(licenseSrc, path.join(PACKAGES_DIR, "LICENSE"));
  for (const info of Object.values(TARGET_MAP)) {
    const dir = path.join(PLATFORMS_DIR, info.pkg);
    if (fs.existsSync(dir)) {
      fs.copyFileSync(path.join(ROOT_DIR, "LICENSE"), path.join(dir, "LICENSE"));
    }
  }
}

function publishPackages(options) {
  copyLicenses();
  console.log("==> Verifying all platform binaries exist before publishing...");
  const missing = [];
  for (const info of Object.values(TARGET_MAP)) {
    const binPath = path.join(PLATFORMS_DIR, info.pkg, "bin", info.exe);
    if (!fs.existsSync(binPath)) {
      missing.push(`${info.pkg} (${binPath})`);
    }
  }
  if (missing.length > 0) {
    throw new Error(
      `Cannot publish: missing prebuilt binaries for: ${missing.join(", ")}`
    );
  }

  const rootPkg = JSON.parse(fs.readFileSync(path.join(PACKAGES_DIR, "package.json"), "utf8"));
  const version = (options.version || options.fromRelease || rootPkg.version).replace(/^v/, "");
  if (options.otp && !/^\d{6}$/.test(options.otp)) {
    throw new Error("Invalid OTP: must be a 6-digit numeric code");
  }
  const otpArg = options.otp ? ` --otp=${options.otp}` : "";
  const publishCmdBase =
    process.env.GITHUB_ACTIONS === "true"
      ? "publish --access public --provenance"
      : "publish --access public";
  const publishCmd = `${publishCmdBase}${otpArg}`;

  // Publish each platform package first
  for (const info of Object.values(TARGET_MAP)) {
    const dir = path.join(PLATFORMS_DIR, info.pkg);
    const pkgJson = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    const pkgName = pkgJson.name;
    const pkgVersion = pkgJson.version || version;

    if (isPublished(pkgName, pkgVersion)) {
      console.log(`  [${info.pkg}] ${pkgName}@${pkgVersion} is already published, skipping.`);
    } else {
      console.log(`  [${info.pkg}] Publishing ${pkgName}@${pkgVersion}...`);
      runNpmIn(dir, publishCmd, options.dryRun);
    }
  }

  // Publish root wrapper package
  const rootName = rootPkg.name;
  if (isPublished(rootName, version)) {
    console.log(`  [root] ${rootName}@${version} is already published, skipping.`);
  } else {
    console.log(`  [root] Publishing ${rootName}@${version}...`);
    runNpmIn(PACKAGES_DIR, publishCmd, options.dryRun);
  }
}

function main() {
  const options = parseArgs();

  const versionToStamp = options.version || options.fromRelease;
  if (versionToStamp) {
    stampVersions(versionToStamp);
  }

  if (options.fromRelease) {
    populateFromRelease(options.fromRelease);
  } else if (options.artifacts) {
    populateFromArtifacts(options.artifacts);
  } else if (options.local) {
    populateLocalBinary();
  }

  if (options.pack) {
    copyLicenses();
    console.log("==> Packaging with npm pack...");
    for (const info of Object.values(TARGET_MAP)) {
      const dir = path.join(PLATFORMS_DIR, info.pkg);
      const binPath = path.join(dir, "bin", info.exe);
      if (fs.existsSync(binPath)) {
        runNpmIn(dir, "pack", options.dryRun);
      }
    }
    runNpmIn(PACKAGES_DIR, "pack", options.dryRun);
  }

  if (options.publish) {
    publishPackages(options);
  }

  console.log("==> npm packaging complete.");
}

main();
