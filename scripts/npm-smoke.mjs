#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { currentTargetKey, exeName, targets } = require("../npm/lib/platform");

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const smokeRoot = path.join(root, "target", "npm-smoke");
const packDir = path.join(smokeRoot, "packs");
const prebuiltDir = path.join(smokeRoot, "prebuilt");
const projectDir = path.join(smokeRoot, "project");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  return result.stdout;
}

function pack(cwd) {
  const stdout = run("npm", ["pack", "--json", "--pack-destination", packDir], {
    cwd,
    capture: true,
  });
  const packages = JSON.parse(stdout);
  if (!Array.isArray(packages) || packages.length !== 1 || !packages[0].filename) {
    throw new Error(`unexpected npm pack output: ${stdout}`);
  }
  return path.join(packDir, packages[0].filename);
}

function assertNoInstallScripts(packageJsonPath) {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
  const scripts = packageJson.scripts || {};
  for (const name of ["preinstall", "install", "postinstall", "prepare"]) {
    if (scripts[name]) {
      throw new Error(`${packageJson.name} must not define ${name}`);
    }
  }
}

const targetKey = currentTargetKey();
if (!targetKey) {
  console.error(
    `detect-secrets-rs: no npm prebuilt target for ${process.platform}/${process.arch}`,
  );
  process.exit(1);
}

const releaseBinary = path.join(
  root,
  "target",
  "release",
  exeName("detect-secrets-rs", targets[targetKey].os),
);
if (!fs.existsSync(releaseBinary)) {
  run("cargo", ["build", "--release"]);
}

fs.rmSync(smokeRoot, { recursive: true, force: true });
fs.mkdirSync(packDir, { recursive: true });
fs.mkdirSync(projectDir, { recursive: true });

run("node", [
  "scripts/npm-prebuilt-package.mjs",
  "--target",
  targetKey,
  "--bin-dir",
  path.join(root, "target", "release"),
  "--out-dir",
  prebuiltDir,
]);

const prebuiltPackageDir = path.join(prebuiltDir, targets[targetKey].packageName);
assertNoInstallScripts(path.join(root, "package.json"));
assertNoInstallScripts(path.join(prebuiltPackageDir, "package.json"));

const rootTgz = pack(root);
const prebuiltTgz = pack(prebuiltPackageDir);

fs.writeFileSync(
  path.join(projectDir, "package.json"),
  `${JSON.stringify({ private: true, dependencies: {} }, null, 2)}\n`,
);

run("npm", [
  "install",
  "--ignore-scripts",
  "--no-audit",
  "--fund=false",
  "--omit=optional",
  rootTgz,
  prebuiltTgz,
], { cwd: projectDir });

const binName = process.platform === "win32" ? "detect-secrets-rs.cmd" : "detect-secrets-rs";
run(path.join(projectDir, "node_modules", ".bin", binName), [
  "scan",
  "--list-all-plugins",
], { cwd: projectDir });

console.log(`npm smoke passed for ${targetKey}`);
