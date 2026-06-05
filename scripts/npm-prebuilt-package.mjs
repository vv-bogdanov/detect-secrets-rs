#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targets = JSON.parse(
  fs.readFileSync(path.join(root, "npm", "prebuilt-targets.json"), "utf8"),
);
const rootPackage = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);

function usage() {
  console.error(
    "usage: node scripts/npm-prebuilt-package.mjs --target <target> --bin-dir <dir> --out-dir <dir>",
  );
  console.error(`targets: ${Object.keys(targets).join(", ")}`);
}

function readArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      usage();
      process.exit(2);
    }
    const key = arg.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      usage();
      process.exit(2);
    }
    args[key] = value;
    index += 1;
  }
  return args;
}

function exeName(name, os) {
  return os === "win32" ? `${name}.exe` : name;
}

function copyBinary(name, target, binDir, packageDir) {
  const fileName = exeName(name, target.os);
  const from = path.join(binDir, fileName);
  if (!fs.existsSync(from)) {
    console.error(`missing built binary for ${target.packageName}: ${from}`);
    process.exit(1);
  }

  const to = path.join(packageDir, "bin", fileName);
  fs.copyFileSync(from, to);
  if (target.os !== "win32") {
    fs.chmodSync(to, 0o755);
  }
}

const args = readArgs(process.argv.slice(2));
const target = targets[args.target];
if (!target || !args["bin-dir"] || !args["out-dir"]) {
  usage();
  process.exit(2);
}

const packageDir = path.resolve(args["out-dir"], target.packageName);
fs.rmSync(packageDir, { recursive: true, force: true });
fs.mkdirSync(path.join(packageDir, "bin"), { recursive: true });

copyBinary("detect-secrets-rs", target, path.resolve(args["bin-dir"]), packageDir);

fs.copyFileSync(path.join(root, "LICENSE"), path.join(packageDir, "LICENSE"));
fs.writeFileSync(
  path.join(packageDir, "README.md"),
  `# ${target.packageName}

${target.description}.

This is an optional native binary package for
[detect-secrets-rs](https://www.npmjs.com/package/detect-secrets-rs), a fast
Rust implementation of the common \`detect-secrets scan\` workflow.

Do not install this package directly. Install the main package instead:

\`\`\`bash
npm install -g detect-secrets-rs
npx detect-secrets-rs scan --help
\`\`\`

This package contains only the native \`detect-secrets-rs\` binary for its
target platform, plus package metadata and license/readme files.

Supply-chain notes:

- no runtime dependencies;
- no install scripts or postinstall downloads;
- published from the project GitHub Actions workflow with npm provenance
  enabled;
- source, release workflow, and security policy are maintained in
  ${rootPackage.repository.url.replace(/^git\+/, "").replace(/\.git$/, "")}.

`,
);

const packageJson = {
  name: target.packageName,
  version: rootPackage.version,
  description: target.description,
  author: rootPackage.author,
  license: rootPackage.license,
  repository: rootPackage.repository,
  homepage: rootPackage.homepage,
  bugs: rootPackage.bugs,
  keywords: [
    "detect-secrets-rs",
    "detect-secrets",
    "prebuilt",
    "native-binary",
    "platform-package",
    `${target.os}-${target.cpu}`,
  ],
  engines: rootPackage.engines,
  os: [target.os],
  cpu: [target.cpu],
  files: ["bin/**", "LICENSE", "README.md"],
  publishConfig: {
    access: "public",
  },
};

if (target.libc) {
  packageJson.libc = [target.libc];
}

fs.writeFileSync(
  path.join(packageDir, "package.json"),
  `${JSON.stringify(packageJson, null, 2)}\n`,
);

console.log(packageDir);
