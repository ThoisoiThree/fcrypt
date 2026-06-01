#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const platformPackages = {
  'darwin:arm64': '@thoisoithree/fcrypt-darwin-arm64',
  'darwin:x64': '@thoisoithree/fcrypt-darwin-x64',
  'linux:arm64': '@thoisoithree/fcrypt-linux-arm64',
  'linux:x64': '@thoisoithree/fcrypt-linux-x64',
  'win32:arm64': '@thoisoithree/fcrypt-win32-arm64',
  'win32:x64': '@thoisoithree/fcrypt-win32-x64'
};

const supportedPlatforms = Object.keys(platformPackages)
  .map((key) => key.replace(':', '/'))
  .sort()
  .join(', ');

function exitWithError(message) {
  console.error(`[fcrypt] ${message}`);
  process.exit(1);
}

const platformKey = `${process.platform}:${process.arch}`;
const packageName = platformPackages[platformKey];

if (!packageName) {
  exitWithError(
    `No prebuilt binary is available for ${process.platform}/${process.arch}. ` +
      `Supported platforms: ${supportedPlatforms}.`
  );
}

let packageJsonPath;

try {
  packageJsonPath = require.resolve(`${packageName}/package.json`);
} catch (error) {
  exitWithError(
    `The platform package ${packageName} is not installed. ` +
      'Reinstall @thoisoithree/fcrypt or install from Cargo with: cargo install filecrypt'
  );
}

const binaryName = process.platform === 'win32' ? 'fcrypt.exe' : 'fcrypt';
const binaryPath = path.join(path.dirname(packageJsonPath), 'bin', binaryName);

if (!fs.existsSync(binaryPath)) {
  exitWithError(`The expected binary was not found: ${binaryPath}`);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: 'inherit'
});

if (result.error) {
  exitWithError(result.error.message);
}

if (typeof result.status === 'number') {
  process.exit(result.status);
}

if (result.signal) {
  exitWithError(`The binary was terminated by signal ${result.signal}.`);
}

process.exit(1);
