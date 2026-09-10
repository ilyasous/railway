'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const ignoredDirectories = new Set([
  '.git',
  'node_modules',
  'security-reports',
  'logs',
  'docs'
]);
const files = [];

function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && (ignoredDirectories.has(entry.name) || entry.name.startsWith('auth_info_'))) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) visit(absolute);
    else if (entry.isFile() && entry.name.endsWith('.js')) files.push(absolute);
  }
}

visit(root);
let failed = false;
for (const file of files.sort()) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failed = true;
    process.stderr.write(result.stderr || result.stdout || ('Syntax check failed: ' + file + '\n'));
  }
}

if (failed) process.exit(1);
console.log('PASS: JavaScript syntax is valid in ' + files.length + ' files.');
