'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const policy = JSON.parse(fs.readFileSync(path.join(root, '.security', 'license-policy.json'), 'utf8'));
const allowed = new Set(policy.allowed);
const denied = new Set(policy.denied);
const failures = [];
const reviewed = [];
const inventory = [];

function identifiers(expression) {
  return String(expression || '')
    .replace(/[()]/g, ' ')
    .split(/\s+(?:AND|OR|WITH)\s+/i)
    .map((value) => value.trim())
    .filter(Boolean);
}

for (const [location, metadata] of Object.entries(lock.packages || {})) {
  if (!location) continue;
  const name = location.replace(/^.*node_modules[\\/]/, '');
  const license = metadata.license;
  const ids = identifiers(license);
  inventory.push({ name, version: metadata.version || 'unknown', license: license || 'MISSING' });

  if (ids.length === 0) {
    failures.push(name + ': missing license metadata');
    continue;
  }
  const explicitlyDenied = ids.filter((id) => denied.has(id));
  const unknown = ids.filter((id) => !allowed.has(id) && !denied.has(id));
  if (explicitlyDenied.length) failures.push(name + ': denied license ' + explicitlyDenied.join(', '));
  if (unknown.length) failures.push(name + ': unreviewed license ' + unknown.join(', '));
  for (const id of ids) {
    if (policy.reviewedCopyleft[id]) reviewed.push(name + '@' + metadata.version + ': ' + id);
  }
}

const report = { generatedAt: new Date().toISOString(), packages: inventory, reviewedCopyleftPackages: reviewed, failures };
const reportDirectory = path.join(root, 'security-reports');
fs.mkdirSync(reportDirectory, { recursive: true });
fs.writeFileSync(path.join(reportDirectory, 'licenses.json'), JSON.stringify(report, null, 2));

if (failures.length) {
  console.error('FAIL: ' + failures.length + ' license policy violation(s).');
  failures.forEach((failure) => console.error('- ' + failure));
  process.exit(1);
}
console.log('PASS: ' + inventory.length + ' dependency licenses are approved; ' + reviewed.length + ' copyleft package occurrence(s) are documented.');
