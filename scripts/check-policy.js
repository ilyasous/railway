'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const policy = JSON.parse(fs.readFileSync(path.join(root, '.security', 'security-policy.json'), 'utf8'));
const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');
const dockerignore = fs.readFileSync(path.join(root, '.dockerignore'), 'utf8');
const web = fs.readFileSync(path.join(root, 'web.js'), 'utf8');
const failures = [];

for (const file of policy.requiredFiles) {
  if (!fs.existsSync(path.join(root, file))) failures.push('required file is missing: ' + file);
}

const fromLines = dockerfile.match(/^FROM\s+\S+/gim) || [];
if (policy.container.forbidLatestBaseImage && fromLines.some((line) => /:latest(?:\s|$)/i.test(line))) {
  failures.push('Dockerfile uses a mutable :latest base image');
}
const userMatches = [...dockerfile.matchAll(/^USER\s+(\S+)/gim)];
const runtimeUser = userMatches.length ? userMatches[userMatches.length - 1][1] : '';
if (runtimeUser !== policy.container.requiredRuntimeUser) {
  failures.push('final container USER must be ' + policy.container.requiredRuntimeUser);
}
if (policy.container.requireHealthcheck && !/^HEALTHCHECK\s/im.test(dockerfile)) {
  failures.push('Dockerfile must define HEALTHCHECK');
}
for (const forbidden of policy.container.forbiddenCopiedPaths) {
  const excluded = dockerignore.split(/\r?\n/).some((line) => line.trim() === forbidden || line.trim().startsWith(forbidden + '*'));
  if (!excluded) failures.push('.dockerignore must exclude ' + forbidden);
}
if (!web.includes("app.get('" + policy.application.requiredHealthPath + "'")) {
  failures.push('application must expose ' + policy.application.requiredHealthPath);
}
if (policy.application.forbidDefaultAdminPassword && /WEB_ADMIN_PASSWORD\s*\|\|\s*['"]admin['"]/.test(web)) {
  failures.push('web admin password falls back to the known value admin');
}

const report = { generatedAt: new Date().toISOString(), policy, failures };
const reportDirectory = path.join(root, 'security-reports');
fs.mkdirSync(reportDirectory, { recursive: true });
fs.writeFileSync(path.join(reportDirectory, 'policy.json'), JSON.stringify(report, null, 2));

if (failures.length) {
  console.error('FAIL: ' + failures.length + ' policy violation(s).');
  failures.forEach((failure) => console.error('- ' + failure));
  process.exit(1);
}
console.log('PASS: repository and container satisfy the security policy as code.');
