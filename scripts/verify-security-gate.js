'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const reportDirectory = path.join(root, 'security-reports');
fs.mkdirSync(reportDirectory, { recursive: true });

const stages = [
  ['1', 'Secrets detection', process.env.STAGE_SECRETS],
  ['2', 'Code quality', process.env.STAGE_QUALITY],
  ['3', 'SAST', process.env.STAGE_SAST],
  ['4', 'SCA', process.env.STAGE_SCA],
  ['5', 'IaC scan', process.env.STAGE_IAC],
  ['6', 'License check', process.env.STAGE_LICENSE],
  ['7', 'Container scan', process.env.STAGE_CONTAINER],
  ['8', 'SBOM generation', process.env.STAGE_SBOM],
  ['9', 'SLSA provenance', process.env.STAGE_PROVENANCE],
  ['10', 'Image signing', process.env.STAGE_SIGNING],
  ['11', 'Policy as code', process.env.STAGE_POLICY],
  ['12', 'DAST (ZAP)', process.env.STAGE_DAST],
  ['13', 'Integration tests', process.env.STAGE_INTEGRATION]
];

const releaseRun = process.env.RELEASE_RUN === 'true';
const buildOutcome = process.env.CONTAINER_BUILD;
const failures = [];
for (const [number, name, outcome] of stages) {
  const supplyChainOnly = number === '9' || number === '10';
  const accepted = outcome === 'success' || (!releaseRun && supplyChainOnly && outcome === 'skipped');
  if (!accepted) failures.push(number + '. ' + name + ': ' + (outcome || 'missing'));
}
if (buildOutcome !== 'success') failures.push('candidate container build: ' + (buildOutcome || 'missing'));

const summary = {
  generatedAt: new Date().toISOString(),
  releaseRun,
  containerBuild: buildOutcome,
  stages: stages.map(([number, name, outcome]) => ({ number: Number(number), name, outcome })),
  passed: failures.length === 0,
  failures
};
fs.writeFileSync(path.join(reportDirectory, 'gate-summary.json'), JSON.stringify(summary, null, 2));

const lines = [
  '## 13-stage security gate',
  '',
  '| # | Stage | Outcome |',
  '|---:|---|---|',
  ...summary.stages.map((stage) => '| ' + stage.number + ' | ' + stage.name + ' | ' + stage.outcome + ' |'),
  '',
  failures.length ? '**BLOCKED**: one or more required checks failed.' : '**PASSED**: deployment may proceed.'
];
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');

if (failures.length) {
  console.error('SECURITY GATE BLOCKED');
  failures.forEach((failure) => console.error('- ' + failure));
  process.exit(1);
}
console.log('SECURITY GATE PASSED: all required stages succeeded.');
