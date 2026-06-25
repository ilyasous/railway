const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const util = require('util');

const SCRIPT = path.join(__dirname, 'index.js');
const RESTART_DELAY_MS = 2000;
const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = process.env.LOG_FILE
  ? (path.isAbsolute(process.env.LOG_FILE) ? process.env.LOG_FILE : path.join(__dirname, process.env.LOG_FILE))
  : path.join(LOG_DIR, 'server.log');

function formatLogArg(arg) {
  if (arg instanceof Error) return arg.stack || arg.message;
  if (typeof arg === 'string') return arg;
  return util.inspect(arg, { depth: 6, breakLength: 180 });
}

function installFileLogger(processName = 'supervisor') {
  if (console.__fileLoggerInstalled) return;
  const original = {};
  for (const method of ['log', 'info', 'warn', 'error', 'debug']) {
    original[method] = console[method].bind(console);
  }

  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (err) { }

  for (const method of Object.keys(original)) {
    console[method] = (...args) => {
      const line = `${new Date().toISOString()} [${processName}] [${method.toUpperCase()}] ${args.map(formatLogArg).join(' ')}\n`;
      try { fs.appendFileSync(LOG_FILE, line, 'utf8'); } catch (err) { original.error('[LOGGER] write failed:', err.message); }
      original[method](...args);
    };
  }

  console.__fileLoggerInstalled = true;
  console.log(`[LOGGER] Logs saved to ${LOG_FILE}`);
}

installFileLogger('supervisor');

function start() {
  console.log(`[SUPERVISOR] Démarrage de ${SCRIPT}...`);
  const child = spawn(process.execPath, [SCRIPT], {
    stdio: 'inherit',
    env: process.env,
  });

  child.on('exit', (code, signal) => {
    console.error(`[SUPERVISOR] Le serveur s'est arrêté (code=${code}, signal=${signal}). Redémarrage dans ${RESTART_DELAY_MS}ms...`);
    setTimeout(start, RESTART_DELAY_MS);
  });

  child.on('error', (err) => {
    console.error('[SUPERVISOR] Erreur lors du spawn:', err);
    setTimeout(start, RESTART_DELAY_MS);
  });
}

process.on('SIGINT', () => { console.log('[SUPERVISOR] SIGINT reçu, arrêt.'); process.exit(0); });
process.on('SIGTERM', () => { console.log('[SUPERVISOR] SIGTERM reçu, arrêt.'); process.exit(0); });

start();
