'use strict';

const startWebServer = require('../../web');

const PORT = Number(process.env.PORT || 18080);
const bots = new Map();
const zeroUsage = () => ({ percent: '0%', used: '0 B', total: '0 B' });

const server = startWebServer({
  PORT,
  SERVER_NAME: 'Security Integration Test',
  SERVER_ROLE: 'test',
  bots,
  addNewBot: () => true,
  deleteBot: () => true,
  disconnectBotAuth: async () => true,
  prepareBotForAuth: async () => ({}),
  getPairingCode: async () => '00000000',
  loadAllowedData: () => ({ groups: [], trackedGroups: [], features: {} }),
  saveAllowedData: () => {},
  getGroupsList: async () => [],
  getContainerRamUsage: zeroUsage,
  getContainerDiskUsage: zeroUsage,
  getHostDiskUsage: zeroUsage,
  runDownloadSpeedTest: async () => ({ downloadMbps: 0, latencyMs: 0, bytes: 0, durationSeconds: 0 }),
  getInstanceStatus: () => ({ ok: true, role: 'test', whatsappActive: false }),
  restartProcess: () => {}
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
