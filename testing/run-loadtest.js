'use strict';
const { spawn } = require('child_process');
const path = require('path');
const net = require('net');

const ROOT = path.join(__dirname, '..');
const mode = process.env.LOADTEST_MODE || 'burst';

const scenarios = {
  burst: { pairs: 100, msgs: 20, stagger: null },
  realistic: { pairs: 100, msgs: 10, stagger: 200 },
};
// LOADTEST_PAIRS / LOADTEST_MSGS scale either scenario, e.g. 500 x 20 = 10,000 messages.
const scenario = { ...(scenarios[mode] || scenarios.burst) };
if (process.env.LOADTEST_PAIRS) scenario.pairs = parseInt(process.env.LOADTEST_PAIRS, 10);
if (process.env.LOADTEST_MSGS) scenario.msgs = parseInt(process.env.LOADTEST_MSGS, 10);
const total = scenario.pairs * scenario.msgs;
scenario.label = scenario.stagger
  ? `Realistic: ${scenario.pairs} concurrent pairs, ${total} messages paced ~${scenario.stagger}ms apart (like real chat)`
  : `Burst: ${scenario.pairs} concurrent pairs, ${total} messages fired at once (stress test)`;

// Grab an unused port so we never collide with (and silently test against) a server
// that's already running on 8080.
function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  });
}

function waitForServer(child) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Server did not start within 5s')), 5000);
    child.once('exit', (code) => { clearTimeout(timeout); reject(new Error(`Server exited early (code ${code})`)); });
    child.stdout.on('data', (data) => {
      if (data.toString().includes('listening')) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.stderr.on('data', (d) => process.stderr.write(d));
  });
}

(async () => {
  console.log(`\n${scenario.label}\n`);

  const port = await getFreePort();
  const server = spawn('node', ['examples/server.js'], { cwd: ROOT, env: { ...process.env, PORT: String(port) } });
  server.stdout.on('data', d => process.env.VERBOSE && process.stdout.write(`[server] ${d}`));

  try {
    await waitForServer(server);
  } catch (e) {
    console.error(e.message);
    server.kill();
    process.exit(1);
  }

  const args = ['testing/loadtest.js', `ws://localhost:${port}`, String(scenario.pairs), String(scenario.msgs)];
  const env = { ...process.env };
  if (scenario.stagger) env.STAGGER_MS = String(scenario.stagger);

  const loadtest = spawn('node', args, { cwd: ROOT, env, stdio: 'inherit' });
  loadtest.on('exit', (code) => {
    server.kill();
    process.exit(code);
  });
})();
