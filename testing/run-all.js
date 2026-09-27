'use strict';
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const sections = [];
let anyFailed = false;

function run(title, cmd, args, env = {}) {
  console.log(`\n${'='.repeat(70)}\n${title}\n${'='.repeat(70)}`);
  const result = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', env: { ...process.env, ...env } });
  const output = (result.stdout || '') + (result.stderr || '');
  process.stdout.write(output);
  if (result.status !== 0) anyFailed = true;
  sections.push({ title, output, ok: result.status === 0 });
  return result.status === 0;
}

const startedAt = new Date();

const okFunctional =
  run('1. FUNCTIONAL CORRECTNESS TESTS (native backend)', 'node', ['testing/functional.test.js']) &
  run('1b. FUNCTIONAL CORRECTNESS TESTS (pure-JS backend, as in React Native)', 'node', ['testing/functional.test.js'], { E2E_BACKEND: 'noble' });

// Only run perf tests if correctness passed — no point benchmarking broken crypto
if (okFunctional) {
  run('2. ISOLATED CRYPTO BENCHMARKS (no network)', 'node', ['testing/bench.js']);
  run('3. LOAD TEST — BURST (worst case: everything fired at once)', 'node', ['testing/run-loadtest.js'], { LOADTEST_MODE: 'burst' });
  run('4. LOAD TEST — REALISTIC PACING (~200ms between messages)', 'node', ['testing/run-loadtest.js'], { LOADTEST_MODE: 'realistic' });
} else {
  console.log('\n⚠ Skipping benchmarks and load tests because functional tests failed. Fix correctness first.');
}

const finishedAt = new Date();

// --- Write a report file ---
const reportPath = path.join(ROOT, 'testing', `report-${startedAt.toISOString().replace(/[:.]/g, '-')}.md`);
const report = [
  `# E2E Chat Test Report`,
  ``,
  `Run: ${startedAt.toISOString()}`,
  `Duration: ${((finishedAt - startedAt) / 1000).toFixed(1)}s`,
  `Node: ${process.version}`,
  `CPUs: ${require('os').cpus().length}x ${require('os').cpus()[0]?.model || 'unknown'}`,
  `Overall: ${anyFailed ? '❌ FAILED' : '✅ ALL PASSED'}`,
  ``,
  ...sections.map(s => `## ${s.title}\n\n${s.ok ? '✅ OK' : '❌ FAILED'}\n\n\`\`\`\n${s.output.trim()}\n\`\`\`\n`),
].join('\n');

fs.writeFileSync(reportPath, report);
console.log(`\n${'='.repeat(70)}`);
console.log(anyFailed ? '❌ SOME TESTS FAILED' : '✅ ALL TESTS PASSED');
console.log(`Report written to: ${reportPath}`);
console.log('='.repeat(70));

process.exit(anyFailed ? 1 : 0);
