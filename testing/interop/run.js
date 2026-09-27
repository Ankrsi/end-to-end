'use strict';
// Cross-language test: JS <-> Kotlin <-> Swift.
//   1. JS writes vectors (primitives + real envelopes alice -> bob)
//   2. each native library reproduces the primitives, decrypts as bob (out of order), and replies
//   3. JS decrypts the replies
// Kotlin needs a JDK 11+; Swift runs on macOS (`swift test`) or in Docker (swift:5.10 image).
// A missing toolchain is skipped, not failed. Usage: npm run test:interop
const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const dir = __dirname;
const vectors = path.join(dir, 'vectors.json');
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { stdio: 'inherit', shell: process.platform === 'win32', ...opts }).status === 0;
const has = (cmd) => { try { execSync(`${cmd} --version`, { stdio: 'ignore' }); return true; } catch { return false; } };

const results = [];
if (!run('node', [path.join(dir, 'gen-vectors.js'), dir])) process.exit(1);

function verify(name, replies) {
  const ok = fs.existsSync(replies) && run('node', [path.join(dir, 'verify-replies.js'), replies, dir]);
  results.push([name, ok ? 'PASS' : 'FAIL']);
}

// Kotlin
const kotlinDir = path.join(root, 'e2e-crypto-kotlin');
const gradlew = path.join(kotlinDir, process.platform === 'win32' ? 'gradlew.bat' : 'gradlew');
if (has('java')) {
  const replies = path.join(dir, 'replies-kotlin.json');
  fs.rmSync(replies, { force: true });
  const ok = run(gradlew, ['test', '--no-daemon', '-q', `-Dinterop.vectors=${vectors}`, `-Dinterop.replies=${replies}`], { cwd: kotlinDir });
  if (ok) verify('kotlin', replies); else results.push(['kotlin', 'FAIL (gradle test)']);
} else results.push(['kotlin', 'SKIPPED (no java)']);

// Swift
const swiftDir = path.join(root, 'e2e-crypto-swift');
const swiftReplies = path.join(dir, 'replies-swift.json');
fs.rmSync(swiftReplies, { force: true });
if (has('swift')) {
  const ok = run('swift', ['test'], { cwd: swiftDir, env: { ...process.env, INTEROP_VECTORS: vectors, INTEROP_REPLIES: swiftReplies } });
  if (ok) verify('swift', swiftReplies); else results.push(['swift', 'FAIL (swift test)']);
} else if (has('docker')) {
  const ok = run('docker', ['run', '--rm', '-v', `${root}:/work`, '-v', 'e2e-swift-build:/build', '-w', '/work/e2e-crypto-swift',
    '-e', 'INTEROP_VECTORS=/work/testing/interop/vectors.json', '-e', 'INTEROP_REPLIES=/work/testing/interop/replies-swift.json',
    'swift:5.10-jammy', 'swift', 'test', '--scratch-path', '/build'], { env: { ...process.env, MSYS_NO_PATHCONV: '1' } });
  if (ok) verify('swift', swiftReplies); else results.push(['swift', 'FAIL (swift test in docker)']);
} else results.push(['swift', 'SKIPPED (no swift or docker)']);

console.log('\nInterop summary:');
for (const [name, r] of results) console.log(`  ${name.padEnd(8)} ${r}`);
process.exit(results.some(([, r]) => r.startsWith('FAIL')) ? 1 : 0);
