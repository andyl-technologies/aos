// Exercises both installed Miniflare versions against their source-built runtimes.
// Run with AOS Node and pass the installed Miniflare store path as the argument.
const assert = require('node:assert/strict');
const { realpathSync } = require('node:fs');
const { createRequire } = require('node:module');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

async function main() {
  const root = process.argv[2];
  assert.ok(root, 'Pass the installed Miniflare output');
  assert.equal(process.env.MINIFLARE_WORKERD_PATH, undefined);
  assert.equal(process.env.LD_LIBRARY_PATH, undefined);

  const loadRoot = createRequire(path.join(root, 'lib/node_modules/runtime-check.cjs'));
  const Database = loadRoot('better-sqlite3');
  const database = new Database(':memory:');
  try {
    assert.deepEqual(database.prepare('SELECT 42 AS answer').get(), { answer: 42 });
  } finally {
    database.close();
  }

  const trees = [
    { directory: 'lib/node_modules', version: '1.20240909.0', date: '2024-09-09' },
    { directory: 'lib/node_modules/wrangler/node_modules', version: '1.20260801.1', date: '2026-08-01' },
  ];

  for (const tree of trees) {
    const load = createRequire(path.join(root, tree.directory, 'runtime-check.cjs'));
    const runtime = load('workerd');
    assert.equal(runtime.version, tree.version);
    const binary = realpathSync(runtime.default);
    assert.match(binary, /^\/nix\/store\/[^/]+-workerd(?:-modern)?-source-[^/]+\/bin\/workerd$/);
    assert.ok(execFileSync(binary, ['--version'], { encoding: 'utf8' }).includes(tree.date));

    const { Miniflare } = load('miniflare');
    const instance = new Miniflare({
      modules: true,
      compatibilityDate: tree.date,
      script: 'export default { fetch(request) { return Response.json({ answer: 42, pathname: new URL(request.url).pathname }); } };',
    });
    try {
      const response = await instance.dispatchFetch('http://example.test/source-runtime');
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { answer: 42, pathname: '/source-runtime' });
      console.log(`PASS: Miniflare request using source Workerd ${tree.version}`);
    } finally {
      await instance.dispose();
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
