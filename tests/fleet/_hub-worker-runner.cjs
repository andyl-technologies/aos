// Serve the built Worker with real workerd and persistent Miniflare bindings.
// Wrangler's development proxy exits on a single upstream connection failure;
// the fleet must observe that failed request without losing its whole executor.
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const path = require('node:path');

async function main() {
  const [toolingRoot, configurationPath] = process.argv.slice(2);
  if (!toolingRoot || !configurationPath) {
    throw new Error('Pass the Miniflare tooling root and Worker configuration');
  }

  // Use the same pinned Miniflare and source-built workerd as Wrangler.
  const load = createRequire(path.join(
    toolingRoot, 'lib/node_modules/wrangler/node_modules/fleet-runner.cjs',
  ));
  const { Miniflare } = load('miniflare');
  const { certificatePath, privateKeyPath, ...options } = JSON.parse(
    readFileSync(configurationPath, 'utf8'),
  );
  const runtime = new Miniflare({
    ...options,
    modules: true,
    modulesRoot: path.dirname(options.scriptPath),
    modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    cf: false,
    https: true,
    httpsCert: readFileSync(certificatePath, 'utf8'),
    httpsKey: readFileSync(privateKeyPath, 'utf8'),
  });

  let closing;
  const stop = () => {
    closing ??= runtime.dispose();
    closing.catch(error => {
      console.error(error);
      process.exitCode = 1;
    });
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);

  try {
    console.info('Hybrid fleet Worker ready:', (await runtime.ready).href);
  } catch (error) {
    await runtime.dispose();
    throw error;
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
