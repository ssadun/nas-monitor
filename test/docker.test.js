const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, test } = require('node:test');

const dockerModule = require('../modules/docker.js');
const { _test } = dockerModule;

const DEFAULT_DEPS = {
  appSettings: {
    dockerConfigFolder: '',
    dockerDataFolder: '/tmp/docker-data',
  },
  logError: () => {},
  logInfo: () => {},
  auditLog: () => {},
  readFile: async () => '',
  formatBytes: (bytes) => `${bytes}B`,
  getCache: () => ({ containers: [] }),
  refreshCache: async () => {},
};

dockerModule.setDependencies(DEFAULT_DEPS);

describe('modules/docker helper tests', () => {
  test('shellQuote escapes single quotes', () => {
    assert.strictEqual(_test.shellQuote('hello'), "'hello'");
    assert.strictEqual(_test.shellQuote("don't"), "'don'\\''t'");
    assert.strictEqual(_test.shellQuote("a'b'c"), "'a'\\''b'\\''c'");
  });

  test('parseComposeServices returns service details', () => {
    const yaml = `services:\n  web:\n    image: nginx:latest\n    container_name: web\n    ports:\n      - \"8080:80\"\n      - \"443:443\"\n  db:\n    image: postgres:latest\n    container_name: db`;

    const services = _test.parseComposeServices(yaml);

    assert.strictEqual(Array.isArray(services), true);
    assert.strictEqual(services.length, 2);
    assert.deepStrictEqual(services[0].service, 'web');
    assert.strictEqual(services[0].containerName, 'web');
    assert.deepStrictEqual(services[0].ports, [
      { host: '8080', container: '80', proto: 'tcp' },
      { host: '443', container: '443', proto: 'tcp' },
    ]);
    assert.deepStrictEqual(services[1].service, 'db');
    assert.strictEqual(services[1].containerName, 'db');
    assert.deepStrictEqual(services[1].ports, []);
  });

  test('normalizeContainerSubPath strips invalid segments', () => {
    assert.strictEqual(_test.normalizeContainerSubPath('/var/lib/containers'), 'var/lib/containers');
    assert.strictEqual(_test.normalizeContainerSubPath('..'), null);
    assert.strictEqual(_test.normalizeContainerSubPath('/../etc/passwd'), null);
    assert.strictEqual(_test.normalizeContainerSubPath('some/dir/../other'), null);
  });

  test('buildComposeSyntheticId and parseComposeSyntheticId round trip', () => {
    const syntheticId = _test.buildComposeSyntheticId('my-project', 'web');
    assert.strictEqual(syntheticId, 'compose:my-project:web');

    const parsed = _test.parseComposeSyntheticId(syntheticId);
    assert.deepStrictEqual(parsed, { project: 'my-project', service: 'web' });
  });

  test('isPathInsideRoot correctly detects path containment', () => {
    const root = path.join(os.tmpdir(), 'docker-root-test');
    const child = path.join(root, 'subdir', 'file.txt');
    const outside = path.join(os.tmpdir(), 'other-root', 'file.txt');

    assert.strictEqual(_test.isPathInsideRoot(child, root), true);
    assert.strictEqual(_test.isPathInsideRoot(root, root), true);
    assert.strictEqual(_test.isPathInsideRoot(outside, root), false);
  });

  test('getSafeComposeFilePath accepts explicit path inside configured root', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-config-root-'));
    const composeFilePath = path.join(tempRoot, 'compose.yaml');
    fs.writeFileSync(composeFilePath, 'services: {}');

    dockerModule.setDependencies({
      ...DEFAULT_DEPS,
      appSettings: { dockerConfigFolder: tempRoot },
    });

    const safePath = _test.getSafeComposeFilePath('default', composeFilePath);
    assert.strictEqual(path.resolve(safePath), path.resolve(composeFilePath));

    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  test('getSafeComposeFilePath rejects explicit path outside root', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-config-root-'));
    const outsideFile = path.join(os.tmpdir(), 'outside-compose.yaml');
    fs.writeFileSync(outsideFile, 'services: {}');

    dockerModule.setDependencies({
      ...DEFAULT_DEPS,
      appSettings: { dockerConfigFolder: tempRoot },
    });

    assert.strictEqual(_test.getSafeComposeFilePath('default', outsideFile), '');

    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(outsideFile, { force: true });
  });
});
