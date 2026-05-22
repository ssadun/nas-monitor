const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { describe, test, beforeEach, afterEach } = require('node:test');

const categories = require('../modules/categories.js');

// ─── Helpers ────────────────────────────────────────────────────────────────

let tmpDir;

function setup() {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'categories-test-'));
  categories.setDependencies(() => {}, tmpDir);
}

function teardown() {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

function makeReqRes(method, pathname, bodyObj) {
  const emitter = new EventEmitter();
  const req = Object.assign(emitter, { method });
  const url = new URL('http://localhost' + pathname);

  const res = {
    statusCode: null,
    headers: {},
    body: '',
    writeHead(code, hdrs) { this.statusCode = code; Object.assign(this.headers, hdrs || {}); },
    end(data) { this.body = data || ''; },
    json() { return JSON.parse(this.body); },
  };

  // emit body after a tick so handlers can attach listeners
  if (bodyObj !== undefined) {
    setImmediate(() => {
      emitter.emit('data', JSON.stringify(bodyObj));
      emitter.emit('end');
    });
  }

  return { req, res, url };
}

// ─── loadCatDefs ─────────────────────────────────────────────────────────────

describe('loadCatDefs', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('returns DEFAULT_CAT_DEFS when no file exists', () => {
    const defs = categories.loadCatDefs();
    assert.strictEqual(Array.isArray(defs), true);
    assert.strictEqual(defs.length, 4);
    assert.strictEqual(defs[0].id, 'media');
  });

  test('returns saved defs when file exists', () => {
    const custom = [{ id: 'custom', label: 'Custom', icon: '🔵', color: '#fff', dot: '#000' }];
    categories.saveCatDefs(custom);
    const loaded = categories.loadCatDefs();
    assert.deepStrictEqual(loaded, custom);
  });

  test('falls back to defaults when file contains empty array', () => {
    fs.writeFileSync(path.join(tmpDir, 'category-defs.json'), '[]', 'utf8');
    const defs = categories.loadCatDefs();
    assert.strictEqual(defs.length, 4);
  });

  test('falls back to defaults when file contains invalid JSON', () => {
    fs.writeFileSync(path.join(tmpDir, 'category-defs.json'), 'not-json', 'utf8');
    const defs = categories.loadCatDefs();
    assert.strictEqual(defs.length, 4);
  });
});

// ─── saveCatDefs / round-trip ────────────────────────────────────────────────

describe('saveCatDefs', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('persists defs and round-trips correctly', () => {
    const input = [{ id: 'foo', label: 'Foo', icon: '🟢', color: '#0f0', dot: '#0f0' }];
    categories.saveCatDefs(input);
    const raw = JSON.parse(fs.readFileSync(path.join(tmpDir, 'category-defs.json'), 'utf8'));
    assert.deepStrictEqual(raw, input);
  });
});

// ─── loadCatAssignments ──────────────────────────────────────────────────────

describe('loadCatAssignments', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('returns empty object when no file exists', () => {
    const result = categories.loadCatAssignments();
    assert.deepStrictEqual(result, {});
  });

  test('returns saved assignments', () => {
    const data = { 'my-container': 'media' };
    categories.saveCatAssignments(data);
    assert.deepStrictEqual(categories.loadCatAssignments(), data);
  });

  test('returns empty object on invalid JSON', () => {
    fs.writeFileSync(path.join(tmpDir, 'category-assignments.json'), 'bad', 'utf8');
    assert.deepStrictEqual(categories.loadCatAssignments(), {});
  });
});

// ─── saveCatAssignments ──────────────────────────────────────────────────────

describe('saveCatAssignments', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('persists assignments to disk', () => {
    const data = { plex: 'media', caddy: 'utilities' };
    categories.saveCatAssignments(data);
    const raw = JSON.parse(fs.readFileSync(path.join(tmpDir, 'category-assignments.json'), 'utf8'));
    assert.deepStrictEqual(raw, data);
  });
});

// ─── registerRoutes — GET /api/category-defs ─────────────────────────────────

describe('registerRoutes GET /api/category-defs', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('returns 200 with default defs when no file exists', () => {
    const { req, res, url } = makeReqRes('GET', '/api/category-defs');
    const handled = categories.registerRoutes(req, res, url);
    assert.strictEqual(handled, true);
    assert.strictEqual(res.statusCode, 200);
    const body = res.json();
    assert.strictEqual(Array.isArray(body), true);
    assert.strictEqual(body.length, 4);
  });

  test('returns 200 with saved defs', () => {
    const custom = [{ id: 'x', label: 'X', icon: '✓', color: '#fff', dot: '#000' }];
    categories.saveCatDefs(custom);
    const { req, res, url } = makeReqRes('GET', '/api/category-defs');
    categories.registerRoutes(req, res, url);
    assert.deepStrictEqual(res.json(), custom);
  });

  test('does not handle unrelated routes', () => {
    const { req, res, url } = makeReqRes('GET', '/api/other');
    assert.strictEqual(categories.registerRoutes(req, res, url), false);
  });
});

// ─── registerRoutes — POST /api/category-defs ────────────────────────────────

describe('registerRoutes POST /api/category-defs', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('saves valid array and responds ok', () => new Promise(resolve => {
    const newDefs = [{ id: 'test', label: 'Test', icon: '🔴', color: '#f00', dot: '#f00' }];
    const { req, res, url } = makeReqRes('POST', '/api/category-defs', newDefs);
    res.end = (data) => {
      res.body = data;
      assert.deepStrictEqual(JSON.parse(data), { ok: true });
      assert.deepStrictEqual(categories.loadCatDefs(), newDefs);
      resolve();
    };
    categories.registerRoutes(req, res, url);
  }));

  test('rejects non-array body', () => new Promise(resolve => {
    const { req, res, url } = makeReqRes('POST', '/api/category-defs', { not: 'array' });
    res.end = (data) => {
      const body = JSON.parse(data);
      assert.strictEqual(body.ok, false);
      assert.ok(body.error);
      resolve();
    };
    categories.registerRoutes(req, res, url);
  }));
});

// ─── registerRoutes — GET /api/categories ────────────────────────────────────

describe('registerRoutes GET /api/categories', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('returns empty object when no assignments saved', () => {
    const { req, res, url } = makeReqRes('GET', '/api/categories');
    categories.registerRoutes(req, res, url);
    assert.deepStrictEqual(res.json(), {});
  });

  test('returns existing assignments', () => {
    categories.saveCatAssignments({ nginx: 'utilities' });
    const { req, res, url } = makeReqRes('GET', '/api/categories');
    categories.registerRoutes(req, res, url);
    assert.deepStrictEqual(res.json(), { nginx: 'utilities' });
  });
});

// ─── registerRoutes — POST /api/categories ───────────────────────────────────

describe('registerRoutes POST /api/categories', () => {
  beforeEach(setup);
  afterEach(teardown);

  test('assigns a category to a container', () => new Promise(resolve => {
    const { req, res, url } = makeReqRes('POST', '/api/categories', { containerName: 'plex', categoryId: 'media' });
    res.end = (data) => {
      const body = JSON.parse(data);
      assert.strictEqual(body.ok, true);
      assert.strictEqual(body.assignments.plex, 'media');
      assert.strictEqual(categories.loadCatAssignments().plex, 'media');
      resolve();
    };
    categories.registerRoutes(req, res, url);
  }));

  test('removes assignment when categoryId is null', () => new Promise(resolve => {
    categories.saveCatAssignments({ plex: 'media' });
    const { req, res, url } = makeReqRes('POST', '/api/categories', { containerName: 'plex', categoryId: null });
    res.end = (data) => {
      const body = JSON.parse(data);
      assert.strictEqual(body.ok, true);
      assert.strictEqual('plex' in body.assignments, false);
      resolve();
    };
    categories.registerRoutes(req, res, url);
  }));

  test('purge removes all assignments for a category id', () => new Promise(resolve => {
    categories.saveCatAssignments({ plex: 'media', jellyfin: 'media', caddy: 'utilities' });
    const { req, res, url } = makeReqRes('POST', '/api/categories', { purge: 'media' });
    res.end = (data) => {
      const body = JSON.parse(data);
      assert.strictEqual(body.ok, true);
      assert.strictEqual('plex' in body.assignments, false);
      assert.strictEqual('jellyfin' in body.assignments, false);
      assert.strictEqual(body.assignments.caddy, 'utilities');
      resolve();
    };
    categories.registerRoutes(req, res, url);
  }));

  test('rejects missing containerName', () => new Promise(resolve => {
    const { req, res, url } = makeReqRes('POST', '/api/categories', { categoryId: 'media' });
    res.end = (data) => {
      const body = JSON.parse(data);
      assert.strictEqual(body.ok, false);
      assert.ok(body.error);
      resolve();
    };
    categories.registerRoutes(req, res, url);
  }));
});
