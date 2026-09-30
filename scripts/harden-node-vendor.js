#!/usr/bin/env node
/**
 * Raise named vendored dependencies of npm to their fixed versions.
 *
 * npm ships a full node_modules tree of its dependencies inside the package.
 * Scanners read those package.json files as an inventory of installed software,
 * so a vendored copy that has fallen behind surfaces as an image vulnerability
 * even though npm itself is current. Verified here: npm 12.1.0, the newest
 * Wolfi ships, still vendors brace-expansion 5.0.10 and ip-address 10.5.1,
 * while 5.0.11 and 10.7.1 carrying the fixes are published on the registry.
 *
 * Upgrading npm does not help - npm chooses what it vendors, and the Wolfi
 * package is already at its newest. Deleting the copies is not an option
 * either: npm imports them at runtime.
 *
 * WHY A NAMED LIST AND NOT A SWEEP
 * --------------------------------
 * Upgrading every vendored package that was behind its own declared range was
 * tried first and broke npm: `npm view` began failing silently, exit 1 with
 * nothing in the debug log, while `npm --version` and `npm help` still worked.
 * All twelve replacements were inside the ranges npm itself declares. npm tests
 * its vendored tree as a unit, so semver compatibility of an individual member
 * is not sufficient evidence that the tree still works.
 *
 * So only packages with a known advisory are touched, each named with the
 * version that fixes it. harden-pip-vendor.py names its targets for the same
 * reason. Anything not named is left exactly as npm shipped it.
 *
 * WHY THE FLOOR IS NOT A PIN
 * --------------------------
 * The version installed is the newest satisfying BOTH the fix floor and every
 * range npm's own dependencies declare for that package. A fix published next
 * month is therefore picked up with no edit here, and a package that has
 * already reached the floor on its own is left untouched. Re-running changes
 * nothing and exits 0, which the Dockerfile asserts by running it twice.
 *
 * It is deliberately strict: a target that is no longer vendored, one whose
 * declared range cannot be determined, one where no published version satisfies
 * both floor and range, or a download that fails verification, all abort the
 * build rather than leaving a half-replaced tree or a silently stale copy.
 *
 * AFTER CHANGING ANYTHING HERE, exercise npm itself - `npm help`, `npm view`
 * and `npm install` - not just `npm --version`. Only `npm view` caught the
 * regression above.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const DRY_RUN = process.env.HARDEN_DRY_RUN === '1';

/**
 * Explicit targets, each with the version at which the advisory is fixed.
 *
 * This is a named list rather than a sweep of every vendored package, and that
 * is deliberate. A blanket "upgrade everything to the newest version its range
 * allows" was tried first and broke npm: `npm view` began failing silently even
 * though all twelve replacements were inside the ranges npm itself declares.
 * npm tests its vendored tree as a unit, so semver compatibility of one member
 * is not sufficient. harden-pip-vendor.py names its targets for the same reason.
 *
 * The floor is not a pin. The newest version satisfying BOTH the floor and the
 * range npm declares is installed, so a later fix is picked up with no edit, and
 * a package already at or above the floor is left alone.
 *
 * Adding an entry requires evidence: the advisory, and the version that fixes
 * it. Removing one requires that npm's own vendored copy has reached the floor.
 */
const TARGETS = {
  // brace-expansion: our scanner does not index npm's vendored tree, but a
  // downstream consumer's does and reported findings against 5.0.10. 5.0.11 is
  // the first release carrying the fix.
  'brace-expansion': '5.0.11',
  // ip-address: same source, reported against 10.5.1; fixed in 10.7.1.
  'ip-address': '10.7.1',
};
const NPM_ROOT = process.argv[2] || '/usr/lib/node_modules/npm';
const MODULES = path.join(NPM_ROOT, 'node_modules');

// npm vendors its own semver; use it rather than reimplementing range logic.
const semver = require(path.join(MODULES, 'semver'));

function fail(msg) {
  console.error(`harden-node-vendor: ${msg}`);
  process.exit(1);
}

function getJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { accept: 'application/json' } }, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const go = (u, depth) => {
      if (depth > 5) return reject(new Error('too many redirects'));
      https.get(u, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return go(res.headers.location, depth + 1);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${u}`));
        }
        const out = fs.createWriteStream(dest);
        res.pipe(out);
        out.on('finish', () => out.close(resolve));
        out.on('error', reject);
      }).on('error', reject);
    };
    go(url, 0);
  });
}

/** Collect every range declared for each vendored package, from npm's own tree. */
function declaredRanges() {
  const ranges = new Map();
  const add = (name, range) => {
    if (!range || range === '*' || /^(file|link|git|https?):/.test(range)) return;
    if (!ranges.has(name)) ranges.set(name, new Set());
    ranges.get(name).add(range);
  };
  const roots = [path.join(NPM_ROOT, 'package.json')];
  for (const d of fs.readdirSync(MODULES)) {
    const p = path.join(MODULES, d, 'package.json');
    if (fs.existsSync(p)) roots.push(p);
  }
  for (const p of roots) {
    let pkg;
    try { pkg = JSON.parse(fs.readFileSync(p, 'utf8')); } catch { continue; }
    for (const field of ['dependencies', 'optionalDependencies']) {
      for (const [n, r] of Object.entries(pkg[field] || {})) add(n, r);
    }
  }
  return ranges;
}

async function main() {
  if (!fs.existsSync(MODULES)) fail(`no node_modules under ${NPM_ROOT}`);
  const ranges = declaredRanges();
  const installed = fs.readdirSync(MODULES).filter(
    (d) => !d.startsWith('.') && fs.existsSync(path.join(MODULES, d, 'package.json'))
  );
  if (installed.length === 0) fail(`no vendored packages found under ${MODULES}`);

  console.log(`harden-node-vendor: ${installed.length} vendored packages under ${MODULES}; ` +
              `${Object.keys(TARGETS).length} target(s)`);
  for (const name of Object.keys(TARGETS)) {
    if (!installed.includes(name)) {
      fail(`target ${name} is not vendored here - the list is stale and must be ` +
           `corrected rather than silently skipped`);
    }
  }
  let upgraded = 0;

  for (const name of installed) {
    const pkgPath = path.join(MODULES, name, 'package.json');
    const current = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version;
    const floor = TARGETS[name];
    if (!floor) continue;                       // not a target; leave it alone
    if (semver.gte(current, floor)) {
      console.log(`  ${name} ${current} already at or above the ${floor} floor`);
      continue;
    }
    const declared = ranges.get(name);
    if (!declared || declared.size === 0) {
      fail(`${name} is a target but no dependency declares a range for it; ` +
           `cannot choose a compatible version safely`);
    }

    let meta;
    try {
      meta = await getJSON(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    } catch (e) {
      fail(`cannot reach the registry for ${name}: ${e.message}`);
    }
    const all = Object.keys(meta.versions || {});
    // Newest version satisfying EVERY range npm declares for this package.
    // Must satisfy every range npm declares AND be at or above the fix floor.
    const ok = all.filter((v) =>
      semver.gte(v, floor) && [...declared].every((r) => semver.satisfies(v, r)));
    if (ok.length === 0) {
      fail(`${name}: no published version satisfies both the ${floor} floor and ` +
           `npm's declared range(s) ${[...declared].join(', ')}`);
    }
    const best = ok.sort(semver.rcompare)[0];
    if (!semver.gt(best, current)) continue;

    console.log(`  ${name} ${current} -> ${best}  (ranges: ${[...declared].join(', ')})`);
    if (DRY_RUN) { upgraded++; continue; }

    const tarball = meta.versions[best].dist.tarball;
    const dest = path.join(MODULES, name);
    const tmp = `${dest}.harden.tmp`;
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.mkdirSync(tmp, { recursive: true });
    // Downloaded with node's own https and unpacked with system tar: these
    // images ship neither wget nor curl, and depending on one would make the
    // script fail on exactly the minimal images it is meant to harden.
    const tgz = path.join(tmp, 'pkg.tgz');
    try {
      await download(tarball, tgz);
      execFileSync('tar', ['-xzf', tgz, '-C', tmp, '--strip-components=1'], { stdio: 'pipe' });
      fs.rmSync(tgz, { force: true });
    } catch (e) {
      fs.rmSync(tmp, { recursive: true, force: true });
      fail(`failed to fetch or unpack ${name}@${best}: ${e.message}`);
    }
    const got = JSON.parse(fs.readFileSync(path.join(tmp, 'package.json'), 'utf8')).version;
    if (got !== best) {
      fs.rmSync(tmp, { recursive: true, force: true });
      fail(`${name}: downloaded ${got}, expected ${best}`);
    }
    fs.rmSync(dest, { recursive: true, force: true });
    fs.renameSync(tmp, dest);
    upgraded++;
  }

  if (DRY_RUN) {
    console.log(`harden-node-vendor: DRY RUN - ${upgraded} package(s) would be upgraded`);
    return;
  }
  if (upgraded === 0) {
    console.log('harden-node-vendor: every target already at or above its fix floor');
    return;
  }
  console.log(`harden-node-vendor: ${upgraded} package(s) upgraded`);
}

main().catch((e) => fail(e.stack || String(e)));
