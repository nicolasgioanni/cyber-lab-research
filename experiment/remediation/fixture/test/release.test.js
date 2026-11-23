const assert = require('node:assert/strict');
const { test } = require('node:test');
const { selectRelease, formatSelection } = require('../release');

test('selects the newest compatible release regardless of catalog order', () => {
  const catalog = ['2.10.0', '3.0.0', '2.9.9', '2.2.0'];
  assert.equal(selectRelease(catalog, '^2.0.0'), '2.10.0');
});

test('respects the upper bound of a maintenance channel', () => {
  assert.equal(selectRelease(['1.9.0', '2.0.0'], '>=1.8.0 <2.0.0'), '1.9.0');
});

test('a stable channel skips prerelease candidates', () => {
  assert.equal(selectRelease(['3.4.1', '3.5.0-rc.2'], '^3.0.0'), '3.4.1');
});

test('a preview channel can select an explicitly requested prerelease', () => {
  const catalog = ['3.5.0-rc.1', '3.5.0-rc.2', '3.5.0'];
  assert.equal(selectRelease(catalog, '>=3.5.0-rc.1 <3.5.0'), '3.5.0-rc.2');
});

test('reports a catalog with no matching release', () => {
  const selection = selectRelease(['1.2.0', '2.1.0'], '^4.0.0');
  assert.equal(selection, null);
  assert.equal(formatSelection('stable', selection), 'stable: no matching release');
});

test('channel output is plain by default and supports a color terminal', () => {
  assert.equal(formatSelection('stable', '2.10.0'), 'stable: 2.10.0');
  assert.equal(formatSelection('stable', '2.10.0', true), 'stable: \x1b[32m2.10.0\x1b[39m');
});
