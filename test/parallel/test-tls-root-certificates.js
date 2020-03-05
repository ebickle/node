'use strict';

const common = require('../common');
if (!common.hasCrypto) common.skip('missing crypto');

const fixtures = require('../common/fixtures');
const assert = require('assert');
const tls = require('tls');
const { fork } = require('child_process');

const extraCertFiles = [
  'ca1-cert.pem',
  'ca2-cert.pem',
  'ca3-cert.pem',
  'ca4-cert.pem',
  'ca5-cert.pem',
  'ca6-cert.pem'
];

// Spawn tests in a child process to check NODE_EXTRA_CA_CERTS behavior.
if (process.argv[2] !== 'child') {
  const env = {
    ...process.env,
    NODE_EXTRA_CA_CERTS: fixtures.path('keys', extraCertFiles[0])
  };

  fork(__filename, ['child'], { env }).on('exit', common.mustCall((status) => {
    assert.strictEqual(status, 0);
  }));

  return;
}

function testGetRootCertificates() {
  assert(Array.isArray(tls.rootCertificates));

  // Getter should return the same object.
  assert.strictEqual(tls.rootCertificates, tls.rootCertificates);

  // Array is immutable.
  assert.throws(() => tls.rootCertificates[0] = 0, /TypeError/);
  assert.throws(() => tls.rootCertificates.push(''), /TypeError/);

  // Does not contain duplicates.
  assert.strictEqual(tls.rootCertificates.length,
                     new Set(tls.rootCertificates).size);

  // Array values are PEM-encoded strings.
  // Only one certificate per array entry.
  assert(tls.rootCertificates.every((s) => {
    const beginCert = '-----BEGIN CERTIFICATE-----\n';
    return (s.lastIndexOf(beginCert) === 0);
  }));

  assert(tls.rootCertificates.every((s) => {
    const endCert = '\n-----END CERTIFICATE-----\n';
    return (s.indexOf(endCert) === s.length - endCert.length);
  }));
}

const extraCerts = extraCertFiles.map((f) => fixtures.readKey(f, 'utf8'));

// Basic checks.
testGetRootCertificates();
assert(tls.rootCertificates.length > 0);

// Contains certificate loaded via NODE_EXTRA_CERTS environment variable.
assert(tls.rootCertificates.includes(extraCerts[0]));

// Can't set to non-array types.
assert.throws(() => tls.rootCertificates = undefined, /TypeError/);
assert.throws(() => tls.rootCertificates = null, /TypeError/);
assert.throws(() => tls.rootCertificates = 0, /TypeError/);
assert.throws(() => tls.rootCertificates = extraCerts[0], /TypeError/);
assert.throws(() => delete tls.rootCertificates, /TypeError/);
assert.throws(() => tls.rootCertificates = [1], /TypeError/);
assert.throws(() => tls.rootCertificates = [null], /TypeError/);

// Can set to empty array.
tls.rootCertificates = [];
testGetRootCertificates();
assert.strictEqual(tls.rootCertificates.length, 0);

// Can set to array of PEM-encoded strings.
tls.rootCertificates = extraCerts;
testGetRootCertificates();
assert.strictEqual(tls.rootCertificates.length, extraCerts.length);
assert.notStrictEqual(tls.rootCertificates, extraCerts);
for (let i = 0; i < extraCerts.length; i++) {
  assert(tls.rootCertificates.includes(
    extraCerts[i].trim() + '\n'));
}

// A single PEM-encoded string can contain multiple certificates.
// Excess whitespace shouldn't adversely affect it.
tls.rootCertificates = [
  '\n    \n\n' + extraCerts[0] + '\n    \n\n',
  extraCerts[1] + '\n\n' + extraCerts[2],
  extraCerts[3]
];
testGetRootCertificates();
assert.strictEqual(tls.rootCertificates.length, 4);
for (let i = 0; i < 4; i++) {
  assert(tls.rootCertificates.includes(
    extraCerts[i].trim() + '\n'));
}

// Strings that aren't PEM-encoded are ignored.
// This is OpenSSL's own behavior when reading PEMs.
tls.rootCertificates = ['INVALID', extraCerts[0], '', ' '];
assert.strictEqual(tls.rootCertificates.length, 1);

// Invaid certificate bodies throw an error.
assert.throws(() => tls.rootCertificates = [
  '-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----\n'
], /Error/);

// TLS connection tests
const server = tls.createServer({
  key: fixtures.readKey('agent3-key.pem'),
  cert: fixtures.readKey('agent3-cert.pem')
}, common.mustCall((socket) => {
  socket.end('bye');
  server.close();
})).listen(0, common.mustCall(() => {
  const copts = {
    port: server.address().port,
    checkServerIdentity: common.mustCall()
  };

  // Successful connection
  tls.rootCertificates = [extraCerts[1]];
  const client = tls.connect(copts, common.mustCall(() => {
    client.end('hi');
  }));

  // Unsuccessful connection
  tls.rootCertificates = [extraCerts[0]];
  tls.connect(copts, common.mustNotCall()).on('error', common.mustCall());
}));
