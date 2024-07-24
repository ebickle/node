'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('node:assert');
const tls = require('node:tls');
const { fork } = require('node:child_process');
const fixtures = require('../common/fixtures');

const tests = [
  'additional-ca',
  'crl',
  'pfx',
];

const clientTest = process.argv[2];
if (clientTest) {
  const clientOptions = {
    port: process.argv[3],
    checkServerIdentity: common.mustCall()
  };

  switch (clientTest) {
    case 'additional-ca':
      clientOptions.secureContext = tls.createSecureContext();
      clientOptions.secureContext.context.addCACert(
        fixtures.readKey('ca1-cert.pem')
      );
      break;
    case 'crl':
      clientOptions.crl = fixtures.readKey('ca2-crl.pem');
      break;
    case 'pfx':
      clientOptions.pfx = fixtures.readKey('agent1.pfx');
      clientOptions.passphrase = 'sample';
      break;
  }

  const client = tls.connect(clientOptions, common.mustCall(() => {
    client.end('hi');
  }));
} else {
  for (const test of tests) {
    const serverOptions = {
      key: fixtures.readKey('agent3-key.pem'),
      cert: fixtures.readKey('agent3-cert.pem')
    };

    const server = tls.createServer(serverOptions, common.mustCall((socket) => {
      socket.end('bye');
      server.close();
    }));

    server.listen(0, common.mustCall(() => {
      const env = {
        ...process.env,
        NODE_EXTRA_CA_CERTS: fixtures.path('keys', 'ca2-cert.pem')
      };

      const args = [
        test,
        server.address().port,
      ];

      fork(__filename, args, { env }).on('exit', common.mustCall((status) => {
        assert.strictEqual(status, 0);
      }));
    }));
  }
}
