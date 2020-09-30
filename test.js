const TycrekCert = require('./certs');
const fs = require('fs');
const moment = require('moment');
const log = require('pino')({
	prettyPrint: true,
	level: 'debug',
	base: null,
	timestamp: () => `,"time": ${moment().format('YYYY-MM-DD hh:mm:ss A')} `,
});

const test = {
	domains: ['*.jmoore.dev', 'jmoore.dev'],
	email: 'josh.moore@jmoore.dev',
	savePath: '/certs'
};

let cert = new TycrekCert(fs.readFileSync('test-token.txt').toString(), test.domains, test.email, test.email, true, log);

async function runTest() {

	cert.callThisForHelp();

	await cert.init();

	await cert.account();

	cert.setSavePath(test.savePath);

	await cert.createCertificate();
}

runTest().catch((err) => console.error(err));
