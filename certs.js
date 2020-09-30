var fs = require('fs');
var path = require('path');
var Keypairs = require('@root/keypairs');
var ACME = require('@root/acme');
var CSR = require('@root/csr');
var PEM = require('@root/pem');
var DO = require('acme-dns-01-digitalocean');

// Base URL to Digital Ocean Domains API. Typically, this will never change.
const DO_BASE_URL = 'https://api.digitalocean.com/v2/domains';

// ACME production and staging URLS. These will most likely not change either.
const DIRECTORY_URL = {
	prod: 'https://acme-v02.api.letsencrypt.org/directory',
	test: 'https://acme-staging-v02.api.letsencrypt.org/directory'
};

// Change this if you have a slow connection or slow DNS servers
const PROPAGATION_DELAY = 5000;

// Used in logging
const LOG_PREFIX = '[ TycrekCert ]';

// Used to create User Agent in constructor()
const pkg = require('./package.json');

/**
 * Custom class for automatically creating HTTPS certificates the way I prefer to do it
 */
class TycrekCert {
	/**
	 * Operations for creating HTTPS certificates
	 * @param {string} token Token for Digital Ocean API
	 * @param {string[]} domains Array containing the domains the certificate applies to
	 * @param {string} maintainerEmail Typically the developer email address
	 * @param {string} subscriberEmail Typically the client email address
	 * @param {boolean} testing Set to true to use the ACME staging server
	 * @param {Object} log (Currently not supported) Tool to use for logging. Must support .info and .warn. Default is built-in console.
	 */
	constructor(token, domains, maintainerEmail, subscriberEmail, testing = false, log = console) {
		this.errors = [];
		this.domains = domains;
		this.maintainerEmail = maintainerEmail;
		this.subscriberEmail = subscriberEmail;
		this.testing = testing;
		//this.log = log; // Currently not supported
		this.log = console;

		// Create Digital Ocean API client
		this.challenge = DO.create({ baseUrl: DO_BASE_URL, token });

		// This is not set by the DO plugin and throws a warning if not set, so we attach it to the client separately
		this.challenge.propagationDelay = PROPAGATION_DELAY;

		// Create ACME client
		this.acme = ACME.create({
			maintainerEmail: this.maintainerEmail,
			packageAgent: 'node-cert' + pkg.name + '/' + pkg.version,
			notify: (ev, msg) => ev === 'error' || ev === 'warning' ? this.errors.push(ev.toUpperCase() + ': ' + msg.message) : this.log.info(LOG_PREFIX, ev + ':', msg.altname || '', msg.status || '')
		});
	}

	async init() {
		// Initialize ACME
		await this.acme.init(DIRECTORY_URL[this.testing ? 'test' : 'prod']);

		// Create account & server private key
		this.accountKey = (await Keypairs.generate({ kty: 'EC', format: 'jwk' })).private;
		this.serverKey = (await Keypairs.generate({ kty: 'RSA', format: 'jwk' })).private;

		this.log.info(LOG_PREFIX, 'ACME client and private keys successfully initialized');
	}

	async account() {
		this.log.info(LOG_PREFIX, 'Registering new ACME account...');

		// Create a new ACME account
		this.account = await this.acme.accounts.create({
			subscriberEmail: this.subscriberEmail,
			accountKey: this.accountKey,
			agreeToTerms: true
		});

		this.log.info(LOG_PREFIX, 'ACME account registered with ID:', this.account.key.kid);
	}

	async createCertificate() {
		this.log.info(LOG_PREFIX, 'Validating domain authorization for:', this.domains.join(', '));

		// Get certificates
		let bytes = await CSR.csr({ jwk: this.serverKey, domains: this.domains, encoding: 'der' });
		let pems = await this.acme.certificates.create({
			account: this.account,
			accountKey: this.accountKey,
			csr: PEM.packBlock({ type: 'CERTIFICATE REQUEST', bytes }),
			domains: this.domains,
			challenges: { 'dns-01': this.challenge }
		});

		// Write privkey
		let data = await Keypairs.export({ jwk: this.serverKey });
		await fs.promises.writeFile(path.join(this.savePath || '.', 'privkey.pem'), data, 'ascii');
		this.log.info(LOG_PREFIX, 'Saved privkey.pem');

		// Write fullchain
		await fs.promises.writeFile(path.join(this.savePath || '.', 'fullchain.pem'), `${pems.cert}\n${pems.chain}\n`, 'ascii');
		this.log.info(LOG_PREFIX, 'Saved fullchain.pem');

		// Print any errors if necessary
		if (this.errors.length) {
			this.log.warn(LOG_PREFIX, 'The following warnings and/or errors were encountered:');
			this.log.warn(LOG_PREFIX, this.errors.join('\n'));
		}
	}

	setSavePath(path) {
		this.savePath = path;
		this.log.info(LOG_PREFIX, 'Set save path to:', path);
	}

	callThisForHelp() {
		this.log.info(
			'\n' + LOG_PREFIX + ' ' + 'Help' + '\n' +
			'    1. Create the object: var foo = new TycrekCert(parameters)' + '\n' +
			'    2. Call init()' + '\n' +
			'    3. Call account()' + '\n' +
			'    4. Call createCertificate()' + '\n' +
			'    ' + '\n' +
			'    If you want to change where fullchain.pem and privkey.pem are saved, call setSavePath() with the ABSOLUTE path before calling createCertificate()'
		);
	}

}

module.exports = TycrekCert;
