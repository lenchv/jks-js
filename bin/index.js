#!/usr/bin/env node
const args = require('args');
const jks = require('..');
const fs = require('fs');

args
  .option('keystore', 'Keystore or truststore file path [required]')
  .option('alias', 'Alias name [required]')
  .option('destcert', 'Path where to store a certificate [required]')
  .option('password', 'Keystore password [optional]', '')
  .option('destkey', 'Path where to store a private key [optional]')

const flags = args.parse(process.argv);

try {
	if (!flags['keystore']) {
		args.showHelp();
		throw new Error('keystore is required');
	}

	if (!flags['alias']) {
		args.showHelp();
		throw new Error('alias is required');
	}

	if (!flags['destcert']) {
		args.showHelp();
		throw new Error('destcert is required');
	}

	const certs = jks.toPem(fs.readFileSync(flags.keystore), flags.password);

	if (!certs[flags.alias]) {
		throw new Error('Keystore doesn\'t contain an alias');
	}

	if (certs[flags.alias].cert) {
		fs.writeFileSync(flags.destcert, certs[flags.alias].cert);
	}
	
	if (certs[flags.alias].ca) {
		fs.writeFileSync(flags.destcert, certs[flags.alias].ca);
	}

	if (certs[flags.alias].key) {
		fs.writeFileSync(flags.destkey, certs[flags.alias].key);
	}

	process.exit(0);
} catch (error) {
	console.error(error);
	process.exit(1);
}

