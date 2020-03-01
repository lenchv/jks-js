const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const { toPem } = require('../../');

const readFile = (name) => {
	return fs.readFileSync(path.join(__dirname, 'pem', name)).toString();
};

const readKey = (name) => {
	const key = readFile(name + '.key');
	const position = key.indexOf('-----BEGIN PRIVATE KEY-----');

	return key.slice(position).replace(/\r\n/g, '\n');
};

const readCert = (name) => {
	const key = readFile(name + '.pem');
	const position = key.indexOf('-----BEGIN CERTIFICATE-----');

	return key.slice(position).replace(/\r\n/g, '\n');
};

describe('Keystore', () => {
	[
		'RSA_2048_keystore',
		'DSA_1024_keystore',
		'EC_256_keystore',
		'RSA_2048_MD5withRSA_keystore',
		'RSA_2048_SHA1withRSA_keystore',
		'RSA_2048_SHA256withRSA_keystore',
	].forEach(name => {
		it('should extract certificates from ' + name, () => {
			const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', name + '.jks')), 'password');
	
			expect(cert).has.key('jks-js');
			expect(cert['jks-js'].key).to.be.eq(readKey(name));
			expect(cert['jks-js'].cert).to.be.eq(readCert(name));
		});
	});
});

describe('Truststore', () => {
	it('cert should be extracted', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'RSA_2048_truststore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].ca).to.be.eq(readCert('RSA_2048_keystore'));
	});
});
