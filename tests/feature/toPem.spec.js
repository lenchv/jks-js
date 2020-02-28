const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const { toPem } = require('../../');

describe('Keystore', () => {
	it('should convert rsa 2048 to PEM', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'rsa_2048_keystore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].key).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'rsa_2048_keystore.key')).toString());
		expect(cert['jks-js'].ca).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'rsa_2048_keystore.pem')).toString());
	});

	it('should convert dsa 1024 to PEM', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'dsa_1024_keystore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].key).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'dsa_1024_keystore.key')).toString());
		expect(cert['jks-js'].ca).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'dsa_1024_keystore.pem')).toString());
	});

	it('should convert dsa 256 to EC', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'ec_256_keystore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].key).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'ec_256_keystore.key')).toString());
		expect(cert['jks-js'].ca).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'ec_256_keystore.pem')).toString());
	});

	it('should convert rsa 2048 to PEM MD5', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'RSA_2048_MD5withRSA_keystore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].key).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'RSA_2048_MD5withRSA_keystore.key')).toString());
		expect(cert['jks-js'].ca).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'RSA_2048_MD5withRSA_keystore.pem')).toString());
	});
	
	it('should convert rsa 2048 to PEM SHA256', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'RSA_2048_SHA256withRSA_keystore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].key).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'RSA_2048_SHA256withRSA_keystore.key')).toString());
		expect(cert['jks-js'].ca).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'RSA_2048_SHA256withRSA_keystore.pem')).toString());
	});

	it('should convert rsa 2048 to PEM SHA1', () => {
		const cert = toPem(fs.readFileSync(path.join(__dirname, 'keystore', 'RSA_2048_SHA1withRSA_keystore.jks')), 'password');

		expect(cert).has.key('jks-js');
		expect(cert['jks-js'].key).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'RSA_2048_SHA1withRSA_keystore.key')).toString());
		expect(cert['jks-js'].ca).to.be.eq(fs.readFileSync(path.join(__dirname, 'pem', 'RSA_2048_SHA1withRSA_keystore.pem')).toString());
	});
});
