const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const { toPem, parseJks, parsePkcs12 } = require('../../');

const readFile = (name, keyPath) => {
  return fs.readFileSync(path.join(keyPath, 'pem', name)).toString();
};

const readKey = (name, keyPath) => {
  const key = readFile(name + '.key', keyPath);
  const position = key.indexOf('-----BEGIN PRIVATE KEY-----');

  return key.slice(position).replace(/\r\n/g, '\n');
};

const readCert = (name, keyPath) => {
  const key = readFile(name + '.pem', keyPath);
  const position = key.indexOf('-----BEGIN CERTIFICATE-----');

  return key.slice(position).replace(/\r\n/g, '\n');
};

const runTests = (javaVersion, keyPath) => {
  describe('Java ' + javaVersion, function () {
	 this.timeout(10000);
	 describe('Keystore', () => {
		[
		  'RSA_2048_keystore',
		  'DSA_1024_keystore',
		  'EC_256_keystore',
		  'RSA_2048_MD5withRSA_keystore',
		  'RSA_2048_SHA1withRSA_keystore',
		  'RSA_2048_SHA256withRSA_keystore',
		].forEach((name) => {
		  it('should extract certificates from ' + name, () => {
			 const cert = toPem(
				fs.readFileSync(path.join(keyPath, 'keystore', name + '.jks')),
				'password'
			 );

			 expect(cert).has.key('jks-js');
			 expect(cert['jks-js'].key).to.be.eq(readKey(name, keyPath));
			 expect(cert['jks-js'].cert).to.be.eq(readCert(name, keyPath));
		  });
		});
	 });

	 describe('Truststore', () => {
		it('cert should be extracted', () => {
		  const cert = toPem(
			 fs.readFileSync(
				path.join(keyPath, 'keystore', 'RSA_2048_truststore.jks')
			 ),
			 'password'
		  );

		  expect(cert).has.key('jks-js');
		  expect(cert['jks-js'].ca).to.be.eq(
			 readCert('RSA_2048_keystore', keyPath)
		  );
		});
	 });

	 describe('Parsing', () => {
		[
		  'RSA_2048_keystore',
		  'DSA_1024_keystore',
		  'EC_256_keystore',
		  'RSA_2048_MD5withRSA_keystore',
		  'RSA_2048_SHA1withRSA_keystore',
		  'RSA_2048_SHA256withRSA_keystore',
		].forEach((name) => {
		  it('should work', () => {
			 const KEY_ALIAS = 'jks-js';
			 if (javaVersion === 8) {
				parseJks(
				  fs.readFileSync(path.join(keyPath, 'keystore', name + '.jks')),
				  'password'
				);
			 } else if (javaVersion === 11) {
				parsePkcs12(
				  fs.readFileSync(path.join(keyPath, 'keystore', name + '.jks')),
				  'password'
				);
			 } else {
				throw new Error(
				  `Please write tests for javaVersion: ${javaVersion}`
				);
			 }
		  });
		});
	 });
  });
};

runTests(8, __dirname);
runTests(11, path.join(__dirname, 'java11'));
