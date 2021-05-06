const JavaKeyStoreParser = require('./keystore/JavaKeyStoreParser');
const PKCS12Parser = require('./keystore/PKCS12Parser');
const KeyEntry = require('./keystore/KeyEntry');
const TrustedKeyEntry = require('./keystore/TrustedKeyEntry');
const EncryptedPrivateKeyInfo = require('./encryption/EncryptedPrivateKeyInfo');
const KeyProtector = require('./encryption/KeyProtector');
const CertificateRegistry = require('./certs/CertificateRegistry');

const serializeCert = (cert) => {
	const registry = new CertificateRegistry();
	const impl = registry.get(cert.certType);

	return impl.generate(cert.value);
};

const decrypt = (protectedKey, password = '') => {
	const keyInfo = new EncryptedPrivateKeyInfo(protectedKey);
	const protector = new KeyProtector(password);

	return protector.recover(keyInfo);
};

const parseJks = (keystore, password) => {
	const jks = new JavaKeyStoreParser(keystore, password);

	return jks.parse();
};

const parsePkcs12 = (keystore, password) => {
	const jks = new PKCS12Parser(keystore, password);

	return jks.parse();
};

const pkcs12ToPem = (keystore, password) => {
	const jks = new PKCS12Parser(keystore, password);
	const p12Bags = jks.parse();

	return jks.toPem(p12Bags);
};

const jksToPem = (keystore, password) => {
	const entries = parseJks(keystore, password);

	return entries.reduce((result, entry) => {
		if (entry instanceof TrustedKeyEntry) {
			return Object.assign({}, result, {
				[entry.alias]: {
					ca: serializeCert(entry.cert)
				}
			});
		} else if (entry instanceof KeyEntry) {
			return Object.assign({}, result, {
				[entry.alias]: {
					cert: entry.chain.map(serializeCert).join('\n'),
					key: decrypt(entry.protectedPrivateKey, password)
				}
			});
		}
	}, {});
};

const toPem = function (keystore, password) {
	if (PKCS12Parser.probe(keystore)) {
		return pkcs12ToPem(keystore, password);
	} else {
		return jksToPem(keystore, password);
	}
};

module.exports = {
	toPem,
	parseJks,
	decrypt,
	parsePkcs12,
};
