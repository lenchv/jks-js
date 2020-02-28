const JavaKeyStoreParser = require('./keystore/JavaKeyStoreParser');
const KeyEntry = require('./keystore/KeyEntry');
const TrustedKeyEntry = require('./keystore/TrustedKeyEntry');
const EncryptedPrivateKeyInfo = require('./encryption/EncryptedPrivateKeyInfo');
const KeyProtector = require('./encryption/KeyProtector');

const decrypt = (protectedKey, password = '') => {
	const keyInfo = new EncryptedPrivateKeyInfo(protectedKey);
	const protector = new KeyProtector(password);

	return protector.recover(keyInfo);
};

const parseJks = (keystore, password) => {
	const jks = new JavaKeyStoreParser(keystore, password);

	return jks.parse();
};

const toPem = function (keystore, password) {
	const entries = parseJks(keystore, password);

	return entries.reduce((result, entry) => {
		if (entry instanceof TrustedKeyEntry) {
			return Object.assign({}, result, {
				[entry.alias]: {
					cert: entry.cert
				}
			});
		} else if (entry instanceof KeyEntry) {
			return Object.assign({}, result, {
				[entry.alias]: {
					ca: entry.chain.join('\n'),
					key: decrypt(entry.protectedPrivateKey, password)
				}
			});
		}
	}, {});
};

module.exports = {
	toPem,
	parseJks,
	decrypt,
};
