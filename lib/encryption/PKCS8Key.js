const crypto = require('crypto');
const ObjectIdentifier = require('./ObjectIdentifier');
const DerValue = require('./DerValue');

class PKCS8Key {
	static supportedTypes = {
		'rsa': '1.2.840.113549.1.1.1',
		'rsa-pss': '1.2.840.113549.1.1.10',
		'dsa': '1.2.840.10040.4.1',
		'ec': '1.2.840.10045.2.1',
		'x25519': '1.3.101.110',
		'x448': '1.3.101.111',
		'ed25519': '1.3.101.112',
		'ed448': '1.3.101.113',
		'dh': '1.2.840.113549.1.3.1',
	};
    /* The version for this key */
	static version = 0;

	/*
	 * Construct PKCS#8 subject public key from a DER value.
	 *
	 * @param plainKey the DER-encoded SubjectPublicKeyInfo value
	 */
	static parseKey(plainKey) {
		if (plainKey.tag !== DerValue.tag_Sequence) {
			throw new Error('corrupt private key');
		}

		const parsedVersion = plainKey.getBigInteger();

		if (parsedVersion !== PKCS8Key.version) {
			throw new Error('version mismatch: (supported ' + this.version + ', parsed: ' + parsedVersion);
		}

		const seq0 = plainKey.getDerValue();
		const seq1 = plainKey.getDerValue();
		const alghorithm = new ObjectIdentifier(
			seq0.data
		);
		const octetString = seq1.getOctetString();

		const privateKey = crypto.createPrivateKey({
			key: octetString,
			format: 'der',
			type: 'pkcs1',
		});

		if (PKCS8Key.supportedTypes[privateKey.asymmetricKeyType] !== alghorithm.toString()) {
			throw new Error('Encryption algorithm is not supported ' + alghorithm.toString());
		}

		return privateKey.export({
			format: 'pem',
			type: 'pkcs8'
		});
	}
}

module.exports = PKCS8Key;
