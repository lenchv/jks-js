const InputStream = require('../stream/InputStream');
const ObjectIdentifier = require('./ObjectIdentifier');
const DerValue = require('./DerValue');

/**
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 * 		encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 * 		encryptedData        EncryptedData
 * }
 */
class EncryptedPrivateKeyInfo {
	constructor(encoded) {
		const derValue = new DerValue(new InputStream(encoded));
		const seq0 = new DerValue(derValue.data);
		const seq1 = new DerValue(derValue.data);
		this.alghorithmId = this.createAlghorithmId(seq0);
		this.octetString = seq1.getOctetString();
	}

	createAlghorithmId(derValue) {
		const oid = new ObjectIdentifier(derValue.data);

		return oid.toString();
	}

	getAlgorithm() {
		return this.alghorithmId;
	}

	getEncryptedData() {
		return this.octetString;
	}
}

module.exports = EncryptedPrivateKeyInfo;
