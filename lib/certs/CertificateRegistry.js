const X509Cert = require('./X509Cert');

class CertificateRegistry {
	constructor() {
		this.alghorithms = {
			'X509': X509Cert,
			'X.509': X509Cert,
		};
	}

	get(alghorithm) {
		if (!this.alghorithms[alghorithm]) {
			throw new Error('The certificate type ' + alghorithm + ' is not supported');
		}

		return new this.alghorithms[alghorithm]();
	}
}

module.exports = CertificateRegistry;
