const X509Cert = require('./X509Cert');

class CertificateRegistry {
	constructor() {
		this.algorithms = {
			'X509': X509Cert,
			'X.509': X509Cert,
		};
	}

	get(algorithm) {
		if (!this.algorithms[algorithm]) {
			throw new Error('The certificate type ' + algorithm + ' is not supported');
		}

		return new this.algorithms[algorithm]();
	}
}

module.exports = CertificateRegistry;
