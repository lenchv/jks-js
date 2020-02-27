const X509Cert = require('./X509Cert');

class CertificateFactory {
	alghorithms = {
		'X509': X509Cert,
		'X.509': X509Cert,
	};

	set(alghorithm, implementation) {
		this.alghorithms[alghorithm] = implementation;
	}

	getInstance(alghorithm) {
		if (!this.alghorithms[alghorithm]) {
			throw new Error('The certificate type ' + alghorithm + ' is not supported');
		}

		return new this.alghorithms[alghorithm]();
	}
}

module.exports = CertificateFactory;
