class X509Cert {
	generateCertificate(data) {
		const payload = data.toString('base64').match(/.{1,64}/g).join('\n');
		return '-----BEGIN CERTIFICATE-----\n' +
			payload +
			'\n-----END CERTIFICATE-----';
	}
}

module.exports = X509Cert;
