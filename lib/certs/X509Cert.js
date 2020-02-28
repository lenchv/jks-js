class X509Cert {
	generate(data) {
		const payload = data.toString('base64').match(/.{1,64}/g).join('\n');
		return '-----BEGIN CERTIFICATE-----\n' +
			payload +
			'\n-----END CERTIFICATE-----\n';
	}
}

module.exports = X509Cert;
