
class TrustedKeyEntry {
	constructor({ alias, date, cert }) {
		this.certType = 'X.509';
		this.alias = alias;
		this.date = date;
		this.cert = cert;
	}
}

module.exports = TrustedKeyEntry;
