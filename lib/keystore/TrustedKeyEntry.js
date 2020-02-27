
class TrustedKeyEntry {
	constructor({ alias, date, cert }) {
		this.alias = alias;
		this.date = date;
		this.cert = cert;
	}
}

module.exports = TrustedKeyEntry;
