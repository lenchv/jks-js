class KeyEntry {
	constructor({
		alias,
		date,
		chain,
		protectedPrivateKey
	}) {
		this.alias = alias;
		this.date = date;
		this.chain = chain;
		this.protectedPrivateKey = protectedPrivateKey;
	}
}

module.exports = KeyEntry;
