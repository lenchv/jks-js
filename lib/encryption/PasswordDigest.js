const crypto = require('crypto');

class PasswordDigest {
	constructor(password) {
		this.hash = this.getPreKeyedHash(password);
		this.password = password;
	}

	update(buffer) {
		this.hash.update(buffer);
	}

	digest() {
		return this.hash.digest();
	}

	getPreKeyedHash(password) {
		const hash = crypto.createHash('sha1');
		const passwdBytes = Buffer.alloc(password.length * 2);
		for (let i = 0, j = 0; i < password.length; i++) {
			passwdBytes[j++] = password[i].charCodeAt() >> 8;
			passwdBytes[j++] = password[i].charCodeAt();
		}
		hash.update(passwdBytes);
		hash.update(Buffer.from('Mighty Aphrodite'));

		return hash;
	}
}

module.exports = PasswordDigest;
