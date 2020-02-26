const fs = require('fs');
const crypto = require('crypto');

const MAGIC = 0xfeedfeed;
const VERSION_1 = 0x01;
const VERSION_2 = 0x02;
const PRIVATE_KEY_TAG = 1;
const TRUSTED_CERT_TAG = 2;

const getPrivateKeyEntry = (dataInputStream) => {
	const protectedPrivateKey = dataInputStream.read(
		dataInputStream.readInt()
	);

	return protectedPrivateKey;
};

const readCert = (dataInputStream, xVersion, certificateFactory) => {
	let cf;

	if (xVersion === VERSION_2) {
		const certType = dataInputStream.readUTF();

		cf = certificateFactory.getInstance(certType);
	} else {
		cf = certificateFactory.getInstance('X.509');
	}

	const encoded = dataInputStream.read(dataInputStream.readInt());
	
	return cf.generateCertificate(encoded);
};

const readCertificateChain = (dataInputStream, xVersion, certificateFactory) => {
	const numOfCerts = dataInputStream.readInt();
	const certs = [];

	if (numOfCerts < 0) {
		return certs;
	}

	for (let i = 0; i < numOfCerts; i++) {
		certs.push(readCert(dataInputStream, xVersion, certificateFactory));
	}

	return certs;
};

/*
 * KEYSTORE FORMAT:
 *
 * Magic number (big-endian integer),
 * Version of this file format (big-endian integer),
 *
 * Count (big-endian integer),
 * followed by "count" instances of either:
 *
 *     {
 *      tag=1 (big-endian integer),
 *      alias (UTF string)
 *      timestamp
 *      encrypted private-key info according to PKCS #8
 *          (integer length followed by encoding)
 *      cert chain (integer count, then certs; for each cert,
 *          integer length followed by encoding)
 *     }
 *
 * or:
 *
 *     {
 *      tag=2 (big-endian integer)
 *      alias (UTF string)
 *      timestamp
 *      cert (integer length followed by encoding)
 *     }
 *
 * ended by a keyed SHA1 hash (bytes only) of
 *     { password + whitener + preceding body }
 */
const parseJavaKeyStore = (jks, password) => {
	let dataInputStream;
	let messageDigest;

	if (password) {
		messageDigest = new PasswordDigest(password); 
		dataInputStream = new DigestInputStream(jks, messageDigest);
	} else {
		dataInputStream = new InputStream(jks);
	}

	const xMagic = dataInputStream.readInt();
	const xVersion = dataInputStream.readInt();
	const certificateFactory = new CertificateFactory();

	if (xMagic !== MAGIC || xVersion !== VERSION_1 && xVersion !== VERSION_2) {
		throw new Error('Invalid keystore format');
	}

	const count = dataInputStream.readInt();
	const certs = {};

	for (let i = 0; i < count; i++) {
		const tag = dataInputStream.readInt();
		const alias = dataInputStream.readUTF();
		const date = new Date(+dataInputStream.readLong().toString());

		if (tag === PRIVATE_KEY_TAG) {
			const protectedPrivateKey = getPrivateKeyEntry(dataInputStream);
			const chain = readCertificateChain(dataInputStream, xVersion, certificateFactory);
		
			certs[alias] = {
				date,
				protectedPrivateKey,
				chain
			};
		} else if (tag === TRUSTED_CERT_TAG) {
			const cert = readCert(dataInputStream, xVersion, certificateFactory);

			certs[alias] = {
				alias,
				date,
				cert
			};
		} else {
			throw new Error('Unrecognized keystore entry');
		}
	}

	if (password) {
		const computed = messageDigest.digest();
		const acctual = dataInputStream.buffer.slice(
			dataInputStream.offset,
			dataInputStream.offset + computed.length,
		);
		const isChecksumCorrect = computed.every((byte, i) => acctual[i] === byte);

		if (!isChecksumCorrect) {
			throw new Error('Password verification failed');
		}
	}

	return certs;
};

class InputStream {
	constructor(buffer) {
		this.buffer = Buffer.from(buffer);
		this.offset = 0;
	}

	readInt() {
		return this.buffer.readUInt32BE(
			this.shift(4)
		);
	}

	readUTF() {
		const length = this.buffer.readUInt16BE(this.shift(2));

		return this.read(length).toString();
	}

	read(length) {
		return this.buffer.slice(
			this.offset,
			this.shift(length) + length
		);
	}

	readLong() {
		return this.buffer.readBigUInt64BE(this.shift(8));
	}

	readByte() {
		return this.buffer.readUInt8(this.shift(1));
	}

	shift(bytes) {
		const offset = this.offset;
		this.offset += bytes;
		return offset;
	}
}

class DigestInputStream extends InputStream {
	constructor(buffer, digest) {
		super(buffer);
		this.digest = digest;
	}

	readInt() {
		this.updateDigest(4);

		return super.readInt();
	}

	readUTF() {
		this.updateDigest(2);

		return super.readUTF();
	}

	read(length) {
		this.updateDigest(length);

		return super.read(length);
	}

	readLong() {
		this.updateDigest(8);

		return super.readLong();
	}

	readByte() {
		this.updateDigest(1);

		return super.readByte();
	}

	updateDigest(length) {
		this.digest.update(this.buffer.slice(
			this.offset,
			this.offset + length
		));
	}
}

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

class OutputStream {
	constructor(buffer) {
		this.buffer = Buffer.from(buffer);
		this.offset = 0;
	}

	write(data) {
		if (typeof data === 'number') {
			this.buffer.writeUInt8(data, this.offset);
			this.offset++;
		} else if (Buffer.isBuffer(data)) {
			this.buffer = Buffer.concat([ this.buffer.slice(0, this.offset), data ]);
			this.offset += data.length;
		}
	}
}

class X509Cert {
	generateCertificate(data) {
		const cert = '-----BEGIN CERTIFICATE-----\n' + data.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
		
		return cert;
	}
}

class CertificateFactory {
	alghorithms = {
		'X509': X509Cert,
		'X.509': X509Cert,
	};

	set(alghorithm, implementation) {
		this.alghorithms[alghorithm] = implementation;
	}

	getInstance(alghorithm) {
		return new this.alghorithms[alghorithm]();
	}
}

const readOneBlock = (is) => {
	const tagSequence = 0x30;
	const c = is.readByte(1);

	if (c === -1) {
		return null;
	}

	if (c === tagSequence) {
		const bout = new OutputStream(Buffer.alloc(2048));
		bout.write(c);
		readBERInternal(is, bout, c);
	
		return bout;
	}

	// TODO
};

const readBERInternal = (is, bout, tag) => {
	if (tag === -1) {
		tag = is.readByte();
		if (tag === -1) {
			throw new Error('BER/DER tag info absent');
		}
		if ((tag & 0x1f) === 0x1f) {
			throw new Error('Multi octets tag not supported');
		}
		bout.write(tag);
	}

	const n = is.readByte();
	if (n === -1) {
		throw new Error('BER/DER length info absent');
	}
	bout.write(n);

	let length;

	if (n === 0x80) {        // Indefinite-length encoding
		if ((tag & 0x20) !== 0x20) {
			throw new Error('Non constructed encoding must have definite length');
		}
		while (true) {
			let subTag = readBERInternal(is, bout, -1);

			if (subTag === 0) {   // EOC, end of indefinite-length section
				break;
			}
		}
	} else {
		if (n < 0x80) {
			length = n;
		} else if (n === 0x81) {
			length = is.readByte();

			if (length == -1) {
				throw new Error('Incomplete BER/DER length info');
			}

			bout.write(length);
		} else if (n === 0x82) {
			const highByte = is.readByte();
			const lowByte = is.readByte();

			if (lowByte === -1) {
				throw new Error('Incomplete BER/DER length info');
			}

			bout.write(highByte);
			bout.write(lowByte);
			length = (highByte << 8) | lowByte;
		} else if (n === 0x83) {
			let highByte = is.readByte();
			let midByte = is.readByte();
			let lowByte = is.readByte();
			if (lowByte == -1) {
				throw new Error('Incomplete BER/DER length info');
			}
			bout.write(highByte);
			bout.write(midByte);
			bout.write(lowByte);
			length = (highByte << 16) | (midByte << 8) | lowByte;
		} else if (n === 0x84) {
			let highByte = is.readByte();
			let nextByte = is.readByte();
			let midByte = is.readByte();
			let lowByte = is.readByte();
			if (lowByte == -1) {
				throw new Error('Incomplete BER/DER length info');
			}
			if (highByte > 127) {
				throw new Error('Invalid BER/DER data (a little huge?)');
			}
			bout.write(highByte);
			bout.write(nextByte);
			bout.write(midByte);
			bout.write(lowByte);
			length = (highByte << 24 ) | (nextByte << 16) |
					(midByte << 8) | lowByte;
		} else { // ignore longer length forms
			throw new Error('Invalid BER/DER data (too huge?)');
		}

		if (readFully(is, bout, length) !== length) {
			throw new Error('Incomplete BER/DER data');
		}
	}

	return tag;
};

const readFully = (is, bout, length) => {
	let read = 0;

	while (length > 0) {
		const buffer = is.read(length < 2048 ? length : 2048);

		if (buffer.length <= 0) {
			break;
		}
		bout.write(buffer);
		read += buffer.length;
		length -= buffer.length;
	}

	return read;
};

const parsedKeystore = parseJavaKeyStore(fs.readFileSync(__dirname + '/assets/keystore.jks'), '1a2b3c');

const privateKey = crypto.createSecretKey(parsedKeystore['volodymyr.local'].protectedPrivateKey);
const decrypted = privateKey.export({
	type: 'pkcs8',
	format: 'der',
	passphrase: '1a2b3c'
});

console.log(parsedKeystore['volodymyr.local'].protectedPrivateKey.toString());
console.log(decrypted.toString());

const certificateFactory = new CertificateFactory();
console.log(certificateFactory.getInstance('X.509').generateCertificate(decrypted));

