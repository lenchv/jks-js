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

	readShort() {
		return this.read(2).readUInt16BE();
	}

	shift(bytes) {
		const offset = this.offset;
		this.offset += bytes;
		return offset;
	}

	available() {
		return this.buffer.length - this.offset;
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

class DerValue {
    /** Tag value indicating an ASN.1 "OBJECT IDENTIFIER" value. */
	static tag_ObjectId = 0x06;
	
	/**
	 * Tag value indicating an ASN.1
	 * "SEQUENCE" (zero to N elements, order is significant).
	 */
	static tag_Sequence = 0x30;

    /** Tag value indicating an ASN.1 "OCTET STRING" value. */
    static tag_OctetString = 0x04;
	
    /** Tag value indicating an ASN.1 "INTEGER" value. */
	static tag_Integer = 0x02;

	tag = null
	length = 0
	data = null
	buffer = null

	constructor(inputStream) {
		this.buffer = inputStream.buffer.slice(inputStream.offset);
		this.init(inputStream);
	}

	init(inputStream) {
		this.tag = inputStream.readByte();
		const lenByte = inputStream.buffer.readUInt8(inputStream.offset);
		this.length = DerValue.getLength(inputStream);

		if (this.length === -1) {
			const readLen = inputStream.available();
			let offset = 2;
			const indefData = new OutputStream(Buffer.alloc(readLen + offset));
			indefData.write(this.tag);
			indefData.write(lenByte);
			indefData.write(inputStream.read(readLen));

			throw new Error('Length is not defined. The DerIndefLenConverter.convert() has not been implmeneted yet');
		}

		this.data = new InputStream(inputStream.read(this.length));
	}

	/** Returns true iff the CONSTRUCTED bit is set in the type tag. */
    isConstructed(constructedTag) {
		const constructed = ((this.tag & 0x020) == 0x020);

		if (!constructed) {
			return false;
		}

		if (constructedTag) {
			return ((tag & 0x01f) == constructedTag);
        } else {
			return true;
		}
	}

	static getLength(inputStream) {
		let len = inputStream.readByte();

		if ((len & 0x080) === 0x00) {
			return len;
		}

		let tmp = len & 0x07f;

		/*
		 * NOTE:  tmp == 0 indicates indefinite length encoded data.
		 * tmp > 4 indicates more than 4Gb of data.
		 */
		if (tmp === 0) {
			return -1;
		}

		if (tmp < 0) {
			throw new Error('Incorrect DER encodding');
		} else if (tmp > 4) {
			throw new Error('DER length too big');
		}
		
		let value;

		for (value = 0; tmp > 0; tmp--) {
			value <<= 8;
			value += 0x0ff & inputStream.readByte();
		}

		if (value < 0) {
			throw new Error('Invalid length byte');
		}

		return value;
	}

	getBigInteger() {
		const inputStream = this.data;

		if (inputStream.readByte() != DerValue.tag_Integer) {
            throw new Error("DER input, Integer tag error");
		}
		const length = DerValue.getLength(inputStream);

		if (length <= 1) {
			return inputStream.readByte();
		} else if (length === 2) {
			return inputStream.readShort();
		} else if (length <= 4) {
			return inputStream.readInt();
		} else {
			return inputStream.readLong();
		}
	}

	getOctetString() {
		if (this.tag !== DerValue.tag_OctetString && !this.isConstructed(DerValue.tag_OctetString)) {
			throw new Error('DerValue.getOctetString, not an Octet String: ' + derValue.tag);
		}

		const stream = new InputStream(this.buffer);

		let bytes = Buffer.from([]);

		while (stream.available()) {
			const tag = stream.readByte();

			if (tag !== DerValue.tag_OctetString) {
				throw new Error('DER input not an octet string: ' + tag);
			}

			const length = DerValue.getLength(stream);
			const data = stream.read(length);

			bytes = Buffer.concat([ bytes, data ]);
		}

		return bytes;
	}

	getDerValue() {
		return new DerValue(this.data);
	}
}

class ObjectIdentifier {
	constructor(inputStream) {
		const typeId = inputStream.readByte();

		if (typeId !== DerValue.tag_ObjectId) {
			throw new Error('data isn\'t an object ID ( tag = ' + typeId + ')');
		}

		const length = DerValue.getLength(inputStream);

		this.encoding = inputStream.read(length);
	}

	toString() {
		const length = this.encoding.length;
		let sb = '';
		let fromPos = 0;

		for (let i = 0; i < length; i++) {
			if ((this.encoding[i] & 0x80) === 0) {
				if (fromPos !== 0) {
					sb += '.';
				}
				let retVal = 0;
				for (let j = fromPos; j <= i; j++) {
					retVal <<= 7;
					const tmp = this.encoding[j];
					retVal |= (tmp & 0x07f);
				}
				if (fromPos === 0) {
					if (retVal < 80) {
						sb += Math.floor(retVal / 40);
						sb += '.';
						sb += retVal % 40;
					} else {
						sb += '2.';
						sb += retVal - 80;
					}
				} else {
					sb += retVal;
				}
				fromPos = i + 1;
			}
		}
		return sb;
	}
}

class EncryptedPrivateKeyInfo {
	constructor(encoded) {
		const derValue = new DerValue(new InputStream(encoded));
		const seq0 = new DerValue(derValue.data);
		const seq1 = new DerValue(derValue.data);
		this.alghorithmId = this.calculateAlghoritmId(seq0);
		this.octetString = seq1.getOctetString();
	}

	calculateAlghoritmId(derValue) {
		const oid = new ObjectIdentifier(derValue.data);

		return oid.toString();
	}

	getAlgorithm() {
		return this.alghorithmId;
	}

	getEncryptedData() {
		return this.octetString;
	}
}

class PKCS8Key {
	static supportedTypes = {
		'rsa': '1.2.840.113549.1.1.1',
		'rsa-pss': '1.2.840.113549.1.1.10',
		'dsa': '1.2.840.10040.4.1',
		'ec': '1.2.840.10045.2.1',
		'x25519': '1.3.101.110',
		'x448': '1.3.101.111',
		'ed25519': '1.3.101.112',
		'ed448': '1.3.101.113',
		'dh': '1.2.840.113549.1.3.1',
	};
    /* The version for this key */
	static version = 0;

	/*
	 * Construct PKCS#8 subject public key from a DER value.
	 *
	 * <P>This mechanism gurantees that keys (and algorithms) may be
	 * freely manipulated and transferred, without risk of losing
	 * information.  Also, when a key (or algorithm) needs some special
	 * handling, that specific need can be accomodated.
	 *
	 * @param plainKey the DER-encoded SubjectPublicKeyInfo value
	 */
	static parseKey(plainKey) {
		if (plainKey.tag !== DerValue.tag_Sequence) {
			throw new Error('corrupt private key');
		}

		const parsedVersion = plainKey.getBigInteger();

		if (parsedVersion !== PKCS8Key.version) {
			throw new Error('version mismatch: (supported ' + this.version + ', parsed: ' + parsedVersion);
		}

		const seq0 = plainKey.getDerValue();
		const seq1 = plainKey.getDerValue();
		const alghorithm = new ObjectIdentifier(
			seq0.data
		);
		const octetString = seq1.getOctetString();

		const privateKey = crypto.createPrivateKey({
			key: octetString,
			format: 'der',
			type: 'pkcs1',
		});

		if (PKCS8Key.supportedTypes[privateKey.asymmetricKeyType] !== alghorithm.toString()) {
			throw new Error('Encryption algorithm is not supported ' + alghorithm.toString());
		}

		return privateKey.export({
			format: 'pem',
			type: 'pkcs8'
		});
	}
}

class KeyProtector {
	static SALT_LEN = 20; // the salt length
    static DIGEST_ALG = "sha1";
    static DIGEST_LEN = 20;

    // defined by JavaSoft
    static KEY_PROTECTOR_OID = "1.3.6.1.4.1.42.2.17.1.1";

    // The password used for protecting/recovering keys passed through this
    // key protector.
    passwdBytes;
	messageDigest;
	
	constructor(password) {
		this.messageDigest = crypto.createHash(KeyProtector.DIGEST_ALG);
		this.passwdBytes = Buffer.alloc(password.length * 2);

		for (let i = 0, j = 0; i < password.length; i++) {
			this.passwdBytes[j++] = password[i].charCodeAt() >> 8;
			this.passwdBytes[j++] = password[i].charCodeAt();
		}
	}

	resetDigest() {
		this.messageDigest = crypto.createHash(KeyProtector.DIGEST_ALG);
	}

    /*
     * Recovers the plaintext version of the given key (in protected format),
     * using the password provided at construction time.
     */
	recover(encryptedPrivateKeyInfo) {
        let digest;
        let numRounds;
		let encrKeyLen; // the length of the encrpyted key
		
		const algId = encryptedPrivateKeyInfo.getAlgorithm();
		if (algId !== KeyProtector.KEY_PROTECTOR_OID) {
			throw new Error("Unsupported key protection alghorithm");
		}
		let protectedKey = encryptedPrivateKeyInfo.getEncryptedData();
		const salt = protectedKey.slice(0, KeyProtector.SALT_LEN);
		encrKeyLen = protectedKey.length - KeyProtector.SALT_LEN - KeyProtector.DIGEST_LEN;
		numRounds = Math.floor(encrKeyLen / KeyProtector.DIGEST_LEN);

		if ((encrKeyLen % KeyProtector.DIGEST_LEN) !== 0) {
			numRounds++;
		}

		// Get the encrypted key portion and store it in "encrKey"
        const encrKey = protectedKey.slice(
			KeyProtector.SALT_LEN,
			encrKeyLen + KeyProtector.SALT_LEN
		);

		let xorKey = Buffer.alloc(encrKey.length);

		// Compute the digests, and store them in "xorKey"
		for (
			let i = 0, xorOffset = 0, digest = salt;
			i < numRounds;
			i++, xorOffset += KeyProtector.DIGEST_LEN
		) {
			this.messageDigest.update(this.passwdBytes);
			this.messageDigest.update(digest);
			digest = this.messageDigest.digest();
			this.resetDigest();
			
			// Copy the digest into "xorKey"
			if (i < numRounds - 1) {
				xorKey = Buffer.concat([
					xorKey.slice(0, xorOffset),
					digest
				]);
			} else {
				xorKey = Buffer.concat([
					xorKey.slice(0, xorOffset),
					digest.slice(0, encrKey.length - xorOffset)
				]);
			}
	   }

	   // XOR "encrKey" with "xorKey", and store the result in "plainKey"
	   const plainKey = Buffer.alloc(encrKey.length);
	   for (let i = 0; i < plainKey.length; i++) {
		   plainKey[i] = encrKey[i] ^ xorKey[i];
	   }

	   /*
		* Check the integrity of the recovered key by concatenating it with
		* the password, digesting the concatenation, and comparing the
		* result of the digest operation with the digest provided at the end
		* of <code>protectedKey</code>. If the two digest values are
		* different, throw an exception.
		*/
		this.messageDigest.update(this.passwdBytes);
        this.messageDigest.update(plainKey);
        digest = this.messageDigest.digest();
		this.resetDigest();
		
		for (let i = 0; i < digest.length; i++) {
            if (digest[i] != protectedKey[KeyProtector.SALT_LEN + encrKeyLen + i]) {
                throw new Error("Cannot recover key");
            }
		}
		
		// The parseKey() method of PKCS8Key parses the key
        // algorithm and instantiates the appropriate key factory,
		// which in turn parses the key material.
		return PKCS8Key.parseKey(
			new DerValue(
				new InputStream(plainKey)
			)
		);
	}
}

const parsedKeystore = parseJavaKeyStore(fs.readFileSync(__dirname + '/assets/keystore.jks'), '1a2b3c');

const privateKey = parsedKeystore['volodymyr.local'].protectedPrivateKey;
const privateKeyInfo = new EncryptedPrivateKeyInfo(privateKey);
const keyProtector = new KeyProtector('1a2b3c');
