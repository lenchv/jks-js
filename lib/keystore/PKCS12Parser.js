const InputStream = require('../stream/InputStream');
const forge = require('node-forge');

/*
* PKCS12 permitted first 24 bytes:
*
* 30 82 -- -- 02 01 03 30 82 -- -- 06 09 2A 86 48 86 F7 0D 01 07 01 A0 8-
* 30 -- 02 01 03 30 -- 06 09 2A 86 48 86 F7 0D 01 07 01 A0 -- 04 -- -- --
* 30 81 -- 02 01 03 30 81 -- 06 09 2A 86 48 86 F7 0D 01 07 01 A0 81 -- 04
* 30 82 -- -- 02 01 03 30 81 -- 06 09 2A 86 48 86 F7 0D 01 07 01 A0 81 --
* 30 83 -- -- -- 02 01 03 30 82 -- -- 06 09 2A 86 48 86 F7 0D 01 07 01 A0
* 30 83 -- -- -- 02 01 03 30 83 -- -- -- 06 09 2A 86 48 86 F7 0D 01 07 01
* 30 84 -- -- -- -- 02 01 03 30 83 -- -- -- 06 09 2A 86 48 86 F7 0D 01 07
* 30 84 -- -- -- -- 02 01 03 30 84 -- -- -- -- 06 09 2A 86 48 86 F7 0D 01
*/
const PKCS12_HEADER_PATTERNS = [
	[ 0x30820000, 0x02010330, 0x82000006, 0x092A8648, 0x86F70D01, 0x0701A080 ],
	[ 0x30000201, 0x03300006, 0x092A8648, 0x86F70D01, 0x0701A000, 0x04000000 ],
	[ 0x30810002, 0x01033081, 0x0006092A, 0x864886F7, 0x0D010701, 0xA0810004 ],
	[ 0x30820000, 0x02010330, 0x81000609, 0x2A864886, 0xF70D0107, 0x01A08100 ],
	[ 0x30830000, 0x00020103, 0x30820000, 0x06092A86, 0x4886F70D, 0x010701A0 ],
	[ 0x30830000, 0x00020103, 0x30830000, 0x0006092A, 0x864886F7, 0x0D010701 ],
	[ 0x30840000, 0x00000201, 0x03308300, 0x00000609, 0x2A864886, 0xF70D0107 ],
	[ 0x30840000, 0x00000201, 0x03308400, 0x00000006, 0x092A8648, 0x86F70D01 ]
];

const PKCS12_HEADER_MASKS = [
	[ 0xFFFF0000, 0xFFFFFFFF, 0xFF0000FF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF0 ],
	[ 0xFF00FFFF, 0xFFFF00FF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF00, 0xFF000000 ],
	[ 0xFFFF00FF, 0xFFFFFFFF, 0x00FFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF00FF ],
	[ 0xFFFF0000, 0xFFFFFFFF, 0xFF00FFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF00 ],
	[ 0xFFFF0000, 0x00FFFFFF, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF ],
	[ 0xFFFF0000, 0x00FFFFFF, 0xFFFF0000, 0x00FFFFFF, 0xFFFFFFFF, 0xFFFFFFFF ],
	[ 0xFFFF0000, 0x0000FFFF, 0xFFFFFF00, 0x0000FFFF, 0xFFFFFFFF, 0xFFFFFFFF ],
	[ 0xFFFF0000, 0x0000FFFF, 0xFFFFFF00, 0x000000FF, 0xFFFFFFFF, 0xFFFFFFFF ]
];

class PKCS12Parser {
	constructor(keystore, password) {
		this.keystore = keystore;
		this.password = password;
	}
	
	/**
	 * @src https://github.com/openjdk/jdk/blob/8554fe6ebce7811a0c3b4670a89e3c07d577d966/src/java.base/share/classes/sun/security/pkcs12/PKCS12KeyStore.java#L2597
	 */
	static probe(keyStoreData) {
		const stream = new InputStream(keyStoreData);
		const first24Bytes = stream.read(24);

		for (let i = 0; i < PKCS12_HEADER_PATTERNS.length; i++) {
			const s = new InputStream(first24Bytes);
			const pattern = PKCS12_HEADER_PATTERNS[i];
			const mask = PKCS12_HEADER_MASKS[i];
			const result = mask.map(m => (s.readInt() & m) >>> 0).every((b, i) => b === pattern[i]);

			if (result) {
				return true;
			}
		}

		return false;
	}

	parse() {
		const p12Buffer = this.keystore.toString("base64");
		const p12Der = forge.util.decode64(p12Buffer);
		const p12Asn1 = forge.asn1.fromDer(p12Der);
		const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, this.password || "");

		return p12.safeContents.reduce((result, item) => {
			if (!Array.isArray(item.safeBags)) {
				return result;
			}

			return result.concat(item.safeBags);
		}, []);
	}

	toPem(bags) {
		return bags.reduce((result, bag) => {
			const alias = bag.attributes.friendlyName[0];
			const hasLocalKeyId = Boolean(bag.attributes.localKeyId);
			let entries = result[alias] || {};

			if (bag.type === forge.pki.oids.certBag) {
				const certKey = hasLocalKeyId ? 'cert' : 'ca';
				
				if (bag.cert) {
					entries = {
						...entries,
						[certKey]: forge.pki.certificateToPem(bag.cert).replace(/\r\n/g, '\n')
					};
				} else if (bag.asn1) {
					entries = {
						...entries,
						[certKey]: derToPem(bag.asn1, 'CERTIFICATE').replace(/\r\n/g, '\n')
					};
				}
			}

			if (bag.key) {
				entries = {
					...entries,
					key: privateKeyToPem(bag.key).replace(/\r\n/g, '\n')
				};
			} else if (bag.asn1 && bag.hasOwnProperty('key')) {
				entries = {
					...entries,
					key: derToPem(bag.asn1, 'PRIVATE KEY').replace(/\r\n/g, '\n')
				};
			}

			return {
				...result,
				[alias]: entries,
			};
		}, {});
	}
}

const privateKeyToPem = (key, maxLine) => {
	return forge.pki.privateKeyInfoToPem(
		forge.pki.wrapRsaPrivateKey(
			forge.pki.privateKeyToAsn1(key)
		)
	);
};

const derToPem = (pki, type) => {
	const msg = {
		type,
		body: forge.asn1.toDer(pki).getBytes()
	};

	return forge.pem.encode(msg);
};

module.exports = PKCS12Parser;
