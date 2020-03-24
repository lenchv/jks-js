const InputStream = require('../stream/InputStream');

class DerValue {
	constructor(inputStream) {
		this.tag = null;
		this.length = 0;
		this.data = null;
		this.buffer = null;

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

	/** Returns true if the CONSTRUCTED bit is set in the type tag. */
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

/** Tag value indicating an ASN.1 "OBJECT IDENTIFIER" value. */
DerValue.tag_ObjectId = 0x06;

/**
 * Tag value indicating an ASN.1
 * "SEQUENCE" (zero to N elements, order is significant).
 */
DerValue.tag_Sequence = 0x30;

/** Tag value indicating an ASN.1 "OCTET STRING" value. */
DerValue.tag_OctetString = 0x04;

/** Tag value indicating an ASN.1 "INTEGER" value. */
DerValue.tag_Integer = 0x02;

module.exports = DerValue;
