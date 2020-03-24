const InputStream = require('./InputStream');

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

module.exports = DigestInputStream;
