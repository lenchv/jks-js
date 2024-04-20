const sliceBuffer = require('../utils/slice');

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
			this.buffer = Buffer.concat([ sliceBuffer(this.buffer, 0, this.offset), data ]);
			this.offset += data.length;
		}
	}
}

module.exports = OutputStream;
