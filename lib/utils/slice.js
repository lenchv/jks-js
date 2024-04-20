/**
 * @param {Buffer} buf 
 * @param {number} start 
 * @param {number} end 
 * @returns {Buffer}
 */
const sliceBuffer = (buf, start, end) => Uint8Array.prototype.slice ? Uint8Array.prototype.slice.call(buf, start, end) : buf.slice(start, end);

module.exports = sliceBuffer;
