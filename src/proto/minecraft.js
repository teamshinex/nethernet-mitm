// minecraft.js — custom protodef (interpreter) datatypes for Bedrock
//
// Each export is a [read, write, sizeOf] tuple in node-protodef's interpreter
// form: read/write/sizeOf are invoked with `this` bound to the ProtoDef
// instance, so they recurse through this.read / this.write / this.sizeOf.
//
// CommonJS: these tuples are consumed through require() by compiler-minecraft.js
// and the protodef interpreter.

const nbtModule = require("prismarine-nbt");
const UUID = require("uuid-1345");

const nbtLE = nbtModule.protos.little;
const nbtVarint = nbtModule.protos.littleVarint;

function readUUID(buffer, offset) {
  if (offset + 16 > buffer.length) throw new Error("Reached end of buffer");
  return { value: UUID.stringify(buffer.slice(offset, 16 + offset)), size: 16 };
}
function writeUUID(value, buffer, offset) {
  UUID.parse(value).copy(buffer, offset);
  return offset + 16;
}

function readNbt(buffer, offset) {
  return nbtVarint.read(buffer, offset, "nbt");
}
function writeNbt(value, buffer, offset) {
  return nbtVarint.write(value, buffer, offset, "nbt");
}
function sizeOfNbt(value) {
  return nbtVarint.sizeOf(value, "nbt");
}

function readNbtLE(buffer, offset) {
  const result = nbtLE.read(buffer, offset, "nbt");
  if (result.value.type === "end") {
    return { value: result.value, size: 1 };
  }
  return result;
}
function writeNbtLE(value, buffer, offset) {
  if (value.type === "end") {
    buffer.writeInt8(0, offset);
    return offset + 1;
  }
  return nbtLE.write(value, buffer, offset, "nbt");
}
function sizeOfNbtLE(value) {
  if (value.type === "end") return 1;
  return nbtLE.sizeOf(value, "nbt");
}

function readEntityMetadata(buffer, offset, { type, endVal }) {
  const results = [];
  let cursor = offset;
  let tag;
  while (true) {
    // NOTE: the bounds check uses the original `offset`, not the advancing
    // `cursor`.
    if (offset + 1 > buffer.length) throw new Error("Reached end of buffer");
    tag = buffer.readUInt8(cursor);
    if (tag === endVal) {
      return { value: results, size: (cursor + 1) - offset };
    }
    const read = this.read(buffer, cursor, type, {});
    results.push(read.value);
    cursor += read.size;
  }
}
function writeEntityMetadata(value, buffer, offset, { type, endVal }) {
  value.forEach((item) => {
    offset = this.write(item, buffer, offset, type, {});
  });
  buffer.writeUInt8(endVal, offset);
  return offset + 1;
}
function sizeOfEntityMetadata(value, { type }) {
  let size = 1;
  for (let i = 0; i < value.length; i++) {
    size += this.sizeOf(value[i], type, {});
  }
  return size;
}

function readIpAddress(buffer, offset) {
  const value = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
  return { size: 4, value };
}
function writeIpAddress(value, buffer, offset) {
  value.split(".").forEach((part) => {
    buffer[offset] = parseInt(part);
    offset += 1;
  });
  return offset;
}

function readEndOfArray(buffer, offset, { type }) {
  let cursor = offset;
  const results = [];
  while (cursor < buffer.length) {
    const read = this.read(buffer, cursor, type, {});
    results.push(read.value);
    cursor += read.size;
  }
  return { value: results, size: cursor - offset };
}
function writeEndOfArray(value, buffer, offset, { type }) {
  value.forEach((item) => {
    offset = this.write(item, buffer, offset, type, {});
  });
  return offset;
}
function sizeOfEndOfArray(value, { type }) {
  let size = 0;
  for (let i = 0; i < value.length; i++) {
    size += this.sizeOf(value[i], type, {});
  }
  return size;
}

function readMaybeIncompleteArray(buffer, offset, { type, countType }) {
  const { value: count, size: countSize } = this.read(buffer, offset, countType, {});
  const results = [];
  let cursor = offset + countSize;
  for (let i = 0; i < count && cursor < buffer.length; i++) {
    try {
      const read = this.read(buffer, cursor, type, {});
      results.push(read.value);
      cursor += read.size;
    } catch (error) {
      if (error.name !== "PartialReadError") throw error;
      break;
    }
  }
  return { value: results, size: cursor - offset };
}
function writeMaybeIncompleteArray(value, buffer, offset, { type, countType }) {
  offset = this.write(value.length, buffer, offset, countType, {});
  for (const item of value) {
    offset = this.write(item, buffer, offset, type, {});
  }
  return offset;
}
function sizeOfMaybeIncompleteArray(value, { type, countType }) {
  let size = this.sizeOf(value.length, countType, {});
  for (const item of value) {
    size += this.sizeOf(item, type, {});
  }
  return size;
}

function readOptionalOnRemaining(buffer, offset, { type }) {
  if (offset >= buffer.length) {
    return { value: undefined, size: 0 };
  }
  return this.read(buffer, offset, type, {});
}
function writeOptionalOnRemaining(value, buffer, offset, { type }) {
  if (value === undefined) {
    return offset;
  }
  return this.write(value, buffer, offset, type, {});
}
function sizeOfOptionalOnRemaining(value, { type }) {
  if (value === undefined) {
    return 0;
  }
  return this.sizeOf(value, type, {});
}

module.exports = {
  uuid: [readUUID, writeUUID, 16],
  nbt: [readNbt, writeNbt, sizeOfNbt],
  lnbt: [readNbtLE, writeNbtLE, sizeOfNbtLE],
  entityMetadataLoop: [readEntityMetadata, writeEntityMetadata, sizeOfEntityMetadata],
  ipAddress: [readIpAddress, writeIpAddress, 4],
  endOfArray: [readEndOfArray, writeEndOfArray, sizeOfEndOfArray],
  maybeIncompleteArray: [readMaybeIncompleteArray, writeMaybeIncompleteArray, sizeOfMaybeIncompleteArray],
  optionalOnRemaining: [readOptionalOnRemaining, writeOptionalOnRemaining, sizeOfOptionalOnRemaining],
};
