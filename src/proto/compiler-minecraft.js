// compiler-minecraft.js — custom protodef (compiler) datatypes for Bedrock
//
// Shape consumed by protodef's ProtoDefCompiler.addTypes: { Read, Write, SizeOf }
// where each entry is ["native" | "context" | "parametrizable", impl]. The
// "parametrizable" impls return source code produced via compiler.wrapCode /
// compiler.callType; "native"/"context" impls are inlined and run with `ctx`
// (the compiled type table) in scope.
//
// CommonJS: it is require()'d synchronously by protocol.cjs and reuses the
// nbt/lnbt natives from ./minecraft.js.

const UUID = require("uuid-1345");
const { nbt, lnbt } = require("./minecraft.js");

// Extracts a function body: drop the `function () {` and closing `}` lines.
function js(fn) {
  return fn.toString().split("\n").slice(1, -1).join("\n").trim();
}

// Emits a parametrizable Write/SizeOf snippet closing the compiler's IIFE.
function str(fn) {
  return fn.toString() + ")();(()=>{}";
}

// NOTE: the functions passed to js()/str() reference identifiers (value,
// offset, values_len, _enum_type) that only exist in the generated code's
// scope; they are stringified, never called here.

const Read = {
  uuid: ["native", (buffer, offset) => {
    return { value: UUID.stringify(buffer.slice(offset, 16 + offset)), size: 16 };
  }],
  restBuffer: ["native", (buffer, offset) => {
    return { value: buffer.slice(offset), size: buffer.length - offset };
  }],
  maybeIncompleteArray: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  const { value: count, size: countSize } = ${compiler.callType(args.countType)}
  if (count > 0xffffff && !ctx.noArraySizeCheck) throw new Error("array size is abnormally large, not reading: " + count)
  const data = []
  let size = countSize
  for (let i = 0; i < count && offset + size < buffer.length; i++) {
    try {
      const elem = ${compiler.callType(args.type, "offset + size")}
      data.push(elem.value)
      size += elem.size
    } catch (error) {
      if (error.name !== "PartialReadError") throw error
      break
    }
  }
  return { value: data, size }
`.trim());
  }],
  optionalOnRemaining: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  if (offset >= buffer.length) return { value: undefined, size: 0 }
  return ${compiler.callType(args.type)}
`.trim());
  }],
  encapsulated: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  const payloadSize = ${compiler.callType(args.lengthType, "offset")}
  if (payloadSize.value === 0) {
    return { value: undefined, size: payloadSize.size }
  }
  const { value, size } = ctx.${args.type}(buffer, offset + payloadSize.size)
  return { value, size: size + payloadSize.size }
`.trim());
  }],
  nbtLoop: ["context", function (buffer, offset) {
    const results = [];
    const start = offset;
    while (buffer[offset] != 0) {
      const n = ctx.nbt(buffer, offset);
      results.push(n.value);
      offset += n.size;
    }
    return { value: results, size: (offset + 1) - start };
  }],
  byterot: ["context", function (buffer, offset) {
    const value = buffer.readUint8(offset);
    return { value: value * 1.40625, size: 1 };
  }],
  nbt: ["native", nbt[0]],
  lnbt: ["native", lnbt[0]],
  enum_size_based_on_values_len: ["parametrizable", (compiler) => {
    return compiler.wrapCode(js(function () {
      if (values_len <= 256) return { value: "byte", size: 0 };
      if (values_len <= 65536) return { value: "short", size: 0 };
      if (values_len <= 16777216) return { value: "int", size: 0 };
    }));
  }],
};

const Write = {
  uuid: ["native", (value, buffer, offset) => {
    UUID.parse(value).copy(buffer, offset);
    return offset + 16;
  }],
  restBuffer: ["native", (value, buffer, offset) => {
    value.copy(buffer, offset);
    return offset + value.length;
  }],
  maybeIncompleteArray: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  offset = ${compiler.callType("value.length", args.countType)}
  for (let i = 0; i < value.length; i++) {
    offset = ${compiler.callType("value[i]", args.type)}
  }
  return offset
`.trim());
  }],
  optionalOnRemaining: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  if (value === undefined) return offset
  return ${compiler.callType("value", args.type)}
`.trim());
  }],
  encapsulated: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  if (value === undefined) {
    return (ctx.${args.lengthType})(0, buffer, offset)
  }
  const buf = Buffer.allocUnsafe(buffer.length - offset)
  const payloadSize = (ctx.${args.type})(value, buf, 0)
  let size = (ctx.${args.lengthType})(payloadSize, buffer, offset)
  size += buf.copy(buffer, size, 0, payloadSize)
  return size
`.trim());
  }],
  nbtLoop: ["context", function (value, buffer, offset) {
    for (const item of value) {
      offset = ctx.nbt(item, buffer, offset);
    }
    buffer.writeUint8(0, offset);
    return offset + 1;
  }],
  byterot: ["context", function (value, buffer, offset) {
    const raw = value / 1.40625;
    buffer.writeUint8(raw, offset);
    return offset + 1;
  }],
  nbt: ["native", nbt[1]],
  lnbt: ["native", lnbt[1]],
  enum_size_based_on_values_len: ["parametrizable", (compiler) => {
    return str(function () {
      if (value.values_len <= 256) {
        _enum_type = "byte";
      } else if (value.values_len <= 65536) {
        _enum_type = "short";
      } else if (value.values_len <= 16777216) {
        _enum_type = "int";
      }
      return offset;
    });
  }],
};

const SizeOf = {
  uuid: ["native", 16],
  restBuffer: ["native", (value) => {
    return value.length;
  }],
  maybeIncompleteArray: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  let size = ${compiler.callType("value.length", args.countType)}
  for (let i = 0; i < value.length; i++) {
    size += ${compiler.callType("value[i]", args.type)}
  }
  return size
`.trim());
  }],
  optionalOnRemaining: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
  if (value === undefined) return 0
  return ${compiler.callType("value", args.type)}
`.trim());
  }],
  encapsulated: ["parametrizable", (compiler, args) => {
    return compiler.wrapCode(`
    if (value === undefined) {
      return (ctx.${args.lengthType})(0)
    }
    const payloadSize = (ctx.${args.type})(value)
    return (ctx.${args.lengthType})(payloadSize) + payloadSize
`.trim());
  }],
  nbtLoop: ["context", function (value, buffer, offset) {
    let size = 1;
    for (const item of value) {
      size += ctx.nbt(item, buffer, offset);
    }
    return size;
  }],
  byterot: ["context", function (value, buffer, offset) {
    return 1;
  }],
  nbt: ["native", nbt[2]],
  lnbt: ["native", lnbt[2]],
  enum_size_based_on_values_len: ["parametrizable", (compiler) => {
    return str(function () {
      if (value.values_len <= 256) {
        _enum_type = "byte";
      } else if (value.values_len <= 65536) {
        _enum_type = "short";
      } else if (value.values_len <= 16777216) {
        _enum_type = "int";
      }
      return 0;
    });
  }],
};

module.exports = { Read, Write, SizeOf };
