// protocol.cjs — Bedrock protocol definition loader
//
// Role: reads the vendored Bedrock protocol JSON from disk, builds id<->name
// packet maps, and (lazily, in compiled()) compiles a protodef serializer and
// parser using the custom minecraft compiler datatypes.
//
// CommonJS: it is require()'d synchronously by compiled(); it in turn
// require()'s ./compiler-minecraft.js.

const { Compiler, FullPacketParser, Serializer } = require("protodef");
const { ProtoDefCompiler } = Compiler;
const fs = require("fs");
const path = require("path");

const cache = new Map();

function load(version) {
  const cached = cache.get(version);
  if (cached) return cached;

  const file = path.join(__dirname, "..", "..", "data", `bedrock-${version}-protocol.json`);
  let protocol;
  try {
    protocol = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`no vendored protocol schema for bedrock ${version} (${file}): ${err.message}`);
  }

  const names = new Map(
    Object.entries(protocol.types.mcpe_packet[1][0].type[1].mappings).map(([id, name]) => [Number(id), name]),
  );
  const ids = new Map(Array.from(names).map(([id, name]) => [name, id]));

  const def = { names, ids, protocol, serializer: null, parser: null };
  cache.set(version, def);
  return def;
}

function compiled(def) {
  if (!def.serializer) {
    const compiler = new ProtoDefCompiler();
    compiler.addTypesToCompile(def.protocol.types);
    compiler.addTypes(require("./compiler-minecraft.js"));
    const proto = compiler.compileProtoDefSync();
    def.serializer = new Serializer(proto, "mcpe_packet");
    def.parser = new FullPacketParser(proto, "mcpe_packet");
  }
  return def;
}

module.exports = { load, compiled };
