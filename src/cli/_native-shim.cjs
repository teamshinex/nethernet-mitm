// _native-shim.cjs — node-datachannel native addon loader (for pkg-bundled builds)
//
// CommonJS, imported for side effect.
//
// Role: when running inside a pkg snapshot (process.pkg), node-datachannel can't
// find its prebuilt addon through the normal filesystem probe. This shim makes
// the probe fail for the bundled "build" path, then redirects a require of the
// platform's @node-datachannel/<platform> package to the real .node file that
// sits next to the executable.

if (process.pkg) {
  const fs = require("node:fs");
  const path = require("node:path");
  const Module = require("node:module");

  const origExistsSync = fs.existsSync;
  fs.existsSync = (file) => {
    if (typeof file === "string" && file.includes("node-datachannel") && file.includes("build")) {
      return false;
    }
    try {
      return origExistsSync.call(fs, file);
    } catch {}
    return false;
  };

  const nativePackages = {
    "win32-x64": "@node-datachannel/win32-x64-msvc",
    "win32-arm64": "@node-datachannel/win32-arm64-msvc",
    "linux-x64": "@node-datachannel/linux-x64-gnu",
    "linux-arm64": "@node-datachannel/linux-arm64-gnu",
    "darwin-x64": "@node-datachannel/darwin-x64",
    "darwin-arm64": "@node-datachannel/darwin-arm64",
  };
  const platformKey = `${process.platform}-${process.arch}`;
  const nativePackage = nativePackages[platformKey];
  if (!nativePackage) {
    throw new Error("no node-datachannel native build known for " + platformKey);
  }

  const nativeAddon = require(path.join(path.dirname(process.execPath), "node_datachannel.node"));
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === nativePackage) return nativeAddon;
    return origLoad.call(this, request, parent, isMain);
  };
}
