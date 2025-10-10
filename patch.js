Object.defineProperties(Module, {
  ensureInitialized: {
    value: (name) => Process.getModuleByName(name).ensureInitialized(),
  },
  getSymbolByName: {
    value: (module, name) =>
      !module
        ? Module.getGlobalExportByName(name)
        : Process.getModuleByName(name).getSymbolByName(name),
  },
  findSymbolByName: {
    value: (module, name) =>
      !module
        ? Module.findGlobalExportByName(name)
        : Process.findModuleByName(name)?.findExportByName(name) ?? null,
  },
  getExportByName: {
    value: (module, name) =>
      !module
        ? Module.getGlobalExportByName(name)
        : Process.getModuleByName(module).getExportByName(name),
  },
  findExportByName: {
    value: (module, name) =>
      !module
        ? Module.findGlobalExportByName(name)
        : Process.findModuleByName(module)?.findExportByName(name) ?? null,
  },
  getBaseAddress: {
    value: (name) => Process.getModuleByName(name).base,
  },
  findBaseAddress: {
    value: (name) => Process.findModuleByName(name)?.base ?? null,
  },
});
const memdef = {};
for (const sign of ["U", "S"]) {
  for (const type of ["8", "16", "32", "64", "Short", "Int", "Long"]) {
    const key = `read${sign}${type}`;
    memdef[key] = { value: (ptr) => NULL[key]?.call(ptr) };
  }
}
for (const odd of [
  "Short",
  "Int",
  "Long",
  "Float",
  "Double",
  "Pointer",
  "ByteArray",
  "Byte",
  "Volatile",
]) {
  const key = `read${odd}`;
  memdef[key] = { value: (ptr) => NULL[key]?.call(ptr) };
}
for (const str of ["CString", "Utf8String", "Utf16String", "AnsiSting"]) {
  const key = `read${str}`;
  memdef[key] = { value: (ptr, len) => NULL[key]?.call(ptr, len) };
}
for (const sign of ["U", "S"]) {
  for (const type of ["8", "16", "32", "64", "Short", "Int", "Long"]) {
    const key = `write${sign}${type}`;
    memdef[key] = { value: (ptr, value) => NULL[key]?.call(ptr, value) };
  }
}
for (const odd of [
  "Short",
  "Int",
  "Long",
  "Float",
  "Double",
  "Pointer",
  "ByteArray",
  "Byte",
  "Volatile",
  "AnsiSting",
  "Utf8String",
  "Utf16String",
]) {
  const key = `write${odd}`;
  memdef[key] = { value: (ptr, value) => NULL[key]?.call(ptr, value) };
}

Object.defineProperties(Memory, memdef);
