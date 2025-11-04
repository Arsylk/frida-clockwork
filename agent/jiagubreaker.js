function inRanges(ptr) {
  if (!ptr || ptr === NULL || `${ptr}` === "0x0") return false;
  for (const { base, size } of ranges) {
    if (ptr >= base && base.add(size) > ptr) {
      return true;
    }
  }
  return false;
}

function getEnumerated(module, symbol) {
  for (const ex of module.enumerateExports()) {
    if (ex.name === symbol) {
      return ex.address;
    }
  }
  for (const sm of module.enumerateSymbols()) {
    if (sm.name === symbol) {
      return sm.address;
    }
  }
  return NULL;
}

function tryOrNull(fn) {
  try {
    return fn();
  } catch (_) {}
  return null;
}

function hardBreakPoint(ptr, fn) {
  let called = false;
  const prot = Memory.queryProtection(ptr);
  Process.setExceptionHandler(function (ex) {
    console.log(
      Thread.backtrace(ex.context, Backtracer.FUZZY).join("\t\n"),
      "hardbrk"
    );
    // logger.info({ tag: 'hardbrk' }, `${ptr}\n    ${trace}`);
    fn();
    Memory.protect(ptr, Process.pointerSize, prot);
    if (!called) return (called = true);
  });
  Memory.protect(ptr, Process.pointerSize, "---");
}

const ranges = new Array();
let found = false;
const mprots = new Array();
const dexes = new Map();
const ents = new Array();

const libart = Process.getModuleByName("libart.so");
const linker64 = Process.getModuleByName("linker64");
const libc = Process.getModuleByName("libc.so");

const dlopen = new NativeFunction(libc.getExportByName("dlopen"), "pointer", [
  "pointer",
  "int",
]);
const dlsym = new NativeFunction(libc.getExportByName("dlsym"), "pointer", [
  "pointer",
  "pointer",
]);

Interceptor.attach(libc.getExportByName("mprotect"), {
  onEnter(args) {
    if (inRanges(this.returnAddress)) {
      console.log("[mprotect]", args[0], args[1], args[2]);
      this.base = args[0];
      this.size = args[1].toInt32();
    }
  },
  onLeave(retval) {
    const base = this.base;
    const size = this.size;
    if (base && size) {
      const range = { base: base, size: size };
      mprots.push(range);
      ranges.push(range);
    }
  },
});

const libdl = Process.getModuleByName("libdl.so");
Interceptor.attach(libdl.getExportByName("dlopen"), {
  onEnter(args) {
    const name = args[0].readCString();
    this.name = name;
    console.log("[dlopen]", name);
  },
  onLeave(retval) {
    const name = this.name;
    if (name) {
      if (!found) {
        hookmore(name);
      }
    }
  },
});

Process.attachModuleObserver({
  onAdded(module) {
    const { base, name, size, path } = module;
    console.log(
      "[phdr]",
      `{ name: ${name}, base: ${base}, size: ${size}, path: ${path} }`
    );
    if (name === "base.odex") {
      hookdex(libart);
      hookhide(linker64, (name) => {
        for (const target of ["frida", "memfd", "libart.so", "libdl.so"]) {
          if (name.includes(target)) {
            return true;
          }
        }
        return false;
      });
      ranges.push({ base: base, size: size });
    }
    if (name.includes("libjiagu") || name.includes("l02e9294c")) {
      ranges.push({ base: base, size: size });

      const getEnumeratedAll = (module, fn) => {
        const b = [];
        for (const ex of module.enumerateExports()) {
          if (fn(ex)) {
            b.push(ex);
          }
        }
        return b;
      };
      ents.push(
        ...getEnumeratedAll(
          module,
          ({ name }) =>
            (name !== "_ULaarch64_local_addr_space" &&
              name.includes("aarch64")) ||
            name.includes("interpreter")
        )
      );

      let uq = 0;
      for (const ent of ents) {
        const { address: addr, name } = ent;
        try {
          Interceptor.attach(addr, {
            onEnter(args) {
              const getAt = (i) =>
                tryOrNull(() =>
                  args[i].sub(base) >= 0 && args[i].sub(base) <= size
                    ? args[i].sub(base)
                    : args[i]
                );
              console.log(
                `[${name}]:${(this.uq = ++uq)} call(${getAt(0)}, ${getAt(
                  1
                )}, ${getAt(2)}, ${getAt(3)})`,
                `${this.returnAddress.sub(base)}`
              );
            },
            onLeave(retval) {
              console.log(
                `[${name}]:${this.uq} return`,
                `${this.returnAddress.sub(base)}`
              );
            },
          });
          // console.log(`${addr} ${name} OK`);
        } catch (e) {
          // console.log(`${addr} ${name} ${e}`);
        }
      }
      Interceptor.attach(base.add(0xc6f8), {
        onEnter(args) {
          this.sym = args[1].readCString();
        },
        onLeave(retval) {
          console.log("[dlsym_mk3]", `${this.sym} ? ${retval.sub(base)}`);
        },
      });

      Interceptor.attach(base.add(0x11564), {
        onEnter(args) {
          console.log(
            "[maps_mk2]",
            `${base.add(0x2bf47c).readPointer()} ? ${this.returnAddress.sub(
              base
            )}`
          );
        },
        onLeave(retval) {},
      });

      // Interceptor.attach(
      //   getEnumerated(module, "interpreter_wrap_int64_t_bridge"),
      //   {
      //     onEnter({ 0: a0, 1: a1, 2: a2, 3: a3, 4: a4, 5: a5 }) {
      //       console.log("[interpreter_wrap_int64_t_bridge]", [
      //         a0.sub(base),
      //         a1,
      //         a2.sub(base),
      //         a3.sub(base),
      //         a4,
      //         a5,
      //       ]);
      //       console.log(
      //         Thread.backtrace(this.context, Backtracer.FUZZY)
      //           .map(DebugSymbol.fromAddress)
      //           .join("\n\t")
      //       );
      //     },
      //     onLeave(retval) {
      //       console.log("[interpreter_wrap_int64_t_bridge]", retval);
      //     },
      //   }
      // );
    }
  },
});

function hookmore(name) {
  let module = Process.findModuleByName(name);
  if (name === "libc.so") module ??= libc;
  if (name === "libart.so") module ??= libart;
  if (name === "linker64") module ??= linker64;
  if (!module) return;
  for (const range of [module, ...mprots]) {
    console.log("[memscan]", `${range.base} - ${range.base.add(range.size)}`);
    for (
      let _base = range.base;
      _base < range.base.add(range.size);
      _base = _base.add(Process.pageSize)
    ) {
      try {
        const match = Memory.scanSync(
          _base,
          Process.pageSize,
          "01 00 b4 ?? 01 00 b4 ?0 0? 3f d6"
        );
        if (match.length === 0) continue;
        const address = match[0].address;
        console.log("[memmatch]", `${address}`);
        const inst = Instruction.parse(address.sub(0x1 + 0x4 * 2));
        if (inst.mnemonic === "bl") {
          found = true;
          const op = inst.operands[0];
          const f = ptr(`${op.value}`);
          console.log("[memfound]", `${inst.address} ${inst} ${f}`);
          Interceptor.attach(f, {
            onEnter(args) {
              this.handle = args[0];
              this.symbol = args[1].readCString();
            },
            onLeave(retval) {
              console.log(
                `[${f.sub(range.base)}]`,
                `${this.symbol} = ${retval} | 0x0`
              );
              retval.replace(ptr(0x0));
            },
          });
          break;
        }
      } catch {}
    }
    if (found) break;
  }
}

function hookdex(libart) {
  const symbol =
    "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE";
  let dex = getEnumerated(libart, symbol);
  if (dex === NULL) {
    console.log("[dex]", "failed to find symbol");
    return;
  }

  Interceptor.attach(dex, {
    onEnter(args) {
      const dexfile = args[5];
      const base = dexfile.add(Process.pointerSize).readPointer();
      const size = dexfile.add(Process.pointerSize * 2).readUInt();
      if (dexes.has(`${base}`)) return;
      dexes.set(`${base}`, size);
      console.log(
        "[dex]",
        `${base.readCString(4).replace("\n", "\\n")} ${size}`
      );
      Memory.protect(base, size, "r");
      const pkgbarr = File.readAllBytes("/proc/self/cmdline");
      let pkg = "";
      for (const b of new Uint8Array(pkgbarr)) {
        if (b === 0x0) break;
        pkg += String.fromCharCode(b);
      }
      const file = `/data/data/${pkg}/classes_${base}.dex`;
      File.writeAllBytes(file, base.readByteArray(size));
      console.log("[dex]", `saved ${file}`);
    },
  });
}

function hookhide(linker, predicate) {
  const solist_get_head = new NativeFunction(
    getEnumerated(linker, "__dl__Z15solist_get_headv"),
    "pointer",
    []
  );
  const soinfo_get_soname = new NativeFunction(
    getEnumerated(linker, "__dl__ZNK6soinfo10get_sonameEv"),
    "pointer",
    ["pointer"]
  );
  const soinfo_get_realpath = new NativeFunction(
    getEnumerated(linker, "__dl__ZNK6soinfo12get_realpathEv"),
    "pointer",
    ["pointer"]
  );

  const nextoff = Process.pointerSize * 5;
  let item = solist_get_head();
  let prev = null;
  while (`${item}` !== "0x0") {
    const name = soinfo_get_soname(item).readCString();
    const path = soinfo_get_realpath(item).readCString();
    const next = item.add(nextoff).readPointer();
    if (predicate(name) || predicate(path)) {
      const nptr = prev?.add(nextoff);
      Memory.protect(nptr, Process.pointerSize, "rwx");
      nptr?.writePointer(next);
      console.log("[linkskip]", name, path);
    }
    prev = item;
    item = next;
  }
}

console.log("[processid]", Process.id);
