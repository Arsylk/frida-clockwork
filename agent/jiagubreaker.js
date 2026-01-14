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

const MORELOGS = true;
const DETACHSELF = true;

const ranges = new Array();
const mprots = new Array();
const dexes = new Map();
const ents = new Array();
let found = false;

const linker64 = Process.getModuleByName("linker64");
const libart = Process.getModuleByName("libart.so");
const libdex = Process.getModuleByName("libdexfile.so");
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
      this.prot = args[2].toInt32();
    }
  },
  onLeave(retval) {
    const base = this.base;
    const size = this.size;
    const prot = this.prot;
    if (base && size && prot & 4) {
      const range = { base: base, size: size };
      mprots.push(range);
      ranges.push(range);
    }
  },
});

function inithook() {
  // doing it this way is actually almost required as it is too slow to hook strlen though js
  const cmodule = new CModule(
    `
#include "glib.h"
#include <gum/guminterceptor.h>

extern char *strstr(const char *haystack, const char *needle);
extern gboolean inRange(void *ptr);
extern void frida_log(const gchar *messag, ...);

typedef struct _IcState IcState;
struct _IcState {
  gchar *arg0;
};

void onEnter(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  is->arg0 = (gchar *)gum_invocation_context_get_nth_argument(ic, 0);
}

void onLeave(GumInvocationContext *ic) {
  IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
  size_t retval = GPOINTER_TO_SIZE(gum_invocation_context_get_return_value(ic));
  void *retaddr = (void *)gum_invocation_context_get_return_address(ic);

  if (inRange(retaddr)) {
    gchar *mc = NULL;
    if (retval > 100) {
      if (strstr(is->arg0, "/apex/com.android.art/lib64/libart.so")) {
        mc = (gchar *)(is->arg0 + 22);
      }
      if (strstr(is->arg0, "/system/lib64/libselinux.so")) {
        mc = (gchar *)(is->arg0 + 22);
      }
      if (strstr(is->arg0, "/system/lib64/libandroid_runtime.so")) {
        mc = (gchar *)(is->arg0 + 22);
      }
      if (mc != NULL) {
        frida_log(is->arg0);
        mc[0] = '-';
        mc[1] = '-';
        mc[2] = '-';
        mc[3] = '-';
      }
    }
  }
}
`,
    {
      strstr: libc.getExportByName("strstr"),
      inRange: new NativeCallback(
        function (ptr) {
          return inRanges(ptr) ? 1 : 0;
        },
        "bool",
        ["pointer"]
      ),
      frida_log: new NativeCallback(
        function (ptr) {
          console.log("[strlen]", ptr.readCString());
        },
        "void",
        ["pointer"]
      ),
    }
  );
  Interceptor.attach(libc.getExportByName("strlen"), cmodule);
}

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
      hookhide(linker64, (name) => {
        for (const target of ["frida", "memfd"]) {
          if (name.includes(target)) {
            return true;
          }
        }
        return false;
      });
      ranges.push({ base: base, size: size });
    }
    if (name.includes("jiagu")) {
      ranges.push({ base: base, size: size });

      // this is basically cosmetic logs, but they make it a bit less stable
      if (MORELOGS) {
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
                  `[${name}]:${this.uq} return ${retval}`,
                  `${this.returnAddress.sub(base)}`
                );
                // if ([18, 20, 28, 34].includes(this.uq)) retval.replace(ptr(0x0));
              },
            });
            // console.log(`${addr} ${name} OK`);
          } catch (e) {
            // console.log(`${addr} ${name} ${e}`);
          }
        }
      }
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
          let finalhook;
          finalhook = () => {
            Interceptor.attach(f, {
              onEnter(args) {
                this.handle = args[0];
                this.symbol = args[1].readCString();
              },
              onLeave(retval) {
                let newval = ptr(0x0);
                // const sym = DebugSymbol.fromName(this.symbol);
                // if (sym) newval = sym.address;
                if (this.symbol === "mprotect") {
                  newval = retval;
                  // this is to save on execution speed and potential crashes, only rehook whats needed
                  if (DETACHSELF) {
                    Interceptor.detachAll();
                    Interceptor.flush();
                    inithook();
                    finalhook();
                  }
                }
                console.log(
                  `[${f.sub(range.base)}]`,
                  `${this.symbol} = ${retval} | ${newval}`
                );
                retval.replace(newval);
              },
            });
          };
          finalhook();
          break;
        }
      } catch {}
    }
    if (found) break;
  }
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
inithook();
