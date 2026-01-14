function prepareArgs(args) {
  if (args === undefined || !Array.isArray(args)) {
    args = [];
  }
  var argNum = args.length;
  var argSize = Process.pointerSize * argNum;
  var argsPtr = Memory.alloc(argSize);

  for (var i = 0; i < argNum; i++) {
    var arg = args[i];
    var argPtr;
    if (!arg) {
      arg = 0;
    }
    if (arg instanceof NativePointer) {
      // 如果是 NativePointer，直接使用
      argPtr = arg;
    } else if (typeof arg === "number") {
      // 如果是数字，直接转换为指针
      argPtr = ptr(arg);
    } else if (typeof arg === "string") {
      // 如果是字符串，分配内存并获取指针
      argPtr = Memory.allocUtf8String(arg);
    } else if (typeof arg === "object" && arg.hasOwnProperty("handle")) {
      // 如果是带有 handle 属性的对象（如 JNIEnv）
      argPtr = arg.handle;
    } else if (typeof arg === "object" && arg instanceof ArrayBuffer) {
      // 如果是二进制数据，分配内存并写入数据
      var dataPtr = Memory.alloc(arg.byteLength);
      dataPtr.writeByteArray(arg);
      argPtr = dataPtr;
    } else {
      console.error(
        "Unsupported argument type at index " + i + ":",
        typeof arg
      );
      throw new TypeError(
        "Unsupported argument type at index " + i + ": " + typeof arg
      );
    }

    // 将参数指针写入参数数组
    argsPtr.add(i * Process.pointerSize).writePointer(argPtr);
  }

  return {
    argsPtr: argsPtr,
    argNum: argNum,
  };
}

var vmtraceAddr;
var vmtrace;

function hookfinal(name) {
  var aimbase = Process.getModuleByName(name).base;
  var targetFuncAddr = aimbase.add(0x2c60);
  console.log("start hook", targetFuncAddr);
  Interceptor.replace(
    targetFuncAddr,
    new NativeCallback(
      function (arg0, arg1, arg2, arg3, arg4, arg5) {
        console.log("trace调用了", aimbase);
        Interceptor.revert(targetFuncAddr);
        Interceptor.flush();
        var args = [arg0];
        var { argsPtr, argNum } = prepareArgs(args);
        var argPtr1 = Memory.allocUtf8String(
          "/data/data/com.revolut.revolut/loga.txt"
        );
        var res = vmtrace(targetFuncAddr, argsPtr, argNum, argPtr1, 0);
        console.log("res", res);
        return res;
      },
      "pointer",
      ["pointer"]
    )
  );
}

function hook_soload() {
  var dlopenPtr = DebugSymbol.fromName("dlopen").address;
  var dlopen = new NativeFunction(dlopenPtr, "pointer", ["pointer", "int"]);
  var soPath = "/data/local/tmp/test.so"; // 示例路径
  var soPathPtr = Memory.allocUtf8String(soPath);
  var handle = dlopen(soPathPtr, 2);
  console.log(handle);
  const vmModule = Process.getModuleByName("test.so");
  vmtraceAddr = vmModule.getExportByName("vm_call");
  vmtrace = new NativeFunction(vmtraceAddr, "pointer", [
    "pointer",
    "pointer",
    "uint32",
    "pointer",
    "uint32",
  ]);

  var isinit = 0;
  var dlopen_addr = DebugSymbol.fromName("android_dlopen_ext").address;
  var find = 0;
  console.log("android_dlopen_ext: ", dlopen_addr);
  Interceptor.attach(dlopen_addr, {
    onEnter: function (args) {
      var addr = args[0];
      var str = ptr(addr).readCString();
      this.name = str;

      if (str.indexOf("libdexprotector.so") >= 0) {
        console.log("dlopen==> " + str);
        find = 1;
      } else {
        find = 0;
      }
    },
    onLeave: function (retval) {
      if (find > 0) {
        if (isinit == 0) {
          hookfinal(this.name);
          isinit = 1;
        }
      }
    },
  });
}
setImmediate(hook_soload);
