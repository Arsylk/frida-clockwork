import Java from 'frida-java-bridge';
import { JNI, asFunction, asLocalRef } from '@clockwork/jnitrace';
import { Color } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';
import { ClassesString } from './define/java.js';
import { toHex } from './text.js';
import { JavaPrimitive } from './define/consts.js';
const { black, gray, red, green, orange, dim, italic, bold, yellow, hidden } = Color.use();

// biome-ignore lint/suspicious/noExplicitAny: ask frida what type it is
function vs(value: any, type?: string, jniEnv: NativePointer = Java.vm.tryGetEnv()?.handle): string {
  if (value === undefined) return Color.number(undefined);
  if (value === null) return Color.number(null);

  //loop over array until max length
  if (type?.endsWith('[]')) {
    return visualizeArray(value, type, jniEnv);
  }

  // console.log(`v: ${value} t: ${typeof value}|${value instanceof NativePointer} s: ${type}`);
  // select by provided type
  switch (type) {
    case 'boolean':
      return Color.number(value ? 'true' : 'false');
    case 'byte': {
      const bvalue = Number(`${value}`) & 0xff;
      const strByte = `0x${toHex(bvalue ?? 0)}`;
      return Color.number(strByte);
    }
    case 'char': {
      const cval = Number(`${value}`) & 0xffff;
      return Color.char(String.fromCharCode(cval ?? 0));
    }
    case 'short': {
      const sval = Number(`${value}`) & 0xffff;
      return Color.number(sval ?? 0);
    }
    case 'int': {
      const ival = Number(value) & 0xffffffff;
      return Color.number(ival ?? 0);
    }
    case 'long': {
      const cond = typeof value === 'object' ? Number(BigInt(`${value}`)) : Number(value);
      return Color.number(`${cond}`);
    }
    case 'float': {
      //@ts-ignore
      const strFloat = Classes.String.valueOf.overload('float').bind(Classes.String);
      return Color.number(strFloat(Number(value)));
    }
    case 'double': {
      function swapEndian64(num: bigint) {
        return (
          ((num & 0xff0000000000000n) >> 56n) |
          ((num & 0x00ff00000000000n) >> 40n) |
          ((num & 0x0000ff000000000n) >> 24n) |
          ((num & 0x000000ff0000000n) >> 8n) |
          ((num & 0x00000000ff00000n) << 8n) |
          ((num & 0x0000000000ff000n) << 24n) |
          ((num & 0x000000000000ff0n) << 40n) |
          ((num & 0x00000000000000fn) << 56n)
        );
      }
      const little = typeof value === 'object' ? Number(swapEndian64(BigInt(value))) : Number(value);
      //@ts-ignore
      const strFloat = Classes.String.valueOf.overload('float').bind(Classes.String);
      return Color.number(strFloat(little));
    }
  }

  // select by actual value type
  switch (typeof value) {
    case 'string':
      return Color.string(value);
    case 'boolean':
      return Color.number(value ? 'true' : 'false');
    case 'number':
    case 'bigint':
      return Color.number(value);
  }

  // * should only have java objects in here
  const classHandle = value.$h ?? value;
  if (classHandle) {
    const handleStr = `${classHandle}`;
    // console.log(value, type, typeof value, value.$h, value instanceof NativePointer);
    // return `${classHandle}`;

    if (handleStr === '0x0' || classHandle === NULL || !classHandle) {
      return Color.number(null);
    }

    if (classHandle) {
      if (handleStr.length !== 12) {
        try {
          // this is ghetto but it works, check if mem address is valid, but skip for local refs
          if (handleStr.length > 12) Memory.queryProtection(classHandle);
        } catch {
          return `{ mem: ${classHandle} ${asFunction(jniEnv, JNI.GetObjectRefType)(jniEnv, classHandle)} }`;
        }
        let text: string | null = null;
        try {
          const NewLocalRef = asFunction(jniEnv, JNI.NewLocalRef);
          const local = NewLocalRef(jniEnv, classHandle);
          local.readByteArray(8);
          text = visualObject(local, type);
          const DeleteLocalRef = asFunction(jniEnv, JNI.DeleteLocalRef);
          DeleteLocalRef(jniEnv, local);
        } catch {
          try {
            text = visualObject(classHandle, type);
          } catch {
            text = black(`${value}`);
          }
        }
        if (text) return text;
      } else {
        const text = visualObject(classHandle, type);
        if (text) return text;
      }
    }

    return black(`${value}`);
  }
  return red(`${value}`);
}

// biome-ignore lint/suspicious/noExplicitAny: ask frida what type it is
function visualizeArray(value: any, type: string, jniEnv: NativePointer): string {
  const baseType = type.replace(/[\\[\\]]/g, '');
  const itemType = type.substring(0, type.length - 2);
  let getItem = (i: number) => value[i];
  let size = value.size ?? value.length;

  // native pointer to array only
  if (!size) {
    const mPointer = value.$h ?? value;
    if (mPointer instanceof NativePointer) {
      size = asFunction(jniEnv, JNI.GetArrayLength)(jniEnv, mPointer);
      switch (JavaPrimitive[itemType]) {
        case undefined: {
          const GetArrayItem = asFunction(jniEnv, JNI.GetObjectArrayElement);
          getItem = (i: number) => vs(GetArrayItem(jniEnv, mPointer, i), itemType, jniEnv);
          break;
        }
        case 'B': {
          const elems = asFunction(jniEnv, JNI.GetByteArrayElements)(jniEnv, mPointer, ptr(0x0));
          getItem = (i: number) => Color.number(`0x${toHex(elems.add(i * 1).readU8())}`);
          break;
        }
        case 'S': {
          const elems = asFunction(jniEnv, JNI.GetByteArrayElements)(jniEnv, mPointer, ptr(0x0));
          getItem = (i: number) => Color.number(`${elems.add(i * 2).readS16()}`);
          break;
        }
        case 'C': {
          const elems = asFunction(jniEnv, JNI.GetCharArrayElements)(jniEnv, mPointer, ptr(0x0));
          getItem = (i: number) => Color.char(String.fromCharCode(elems.add(i * 2).readU16()));
          break;
        }
        case 'I': {
          const elems = asFunction(jniEnv, JNI.GetIntArrayElements)(jniEnv, mPointer, ptr(0x0));
          getItem = (i: number) => Color.number(elems.add(i * 4).readS32());
          break;
        }
        default:
          return `${value}`;
      }
    }
  }

  const items: string[] = [];
  let messageSize = 0;
  for (let i = 0; i < size; i += 1) {
    const mapped = `${getItem(i)}`;
    items.push(mapped);
    messageSize += mapped.length;
    if ((messageSize > 200 || i >= 16) && i + 1 < size) {
      items.push(gray(' ... '));
      break;
    }
  }
  if (items.length === 0) return black('[]');
  return `${black('[')} ${items.join(black(', '))} ${black(']')}`;
}

function visualObject(value: NativePointer, type?: string): string {
  // ? do not ask, i have no idea why this prevents crashes
  // String(value) + String(value.readByteArray(8));

  try {
    if (type === ClassesString.String || type === ClassesString.CharSequence) {
      const str = Java.cast(value, Classes.CharSequence);
      return Color.string(str);
    }

    if (type === ClassesString.InputDevice) {
      const dev = Java.cast(value, Classes.InputDevice);
      return `${ClassesString.InputDevice}(name=${dev.getName()})`;
    }

    if (type === ClassesString.OpenSSLX509Certificate || type === ClassesString.X509Certificate) {
      const win = Java.cast(value, Classes.X509Certificate);
      return `${ClassesString.X509Certificate}(issuer=${win.getIssuerX500Principal()})`;
    }
    if (type === ClassesString.OpenSSLX509Certificate) {
      const win = Java.cast(value, Classes.OpenSSLX509Certificate);
      return `${ClassesString.OpenSSLX509Certificate}(issuer=${win.getIssuerX500Principal()})`;
    }

    if (type === ClassesString.Certificate) {
      const win = Java.cast(value, Classes.Certificate);
      return `${ClassesString.Certificate}(issuer=${win.getType()})`;
    }

    if (type === ClassesString.WindowInsets) {
      const win = Java.cast(value, Classes.WindowInsets);
      return `${ClassesString.WindowInsets}(frame=${win.getFrame()})`;
    }

    const object = Java.cast(value, Classes.Object);
    // hardcoded classes which cause issues cause reasons ?
    if (object.$className === 'android.graphics.Matrix') {
      return `kilme`;
    }
    //@ts-ignore
    const strObj = Classes.String.valueOf.overload(ClassesString.Object).bind(Classes.String);
    return strObj(object);
  } catch (e: any) {
    return black(
      `${e.message} ${black('<')}${dim(`${value}`)}${black('>')}${black(`${typeof value}:${type}`)}`,
    );
  }
}

export { visualObject, vs };
