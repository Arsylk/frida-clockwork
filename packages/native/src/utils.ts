import Java from 'frida-java-bridge';
import { ProcMaps } from '@clockwork/cmodules';
import { Libc, Consts } from '@clockwork/common';
import { Text } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
const { gray, black } = Color.use();

function dellocate(ptr: NativePointer) {
    try {
        const env = Java.vm.tryGetEnv();
        env?.ReleaseStringUTFChars(ptr);
    } catch (_) {}
}

function asExportedObject(module: Module) {
    return Object.fromEntries(
        module.enumerateExports().map(({name, address}) => [name, address])
    )
}

function mkdir(path: string): boolean {
    const cPath = Memory.allocUtf8String(path);
    const dir = Libc.opendir(cPath);
    if (!dir.isNull()) {
        Libc.closedir(dir);
        return false;
    }
    Libc.mkdir(cPath, 0o755);
    Libc.chmod(cPath, 0o755);
    dellocate(cPath);

    return true;
}

function getSelfProcessName(): string | null {
    const cached = Reflect.get(globalThis, 'packageName');
    if (cached) return cached;

    const filename = Memory.allocUtf8String('/proc/self/cmdline');
    const mode = Memory.allocUtf8String('r');
    const { value: file } = Libc.fopen(filename, mode);

    if (!file.isNull()) {
        const buffer = Memory.alloc(256);
        const bytesRead = Libc.fread(buffer, 1, 255, file);
        Libc.fclose(file);

        if (bytesRead > 0) {
            const value = buffer.readCString(bytesRead)?.replace(/�/gi, '') ?? null;
            if (value && value.length > 0) {
                Reflect.set(globalThis, 'packageName', value);
                return value;
            }
        }
    }
    return null;
}

function getSelfFiles(): string {
    const process_name = getSelfProcessName();
    const files_dir = `/data/data/${process_name}/files`;
    mkdir(files_dir);
    return files_dir;
}

Object.defineProperties(addressOf, {
    transform: {
        writable: true,
        value: (ptr: NativePointer) => ptr,
    },
});

function addressOf(ptr: NativePointer, extended?: boolean) {
    if (!ptr || ptr === NULL || `${ptr}` === '0x0') return;
    const str = `${ProcMaps.addressOf(ptr)}`;
    return extended === true ? `${str} ${DebugSymbol.fromAddress(ptr)}` : str;

    const surround = (str: any) => `${black('⟨')}${str}${black('⟩')}`;
    const debug = DebugSymbol.fromAddress(ptr);
    ptr = (addressOf as any).transform(ptr);

    if (debug.moduleName) {
        const rel = debug.name ?? `0x${ptr.toString(16)}`;
        return surround(`${debug.moduleName}${gray('!')}${rel} ${extended ? `0x${ptr.toString(16)}` : ''}`);
    }
    return surround(`0x${ptr.toString(16)}`);
    // for (const { base, name, size } of Inject.modules.values()) {
    //     if (ptr > base && ptr < base.add(size) && !name.endsWith('.oat')) {
    //         return surround(`${name}${gray('!')}0x${ptr.sub(base).toString(16)} 0x${ptr.toString(16)}`)
    //     }
    // }
    // return surround(`0x${ptr.toString(16)}`)
}

function chmod(path: string): void {
    const cPath = Memory.allocUtf8String(path);
    Libc.chmod(cPath, 755);
    dellocate(cPath);
}

function mkdirs(base_path: string, file_path: string): void {
    const dir_array = file_path.split('/');
    let path = base_path;
    for (const segment of dir_array) {
        mkdir(path);
        path += `/${segment}`;
    }
}

function dumpFile(stringPtr: NativePointer, size: number, relativePath: string, tag: string): boolean {
    const process_name = getSelfProcessName();
    const filesDir = `/data/data/${process_name}/files`;
    mkdir(filesDir);

    const dexDir = `${filesDir}/dump_${tag}_${process_name}`;
    mkdir(dexDir);

    const fullpath = `${dexDir}/${relativePath}`;
    // Memory.protect(stringPtr, size, 'rw');
    const buffer = stringPtr.readCString(size);
    if (!buffer) {
        return false;
    }

    mkdirs(dexDir, relativePath);
    //@ts-ignore issue with File from esnext 5.4
    const file: any = new File(fullpath, 'w');
    file.write(buffer);
    file.close();
    return true;
}

function readFdPath(fd: number, bufsize: number = Consts.PATH_MAX): string | null {
    const buf = Memory.alloc(bufsize);
    const path = Memory.allocUtf8String(`/proc/self/fd/${fd}`);

    const _ = Libc.readlinkat(0, path, buf, bufsize);
    const str = buf.readCString();
    dellocate(buf);
    dellocate(path);
    return str;
}

function readFpPath(fp: NativePointer): string | null {
    const { value: fd } = Libc.fileno(fp) as UnixSystemFunctionResult<number>;
    if (fd !== -1) {
        return readFdPath(fd);
    }
    return null;
}

function readTidName(tid: number): string {
    if (!tid || tid <= 0) return '';
    const fd = Libc.syscall_openat(
        56,
        0,
        Memory.allocUtf8String(`/proc/self/task/${tid}/comm`),
        'r'.charCodeAt(0),
    );
    if (fd !== -1) {
        const buffer = Memory.alloc(16);
        Libc.read(fd, buffer, 16);
        const str = buffer.readCString();
        dellocate(buffer);
        return Text.noLines(str);
    }
    return '';
    // this seems unstable when hooking other things
    // return File.readAllText(`/proc/self/task/${tid}/comm`);
}

function getEnumerated(module: Module, symbol: string) {
    for (const e of module.enumerateExports()) {
        if (e.name === symbol) {
            return e.address
        }
    }
    for (const s of module.enumerateSymbols()) {
        if (s.name === symbol) {
            return s.address
        }
    }
    return NULL
}


function tryDemangle<T extends string | null>(name: T): T {
    if (!name) return name;
    try {
        if (!Libc.__cxa_demangle) {
            throw Error('__cxa_demangle not found');
        }
        const str = Memory.allocUtf8String(name);
        const len = Memory.alloc(4).writeUInt(name.length);
        const buf = Libc.__cxa_demangle(str, NULL, len, NULL);
        dellocate(str);
        const demangled = buf.readCString();
        dellocate(buf);
        if (demangled && demangled.length > 0) return demangled as T;
    } catch (e) {}
    return name;
}

const sscanf = new NativeFunction(Module.getGlobalExportByName('sscanf'), 'int', [
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
]);
function tryResolveMapsSymbol(loc: NativePointer, pid: number = Process.id): DebugSymbol | null {
    try {
        const path = Memory.allocUtf8String(`/proc/${pid}/maps`);
        const mode = Memory.allocUtf8String('r');
        const fd = Libc.fopen(path, mode);
        dellocate(path);
        dellocate(mode);
        if (!fd.value.isNull()) {
            let nread: NativePointer;
            const size = 0x1000;
            const linePtr = Memory.alloc(size);
            const [begin, end] = [Memory.alloc(12), Memory.alloc(12)];
            const [perm, foo, dev, inode, mapname] = [
                Memory.alloc(12),
                Memory.alloc(12),
                Memory.alloc(Process.pointerSize),
                Memory.alloc(Process.pointerSize),
                Memory.alloc(size),
            ];

            const template = Memory.allocUtf8String('%lx-%lx %s %lx %s %ld %s');
            while ((nread = Libc.fgets(linePtr, size, fd.value))) {
                const read = sscanf(linePtr, template, begin, end, perm, foo, dev, inode, mapname);
                logger.info({ tag: 'mapres' }, `${linePtr.readCString()} ${read}`);
            }
            dellocate(template);

            Libc.fclose(fd.value);
        }
    } catch (e) {
        console.error(`${e}`);
    }
    return null;
}

export {
    addressOf,
    dellocate,
    dumpFile,
    getSelfFiles,
    getSelfProcessName,
    mkdir,
    readFdPath,
    readFpPath,
    readTidName,
    tryDemangle,
    asExportedObject,
    getEnumerated
};
