import { Libc } from '@clockwork/common';

function dellocate(ptr: NativePointer) {
    try {
        const env = Java.vm.tryGetEnv();
        env?.ReleaseStringUTFChars(ptr);
    } catch (_) {}
}

function mkdir(path: string): boolean {
    const cPath = Memory.allocUtf8String(path);
    const dir = Libc.opendir(cPath);
    if (!dir.isNull()) {
        Libc.closedir(dir);
        return false;
    }
    Libc.mkdir(cPath, 755);
    Libc.chmod(cPath, 755);
    dellocate(cPath);

    return true;
}

function getSelfProcessName(): string | null {
    const path = Memory.allocUtf8String('/proc/self/cmdline');
    const fd = Libc.open(path, 0);
    dellocate(path);
    if (fd !== -1) {
        const buffer = Memory.alloc(0x1000);
        Libc.read(fd, buffer, 0x1000);
        Libc.close(fd);
        return buffer.readCString();
    }
    return null;
}

function getSelfFiles(): string {
    const process_name = getSelfProcessName();
    const files_dir = '/data/data/' + process_name + '/files';
    mkdir(files_dir);
    return files_dir;
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

export { dellocate, getSelfProcessName, getSelfFiles, dumpFile };
