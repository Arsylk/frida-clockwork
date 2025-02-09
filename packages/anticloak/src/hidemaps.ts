import { Linker, isNully, Text } from '@clockwork/common';

function hiddenSobaseInMem(so_path: string) {
    //  /apex/com.android.runtime/lib64/bionic/libc.so
    const parts = so_path.split('/');
    const so_name = `${parts.pop()}`;

    const soExecSegmentFromFile = findSoExecSegmentFromFile(so_path);
    if (!soExecSegmentFromFile) {
        console.log('missing soExecSegmentFromFile');
        return;
    }
    const soRangeFromMaps = findSoRangeFromMaps(so_name);
    const startAddress = soRangeFromMaps.base;
    const size = soRangeFromMaps.size;
    console.log(startAddress, size);

    const new_addr = Libc.mmap(ptr(-1), size, 7, 0x20 | 2, -1, 0);
    console.log('创建的匿名内存起始地址:' + new_addr);

    Memory.copy(new_addr, startAddress, size);
    console.log('复制完毕');

    Memory.copy(
        new_addr.add(soExecSegmentFromFile.p_offset),
        soExecSegmentFromFile.start,
        soExecSegmentFromFile.size,
    );
    console.log('真实节区复制成功');

    //从linker中获取到soinfo结构链表
    const solist = Linker.getSoListHead();
    let soinfo_next = solist;

    let num = 0;
    console.log('开始遍历');
    do {
        const soptr = soinfo_next.ptr ?? NULL;
        const realpath = solist.getRealpath(); //获取soinfo所属的名字
        console.log(num++ + '-->' + realpath);

        if (realpath.includes(so_name)) {
            Memory.protect(soptr.add(Process.pointerSize * 2), 4, 'rw');
            soptr.add(Process.pointerSize * 2).writePointer(new_addr); //so base

            Memory.protect(soptr.add(Process.pointerSize * 26), 4, 'rw');
            soptr.add(Process.pointerSize * 26).writePointer(new_addr); //linker map

            //load_bias 没法直接修改 否则会因为找不到符号崩溃
            break;
        }
        soinfo_next = soinfo_next.getNext() as any;
    } while (soinfo_next);
    console.log('遍历完成:');
    console.log('内存中隐藏so首地址完成');
}

function hiddenSectionInMem(so_path: string) {
    //  /apex/com.android.runtime/lib64/bionic/libc.so

    const parts = so_path.split('/');
    const so_name = `${parts.pop()}`;

    const soSectionFromFile: any = findSoSectionFromFile(so_path);
    if (!soSectionFromFile) {
        console.log('missing soSectionFromFile ');
        return;
    }
    const soExecSegmentFromFile = findSoExecSegmentFromFile(so_path);
    if (!soExecSegmentFromFile) {
        console.log('missing soExecSegmentFromFile');
        return;
    }

    //获取maps中so的内存
    const soRangeFromMaps: { base: NativePointer; size: number } = findSoRangeFromMaps(so_name);
    const startAddress = soRangeFromMaps.base;
    const size = soRangeFromMaps.size;

    //创建匿名内存,存储so内存区域的内存
    const new_addr = Libc.mmap(ptr(-1), size, 7, 0x20 | 2, -1, 0);
    console.log('创建的匿名内存起始地址:' + new_addr + ' size: ' + size);

    //把maps中so内存区域的内存复制到创建的匿名内存中去
    Memory.copy(new_addr, startAddress, size);
    console.log('复制完毕');

    //把文件中的可执行段复制到匿名内存中去
    Memory.copy(
        new_addr.add(soExecSegmentFromFile.p_offset),
        soExecSegmentFromFile.start,
        soExecSegmentFromFile.size,
    );
    console.log('真实节区复制成功');

    //从linker中获取到soinfo结构链表
    const solist = Linker.getSoListHead();
    let soinfo_next = solist;

    let strtab_addr = NULL;
    let symtab_addr = NULL;
    let dynamic_addr = NULL;

    console.log('开始遍历');
    let num = 0;
    do {
        const soptr = soinfo_next.ptr ?? NULL;
        const realpath = soinfo_next.getRealpath(); //获取soinfo所属的名字
        console.log(num++ + '-->' + realpath);

        if (realpath?.includes(so_name)) {
            dynamic_addr = soptr.add(Process.pointerSize * 4).readPointer(); //dynamic
            strtab_addr = soptr.add(Process.pointerSize * 7).readPointer(); //strtab_
            symtab_addr = soptr.add(Process.pointerSize * 8).readPointer(); //symtab_

            Memory.protect(soptr.add(Process.pointerSize * 4), 4, 'rw');
            soptr.add(Process.pointerSize * 4).writePointer(new_addr.add(soSectionFromFile.dynamic.offset)); //dynamic 模拟
            Memory.protect(soptr.add(Process.pointerSize * 7), 4, 'rw');
            soptr.add(Process.pointerSize * 7).writePointer(new_addr.add(soSectionFromFile.dynstr.offset)); //strtab_ 模拟
            Memory.protect(soptr.add(Process.pointerSize * 8), 4, 'rw');
            soptr.add(Process.pointerSize * 8).writePointer(new_addr.add(soSectionFromFile.dynsym.offset)); //symtab_ 模拟

            break;
        }
        soinfo_next = soinfo_next.getNext() as any;
    } while (soinfo_next);
    console.log('遍历完成:');
    console.log('内存中隐藏节表地址完成');
}

function hiddenSoExecSegmentInMaps(so_path: string) {
    //      /apex/com.android.runtime/lib64/bionic/libc.so
    const parts = so_path.split('/');
    const so_name = `${parts.pop()}`;

    const soExecSegmentRangeFromMaps = findSoExecSegmentRangeFromMaps(so_name);
    const startAddress = soExecSegmentRangeFromMaps.base;
    const size = soExecSegmentRangeFromMaps.size;

    if (isNully(startAddress) || size === 0) {
        console.log('可执行段未找到:', startAddress, size);
        return;
    }

    const soExecSegmentFromFile = findSoExecSegmentFromFile(so_path);
    if (!soExecSegmentFromFile) {
        console.log('missing soExecSegmentFromFile');
        return;
    }

    //创建匿名内存,临时存储so可执行段内存
    const new_addr = Libc.mmap(ptr(-1), size, 7, 0x20 | 2, -1, 0); //0x20:匿名内存标识符(MAP_ANONYMOUS), 2:私有(MAP_PRIVATE)
    console.log('创建的可执行段匿名内存起始地址:' + new_addr);

    //把so可执行段内存复制到创建的匿名内存中去
    Memory.copy(new_addr, startAddress, size);
    console.log('复制完毕');

    //调整so,使传入的so可执行段内存变成匿名内存
    const ret = Libc.mremap(new_addr, size, size, 1 | 2, startAddress);
    console.log('mremap:', ret);
    if (ret === ptr(-1) /* impossible ? */) {
        console.log('mremap  调整失败');
        return;
    }
    console.log('匿名目标so可执行段完成 ret:' + ret);

    // 打开需要模拟的文件路径，用于后续在maps中生成指定名称的内存区域
    const moniter_path = so_path;
    const moniter_path_addr = Memory.allocUtf8String(moniter_path);
    const fd = Libc.open(moniter_path_addr, 0).value;
    if (fd === -1) {
        console.log('open ' + moniter_path + ' is error');
        return -1;
    }

    //在maps中创建传入so路径名称的内存区域
    const target_addr = Libc.mmap(ptr(-1), size, 7, 2, fd, 0);
    console.log('address of simulated executable segment memory: ' + target_addr + ' size: ' + size);

    Libc.close(fd);

    //给创建的so内存区域全部置0
    Libc.memset(target_addr, 0, size);

    //把so文件中获取的可执行段内存复制到创建的so名称的内存区域中
    Memory.copy(target_addr, soExecSegmentFromFile.start, soExecSegmentFromFile.size);
    Memory.protect(target_addr, size, 'r-x');

    //卸载映射的匿名内存
    // Libc.munmap(addr, size);
    console.log('hiding executable segments in maps');
}

function hiddenSoInMaps(so_name: string) {
    const soRangeFromMaps = findSoRangeFromMaps(so_name);
    const startAddress = soRangeFromMaps.base;
    const size = soRangeFromMaps.size;
    console.log('soname:' + so_name, startAddress, size);
    if (isNully(startAddress) || size === 0) {
        console.log("can't hide so", 'startAddress:' + startAddress, 'size:' + size);
        return;
    }

    //创建匿名内存,临时存储so内存
    // let null_ptr = Memory.alloc(Process.pointerSize);//创建空指针
    const new_addr = Libc.mmap(ptr(-1), size, 7, 0x20 | 2, -1, 0);
    console.log('address of annonymous memory: ' + new_addr + ' size: ' + size);

    //把so内存复制到创建的匿名内存中去
    Memory.copy(new_addr, startAddress, size);
    console.log('copy complete');

    //调整so,使传入的so变成匿名内存名称
    const ret = Libc.mremap(new_addr, size, size, 1 | 2, startAddress);
    if (ret === ptr(-1) /* impossible ? **/) {
        console.log('mremap failed');
        return;
    }
    console.log(`anonymous so complete: ret: ${ret} size: ${size}`);

    //卸载映射的匿名内存
    Libc.munmap(new_addr, size);
}

function findSoSectionFromFile(so_path: string) {
    //      /apex/com.android.runtime/lib64/bionic/libc.so
    const path_addr = Memory.allocUtf8String(so_path);
    const fd = Libc.open(path_addr, 0).value;
    if (fd === -1) {
        console.log('openFunc is error');
        return null;
    }

    // 读取 ELF 头
    const ehdr = Memory.alloc(64);
    const readRet = Libc.read(fd, ehdr, 64);
    if (readRet <= 0) {
        console.log('readFunc readRet:' + readRet);
        Libc.close(fd);
        return null;
    }

    const e_shoff = ehdr.add(40).readPointer(); //节头表偏移
    console.log('e_shoff:' + e_shoff);

    const shstrtab_index = ehdr.add(62).readS16(); //存储所有节表名称的节表在节头表中的索引
    console.log('shstrtab_index:' + shstrtab_index);

    //获取节头表表项数量
    const e_shnum = ehdr.add(60).readU16();
    console.log('e_shnum:' + e_shnum);

    // 定位节头表
    Libc.lseek(fd, e_shoff, 0);

    //创建shdr
    const shdr = Memory.alloc(0x40);

    //从文件中获取shstrtab
    let s = Libc.pread(fd, shdr, 0x40, Number(e_shoff.add(shstrtab_index * 0x40)));
    if (s !== 0x40) {
        console.log('获取shstrtab error:' + s);
        return null;
    }

    //获取shstrtab节中的偏移和大小
    const shstrtab_offset = shdr.add(24).readPointer();
    const shstrtab_size = shdr.add(32).readPointer().toInt32();
    console.log('shstrtab_offset:' + shstrtab_offset, 'shstrtab_size:' + shstrtab_size);

    //文件中获取的shstrtab赋值变量shstrtab
    const shstrtab = Memory.alloc(shstrtab_size);
    s = Libc.pread(fd, shstrtab, shstrtab_size, Number(shstrtab_offset));
    if (s !== shstrtab_size) {
        console.log('shstrtab error');
        return -1;
    }
    console.log('提取shstrtab完成');

    // 遍历节头
    const section: { dynstr?: any; dynsym?: any; dynamic?: any } = {};
    for (let i = 0; i < e_shnum; i++) {
        const s = Libc.read(fd, shdr, 0x40);
        if (s !== 0x40) break;
        const s_name_off = shdr.readU32(); //节表名字在shstrtab中的偏移
        const s_offset = shdr.add(24).readPointer(); //节表偏移
        const s_size = shdr.add(32).readU64(); //节表大小
        const s_name = shstrtab.add(s_name_off).readCString(); //节表名称
        console.log('[' + s_name + ']\t\ts_offset:' + s_offset + '\ts_size:' + s_size);

        type keyType = 'dynstr' | 'dynsym' | 'dynamic';
        if (s_name === '.dynstr') {
            const dynstr: { [key: string]: NativePointer | number } = {};
            dynstr.offset = s_offset;
            dynstr.size = Number(s_size);
            section.dynstr = dynstr;
        } else if (s_name === '.dynsym') {
            const dynsym: { [key: string]: NativePointer | number } = {};
            dynsym.offset = s_offset;
            dynsym.size = Number(s_size);
            section.dynsym = dynsym;
        } else if (s_name === '.dynamic') {
            const dynamic: { [key: string]: NativePointer | number } = {};
            dynamic.offset = s_offset;
            dynamic.size = Number(s_size);
            section.dynamic = dynamic;
        }
    }
    console.log(Text.stringify(section));
    if (section !== null) {
        return section;
    }
    return null;
}

function findSoRangeFromMaps(so_name: string): { base: NativePointer; size: number } {
    let startAddress = NULL;
    let endAddress = NULL;
    const file = Libc.fopen(Memory.allocUtf8String('/proc/self/maps'), Memory.allocUtf8String('r')).value;
    const line = Memory.alloc(1024);
    let num = 1;
    while (!isNully(Libc.fgets(line, 1024, file))) {
        const lineStr = line.readCString();
        if (lineStr?.includes(so_name) && lineStr?.includes('r--p')) {
            // console.log(line.readCString())
            const match = lineStr?.match(/^([0-9a-f]+)-([0-9a-f]+)/);
            if (match) {
                if (num === 1) {
                    startAddress = ptr(match[1]);
                    endAddress = ptr(match[2]);
                    console.log('start at:', startAddress);
                    num += 1;
                } else {
                    endAddress = ptr(match[2]);
                }
            }
        }
    }
    Libc.fclose(file);
    // console.log(startAddress, endAddress);
    const size = endAddress.sub(startAddress);
    return { base: startAddress, size: Number(size) };
}

function findSoExecSegmentRangeFromMaps(so_name: string): { base: NativePointer; size: number } {
    let startAddress = NULL;
    let endAddress = NULL;
    const file = Libc.fopen(Memory.allocUtf8String('/proc/self/maps'), Memory.allocUtf8String('r')).value;
    const line = Memory.alloc(1024);
    let num = 1;
    while (!isNully(Libc.fgets(line, 1024, file))) {
        const lineStr = line.readCString();
        if (lineStr?.includes(so_name) && lineStr?.includes('-xp')) {
            // console.log(line.readCString())
            const match = lineStr.match(/^([0-9a-f]+)-([0-9a-f]+)/);
            if (match) {
                if (num === 1) {
                    startAddress = ptr(match[1]);
                    endAddress = ptr(match[2]);
                    num += 1;
                } else {
                    endAddress = ptr(match[2]);
                }
            }
        }
    }
    Libc.fclose(file);
    // console.log(startAddress, endAddress);
    const size = endAddress.sub(startAddress);
    return { base: startAddress, size: Number(size) };
}

function findSoExecSegmentFromFile(so_path: string): {
    start: NativePointer;
    size: number;
    p_offset: NativePointer;
} | null {
    //  /apex/com.android.runtime/lib64/bionic/libc.so
    const path_addr = Memory.allocUtf8String(so_path);
    const fd = Libc.open(path_addr, 0).value;
    console.log('openFunc fd:' + fd);
    if (ptr(fd).toUInt32() === -1) {
        console.log('openFunc is error');
        return null;
    }

    // 读取 ELF 头
    const buf = Memory.alloc(64);
    const readRet = Libc.read(fd, buf, 64);
    if (readRet <= 0) {
        console.log('readFunc readRet:' + readRet);
        Libc.close(fd);
        return null;
    }

    const e_phoff = buf.add(32).readPointer();
    console.log('e_phoff:' + e_phoff);

    // 定位程序头表
    Libc.lseek(fd, e_phoff, 0);

    //获取程序头表表项数量
    const e_phnum = buf.add(56).readU16();
    console.log('e_phnum:' + e_phnum);

    //创建phdr
    const phdr = Memory.alloc(0x38);

    // 遍历程序头
    for (let i = 0; i < e_phnum; i++) {
        const s = Libc.read(fd, phdr, 0x38);
        if (s !== 0x38) break;
        const p_type = phdr.readU32();
        const p_flags = phdr.add(4).readU32();
        if (p_type === 1 && p_flags & 1) {
            //PT_LOAD PF_X 寻找可执行段
            const p_filesz = phdr.add(32).readU64();
            const p_offset = phdr.add(8).readPointer();
            Libc.lseek(fd, p_offset, 0);
            const size = p_filesz;
            console.log('size in loop:', size, p_offset);
            if (Number(size) === -1 || Number(p_offset) === 0) continue;
            const start = Memory.alloc(p_filesz);
            Libc.read(fd, start, size);
            Libc.close(fd);
            return { start: start, size: Number(size), p_offset: p_offset };
        }
    }
    return null;
}

function hide(target: string) {
    const name = `${target.split('/').pop()}`;
    hiddenSoExecSegmentInMaps(target);
    // hiddenSobaseInMem(target);
    // hiddenSectionInMem(target);
    // hiddenSoInMaps(name);
}

export { hide };
