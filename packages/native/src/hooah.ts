import { Inject } from './inject.js';
module Utils {
    const callMnemonics = ['call', 'bl', 'blx', 'blr', 'bx'];
    export const insertAt = (str: string, sub: string, pos: number) => `${str.slice(0, pos)}${sub}${str.slice(pos)}`;

    export function ba2hex(b: ArrayBuffer): string {
        let uint8arr = new Uint8Array(b);
        if (!uint8arr) {
            return '';
        }
        let hexStr = '';
        for (let i = 0; i < uint8arr.length; i++) {
            let hex = (uint8arr[i] & 0xff).toString(16);
            hex = hex.length === 1 ? '0' + hex : hex;
            hexStr += hex;
        }
        return hexStr;
    }

    export function getSpacer(space: number): string {
        if (space < 0) return '';
        return ' '.repeat(space);
    }

    export function isCallInstruction(instruction: Instruction): boolean {
        return callMnemonics.indexOf(instruction.mnemonic) >= 0;
    }

    export function isJumpInstruction(instruction: Instruction): boolean {
        return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
    }

    export function isRetInstruction(instuction: Instruction): boolean {
        return instuction.groups.indexOf('return') >= 0;
    }
}

module Color {
    const _red = '\x1b[0;31m';
    const _green = '\x1b[0;32m';
    const _yellow = '\x1b[0;33m';
    const _blue = '\x1b[0;34m';
    const _pink = '\x1b[0;35m';
    const _cyan = '\x1b[0;36m';
    const _bold = '\x1b[0;1m';
    const _highlight = '\x1b[0;3m';
    const _highlight_off = '\x1b[0;23m';
    const _resetColor = '\x1b[0m';

    export function applyColorFilters(text: string): string {
        text = text.toString();
        text = text.replace(/(\W|^)([a-z]{1,4}\d{0,2})(\W|$)/gm, '$1' + colorify('$2', 'blue') + '$3');
        text = text.replace(/(0x[0123456789abcdef]+)/gm, colorify('$1', 'red'));
        text = text.replace(/#(\d+)/gm, '#' + colorify('$1', 'red'));
        return text;
    }

    export function colorify(what: string, pat: string): string {
        if (pat === 'filter') {
            return applyColorFilters(what);
        }
        let ret = '';
        if (pat.indexOf('red') >= 0) {
            ret += _red;
        } else if (pat.indexOf('green') >= 0) {
            ret += _green;
        } else if (pat.indexOf('yellow') >= 0) {
            ret += _yellow;
        } else if (pat.indexOf('blue') >= 0) {
            ret += _blue;
        } else if (pat.indexOf('pink') >= 0) {
            ret += _pink;
        } else if (pat.indexOf('cyan') >= 0) {
            ret += _cyan;
        }
        if (pat.indexOf('bold') >= 0) {
            ret += _bold;
        } else if (pat.indexOf('highlight') >= 0) {
            ret += _highlight;
        }

        ret += what;
        if (pat.indexOf('highlight') >= 0) {
            ret += _highlight_off;
        }
        ret += _resetColor;
        return ret;
    }
}

export module HooahTrace {
    const getSpacer = Utils.getSpacer;

    interface AnyCpuContext extends PortableCpuContext {
        [name: string]: NativePointer;
    }

    interface HooahPrintOptions {
        colored?: boolean;
        details?: boolean;
        treeSpaces?: number;
    }

    interface HooahOptions {
        printBlocks?: boolean;
        count?: number;
        filterModules?: string[];
        instructions?: string[];
        printOptions?: HooahPrintOptions;
    }

    interface PrintInfo {
        data: string;
        lineLength: number;
        details?: PrintInfo[];
        postDetails?: PrintInfo[];
    }

    interface RegisterInfo {
        reg: string;
        value: NativePointer;
    }

    type HooahCallback = (context: CpuContext, instruction: Instruction) => void;

    const treeTrace: NativePointer[] = [];
    let targetTid = 0;
    let onInstructionCallback: HooahCallback | null = null;
    let moduleMap = new ModuleMap();
    let filtersModuleMap: ModuleMap | null = null;

    const currentExecutionBlockStackRegisters: RegisterInfo[] = [];
    const currentExecutionBlock: PrintInfo[] = [];
    let currentBlockStartWidth = 0;
    let currentBlockMaxWidth = 0;
    let hitRetInstruction = false;

    let sessionPrintBlocks = true;
    let sessionPrintOptions: HooahPrintOptions;
    let sessionPrevSepCount = 0;

    export function trace(params: HooahOptions = {}, callback: HooahCallback | undefined) {
        if (targetTid > 0) {
            console.log('Hooah is already tracing thread: ' + targetTid);
            return 1;
        }

        if (targetTid > 0) {
            console.log('Hooah is already tracing thread: ' + targetTid);
            return;
        }

        const { printBlocks = true, count = -1, filterModules = [], instructions = [], printOptions = {} } = params;
        sessionPrintBlocks = printBlocks;
        sessionPrintOptions = printOptions;
        if (sessionPrintOptions.treeSpaces && sessionPrintOptions.treeSpaces < 4) {
            sessionPrintOptions.treeSpaces = 4;
        }

        targetTid = Process.getCurrentThreadId();
        if (callback) {
            onInstructionCallback = callback;
        } else {
            onInstructionCallback = null;
        }

        moduleMap.update();
        filtersModuleMap = new ModuleMap((module) => {
            // do not follow frida agent
            if (module.name.includes('frida-agent') || module.name.includes('hluda-agent')) {
                return true;
            }

            let found = false;
            filterModules.forEach((filter) => {
                if (module.name.indexOf(filter) >= 0) {
                    found = true;
                }
            });
            return found;
        });

        Inject.afterInitArray(() => {
            moduleMap.update();
            if (filtersModuleMap) {
                filtersModuleMap.update();
            }
        });

        let instructionsCount = 0;
        let startAddress = NULL;

        Stalker.follow(targetTid, {
            transform: function (iterator: StalkerArm64Iterator | StalkerX86Iterator) {
                let instruction: Arm64Instruction | X86Instruction | null;
                let moduleFilterLocker = false;

                while ((instruction = iterator.next()) !== null) {
                    currentExecutionBlockStackRegisters.length = 0;

                    if (moduleFilterLocker) {
                        iterator.keep();
                        continue;
                    }

                    if (filtersModuleMap && filtersModuleMap.has(instruction.address)) {
                        moduleFilterLocker = true;
                    }

                    if (!moduleFilterLocker) {
                        // basically skip the first block of code (from frida)
                        if (startAddress.compare(NULL) === 0) {
                            startAddress = instruction.address;
                            moduleFilterLocker = true;
                        } else {
                            if (instructions.length > 0 && instructions.indexOf(instruction.mnemonic) < 0) {
                                iterator.keep();
                                continue;
                            }

                            iterator.putCallout(<(context: PortableCpuContext) => void>(onHitInstruction as any));
                        }
                    }

                    if (count > 0) {
                        instructionsCount++;
                        if (instructionsCount === count) {
                            stop();
                        }
                    }

                    iterator.keep();
                }
            },
        });

        return 0;
    }

    export function stop(): void {
        Stalker.unfollow(targetTid);
        filtersModuleMap = null;
        onInstructionCallback = null;
        treeTrace.length = 0;
        targetTid = 0;

        currentExecutionBlockStackRegisters.length = 0;
        currentExecutionBlock.length = 0;
        currentBlockMaxWidth = 0;

        sessionPrevSepCount = 0;
    }

    function onHitInstruction(context: AnyCpuContext): void {
        const address = context.pc;
        const instruction: Instruction = Instruction.parse(address);
        const treeTraceLength = treeTrace.length;

        if (onInstructionCallback !== null) {
            if (hitRetInstruction) {
                hitRetInstruction = false;
                if (treeTraceLength > 0) {
                    treeTrace.pop();
                }
            }

            onInstructionCallback.apply({}, [context, instruction]);

            if (sessionPrintBlocks) {
                const { details = false, colored = false, treeSpaces = 4 } = sessionPrintOptions;

                const isCall = Utils.isCallInstruction(instruction);
                const isJump = Utils.isJumpInstruction(instruction);
                const isRet = Utils.isRetInstruction(instruction);

                const printInfo = formatInstruction(context, address, instruction, details, colored, treeSpaces, isJump);
                currentExecutionBlock.push(printInfo);

                if (isJump || isRet) {
                    if (currentExecutionBlock.length > 0) {
                        blockifyBlock(details);
                    }
                    currentExecutionBlock.length = 0;
                    currentBlockMaxWidth = 0;
                }

                if (isCall) {
                    treeTrace.push(instruction.next);
                } else if (isRet) {
                    hitRetInstruction = true;
                }
            }
        }
    }

    function blockifyBlock(details: boolean): void {
        const divMod = currentBlockMaxWidth % 8;
        if (divMod !== 0) {
            currentBlockMaxWidth -= divMod;
            currentBlockMaxWidth += 8;
        }
        const realLineWidth = currentBlockMaxWidth - currentBlockStartWidth;
        const startSpacer = Utils.getSpacer(currentBlockStartWidth + 1);
        let sepCount = (realLineWidth + 8) / 4;
        const topSep = ' _'.repeat(sepCount).substring(1);
        const botSep = ' \u00AF'.repeat(sepCount).substring(1);
        const nextSepCount = currentBlockStartWidth + 1 + botSep.length;
        const emptyLine = formatLine({ data: ' '.repeat(currentBlockMaxWidth), lineLength: currentBlockMaxWidth });
        let topMid = ' ';
        if (sessionPrevSepCount > 0) {
            topMid = '|';
            const sepDiff = sessionPrevSepCount - nextSepCount;
            if (sepDiff < 0) {
                const spacer = Utils.getSpacer(sessionPrevSepCount);
                if (details) {
                    console.log(spacer + '|');
                }
                console.log(spacer + '|' + '_ '.repeat(-sepDiff / 2));
                console.log(spacer + Utils.getSpacer(-sepDiff) + '|');
            } else if (sepDiff > 0) {
                const spacer = Utils.getSpacer(nextSepCount);
                console.log(spacer + '|' + '\u00AF '.repeat(sepDiff / 2));
                if (details) {
                    console.log(spacer + '|');
                }
            }
        }
        console.log(startSpacer + topSep + topMid + topSep);
        currentExecutionBlock.forEach((printInfo) => {
            if (details && printInfo.details) {
                console.log(emptyLine);
                printInfo.details.forEach((detailPrintInfo) => {
                    console.log(formatLine(detailPrintInfo));
                });
            }
            console.log(formatLine(printInfo));
            if (details) {
                if (printInfo.postDetails) {
                    printInfo.postDetails.forEach((postPrintInfo) => {
                        console.log(formatLine(postPrintInfo));
                    });
                }
                console.log(emptyLine);
            }
        });
        console.log(startSpacer + botSep + '|' + botSep);
        sessionPrevSepCount = nextSepCount;
        console.log(Utils.getSpacer(sessionPrevSepCount) + '|');
        if (details) {
            console.log(Utils.getSpacer(sessionPrevSepCount) + '|');
        }
    }

    function formatLine(printInfo: PrintInfo) {
        let toPrint = printInfo.data;
        toPrint = Utils.insertAt(toPrint, '|    ', currentBlockStartWidth);
        toPrint += Utils.getSpacer(currentBlockMaxWidth - printInfo.lineLength);
        toPrint += '    |';
        return toPrint;
    }

    function formatInstruction(
        context: AnyCpuContext,
        address: NativePointer,
        instruction: Instruction,
        details: boolean,
        colored: boolean,
        treeSpaces: number,
        isJump: boolean,
    ): PrintInfo {
        const anyCtx = context as AnyCpuContext;
        let line = '';
        let coloredLine = '';
        let part: string;
        let intTreeSpace = 0;
        let spaceAtOpStr: number;

        const append = function (what: string, color?: string): void {
            line += what;
            if (colored) {
                if (color) {
                    coloredLine += Color.colorify(what, color);
                } else {
                    coloredLine += what;
                }
            }
        };

        const appendModuleInfo = function (address: NativePointer): void {
            const module = moduleMap.find(address);
            if (module !== null) {
                append(' (');
                append(module.name, 'green bold');
                part = '#';
                append(part);
                part = address.sub(module.base).toString();
                append(part, 'red');
                part = ')';
                append(part);
            }
        };

        const addSpace = function (count: number): void {
            append(Utils.getSpacer(count + intTreeSpace - line.length));
        };

        if (treeSpaces > 0 && treeTrace.length > 0) {
            intTreeSpace = treeTrace.length * treeSpaces;
            append(Utils.getSpacer(intTreeSpace));
        }

        currentBlockStartWidth = line.length;
        append(address.toString(), 'red bold');

        appendModuleInfo(address);
        addSpace(40);

        const bytes = instruction.address.readByteArray(instruction.size);
        if (bytes) {
            part = Utils.ba2hex(bytes);
            append(part, 'yellow');
        } else {
            let _fix = '';
            for (let i = 0; i < instruction.size; i++) {
                _fix += '00';
            }
            append(_fix, 'yellow');
        }

        addSpace(50);

        append(instruction.mnemonic, 'green bold');

        addSpace(60);
        spaceAtOpStr = line.length;
        append(instruction.opStr, 'filter');

        if (isJump) {
            try {
                let jumpInsn = getJumpInstruction(instruction, anyCtx);
                if (jumpInsn) {
                    appendModuleInfo(jumpInsn.address);
                }
            } catch (e) {}
        }

        const lineLength = line.length;
        if (lineLength > currentBlockMaxWidth) {
            currentBlockMaxWidth = lineLength;
        }

        let detailsData: PrintInfo[] = [];
        if (details) {
            if (currentExecutionBlockStackRegisters.length > 0) {
                let postLines: PrintInfo[] = [];
                currentExecutionBlockStackRegisters.forEach((reg) => {
                    const contextVal = getRegisterValue(context, reg.reg);
                    if (contextVal && contextVal != reg.value) {
                        const toStr = contextVal.toString();
                        let str = getSpacer(spaceAtOpStr);
                        if (colored) {
                            str += Color.colorify(reg.reg, 'blue bold') + ' = ' + Color.colorify(toStr, 'red');
                        } else {
                            str += reg.reg + ' = ' + toStr;
                        }
                        postLines.push({ data: str, lineLength: spaceAtOpStr + reg.reg.length + toStr.length + 3 });
                    }
                });
                currentExecutionBlockStackRegisters.length = 0;
                if (currentExecutionBlock.length > 0) {
                    currentExecutionBlock[currentExecutionBlock.length - 1].postDetails = postLines;
                }
            }

            detailsData = formatInstructionDetails(spaceAtOpStr, context, instruction, colored, isJump);
            detailsData.forEach((detail) => {
                if (detail.lineLength > currentBlockMaxWidth) {
                    currentBlockMaxWidth = detail.lineLength;
                }
            });
        }

        return { data: colored ? coloredLine : line, lineLength: lineLength, details: detailsData };
    }

    function formatInstructionDetails(
        spaceAtOpStr: number,
        context: AnyCpuContext,
        instruction: Instruction,
        colored: boolean,
        isJump: boolean,
    ): PrintInfo[] {
        const anyContext = context as AnyCpuContext;
        const data: any[] = [];
        const visited: Set<string> = new Set<string>();

        let insn: Arm64Instruction | X86Instruction | null = null;
        if (Process.arch === 'arm64') {
            insn = instruction as Arm64Instruction;
        } else if (Process.arch === 'ia32' || Process.arch === 'x64') {
            insn = instruction as X86Instruction;
        }
        if (insn != null) {
            insn.operands.forEach((op: Arm64Operand | X86Operand) => {
                let reg: Arm64Register | X86Register | undefined;
                let value = null;
                let adds = 0;
                if (op.type === 'mem') {
                    adds = op.value.disp;
                    reg = op.value.base;
                } else if (op.type === 'reg') {
                    reg = op.value;
                }

                if (typeof reg !== 'undefined' && !visited.has(reg)) {
                    visited.add(reg);
                    try {
                        value = getRegisterValue(anyContext, reg);
                        if (typeof value !== 'undefined') {
                            currentExecutionBlockStackRegisters.push({ reg: reg.toString(), value: value });
                            value = getRegisterValue(anyContext, reg);
                            let regLabel = reg.toString();
                            data.push([
                                regLabel,
                                value.toString() + (adds > 0 ? '#' + adds.toString(16) : ''),
                                getTelescope(value.add(adds), colored, isJump),
                            ]);
                        }
                    } catch (e) {}
                }
            });
        }

        const applyColor = function (what: string, color: string | null): string {
            if (colored && color) {
                what = Color.colorify(what, color);
            }
            return what;
        };

        let lines: PrintInfo[] = [];
        data.forEach((row) => {
            let line = Utils.getSpacer(spaceAtOpStr);
            let lineLength = spaceAtOpStr + row[0].length + row[1].toString().length + 3;
            line += applyColor(row[0], 'blue') + ' = ' + applyColor(row[1], 'filter');
            if (row.length > 2 && row[2] !== null) {
                const printInfo = row[2] as PrintInfo;
                if (printInfo.lineLength > 0) {
                    line += ' >> ' + printInfo.data;
                    lineLength += printInfo.lineLength + 4;
                }
            }
            lines.push({ data: line, lineLength: lineLength });
        });
        return lines;
    }

    function getTelescope(address: NativePointer, colored: boolean, isJump: boolean): PrintInfo {
        if (isJump) {
            try {
                const instruction = Instruction.parse(address);
                let ret;
                if (colored) {
                    ret = Color.colorify(instruction.mnemonic, 'green');
                } else {
                    ret = instruction.mnemonic;
                }
                ret += ' ' + instruction.opStr;
                return { data: ret, lineLength: instruction.mnemonic.length + instruction.opStr.length + 1 };
            } catch (e) {}
        } else {
            let count = 0;
            let current = address;
            let result: string = '';
            let resLen = 0;
            while (true) {
                try {
                    current = current.readPointer();
                    const asStr = current.toString();
                    if (result.length > 0) {
                        result += ' >> ';
                        resLen += 4;
                    }
                    resLen += asStr.length;
                    if (current.compare(0x10000) < 0) {
                        if (colored) {
                            result += Color.colorify(asStr, 'cyan bold');
                        } else {
                            result += asStr;
                        }
                        break;
                    } else {
                        if (colored) {
                            result += Color.colorify(asStr, 'red');
                        } else {
                            result += asStr;
                        }

                        try {
                            let str = address.readUtf8String();
                            if (str && str.length > 0) {
                                let ret = str.replace('\n', ' ');
                                if (colored) {
                                    result += ' (' + Color.colorify(ret, 'green') + ')';
                                } else {
                                    result += ' (' + ret + ')';
                                }
                                resLen += str.length + 3;
                            }
                        } catch (e) {}
                    }
                    if (count === 5) {
                        break;
                    }
                    count += 1;
                } catch (e) {
                    break;
                }
            }
            return { data: result, lineLength: resLen };
        }

        return { data: '', lineLength: 0 };
    }

    function getJumpInstruction(instruction: Instruction, context: AnyCpuContext): Instruction | null {
        let insn: Arm64Instruction | X86Instruction | null = null;
        if (Process.arch === 'arm64') {
            insn = instruction as Arm64Instruction;
        } else if (Process.arch === 'ia32' || Process.arch === 'x64') {
            insn = instruction as X86Instruction;
        }
        if (insn) {
            if (Utils.isJumpInstruction(instruction)) {
                const lastOp = insn.operands[insn.operands.length - 1];
                switch (lastOp.type) {
                    case 'reg':
                        return Instruction.parse(context[lastOp.value]);
                    case 'imm':
                        return Instruction.parse(ptr(lastOp.value.toString()));
                }
            }
        }
        return null;
    }

    function getRegisterValue(context: AnyCpuContext, reg: string): NativePointer {
        if (Process.arch === 'arm64') {
            if (reg.startsWith('w')) {
                return context[reg.replace('w', 'x')].and(0x00000000ffffffff);
            }
        }

        return context[reg];
    }
}
