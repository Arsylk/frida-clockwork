import { Consts } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
const { gray, green, red } = Color.use();
const { a_type } = Consts;

function hookGetauxval() {
    // ? found single case where this would hang the app forever, attach version works fine
    //Interceptor.replace(
    //    Libc.getauxval,
    //    new NativeCallback(
    //        (type) => {
    //            const retval = Libc.getauxval(type);
    //            logger.info({ tag: 'getauxval' }, `${gray(a_type[type as a_type])}: ${ptr(retval)}`);
    //            return retval;
    //        },
    //        'uint32',
    //        ['uint32'],
    //    ),
    //);
    Interceptor.attach(Libc.getauxval, {
        onEnter({ 0: type }) {
            this.type = type;
        },
        onLeave(retval) {
            const numType = Number(this.type);
            logger.info({ tag: 'getauxval' }, `${gray(a_type[numType])}: ${retval}`);
        },
    });
}

function hookSystem() {
    Interceptor.replace(
        Libc.system,
        new NativeCallback(
            (command) => {
                const cmd = command.readCString();
                logger.info({ tag: 'system' }, `${cmd}`);
                if (cmd?.startsWith('rm -')) {
                    return 0;
                }
                const retval = Libc.system(command);
                return retval;
            },
            'int',
            ['pointer'],
        ),
    );
}

function hookPosixSpawn() {
    Interceptor.attach(Libc.posix_spawn, {
        onEnter({ 0: pid, 1: path, 2: action }) {
            const pathStr = path.readCString();
            logger.info({ tag: 'posix_spawn' }, `pid: ${pid} path: ${pathStr} action: ${action}`);
        },
        onLeave(retval) {
            logger.info({ tag: 'posix_spawn' }, `return: ${retval}`);
        },
    });
}

// biome-ignore lint/suspicious/noConfusingVoidType:
function hookPopen(fn?: (cmd: string) => string | void) {
    fn ??= (cmd) => {
        if (cmd.startsWith('uname')) return 'echo -a';
        if (cmd.startsWith('getprop') && !cmd.startsWith('getprop ro.dalvik.vm.isa.arm')) return 'echo';
        if (cmd.startsWith('su -v')) return 'file';
        return;
    };
    Interceptor.replace(
        Libc.popen,
        new NativeCallback(
            (arg0, arg1) => {
                const cmd = arg0.readCString();
                const newCmd = fn?.(`${cmd}`);
                if (newCmd) {
                    const newArg = Memory.allocUtf8String(newCmd);
                    logger.info({ tag: 'popen' }, `${red(`${cmd}`)} -> ${green(newCmd)}`);
                    return Libc.popen(arg0, newArg);
                }
                logger.info({ tag: 'popen' }, `${cmd}`);
                return Libc.popen(arg0, arg1);
            },
            'pointer',
            ['pointer', 'pointer'],
        ),
    );
}

function hookExecv() {}

export { hookPopen, hookGetauxval, hookPosixSpawn, hookSystem };
