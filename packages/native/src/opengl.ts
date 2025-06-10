import { Color, logger } from '@clockwork/logging';
const { dim } = Color.use();

const GL_ENUM = {
    7936: 'GL_VENDOR',
    7937: 'GL_RENDERER',
    7938: 'GL_VERSION',
    7939: 'GL_EXTENSIONS',
};

function hookGlGetString() {
    Interceptor.attach(Module.getGlobalExportByName('glGetString'), {
        onEnter(args: any) {
            this.name = args[0];
        },
        onLeave(retval) {
            const name = this.name.toInt32();
            const label = GL_ENUM[name] ?? 'UNKNOWN';
            const value = retval.readCString();
            let mvalue = value ?? '';
            if (label === 'GL_VENDOR' || label === 'GL_RENDERER' || label === 'GL_EXTENSIONS') {
                mvalue = mvalue.replace(
                    /x86|sdk|open|source|emulator|google|aosp|apple|ranchu|goldfish|cuttlefish|generic|unknown|android_emu/gi,
                    'nya',
                );
                if (mvalue !== value) retval.replace(Memory.allocUtf8String(mvalue));
            }
            logger.info({ tag: 'opengl' }, `${label}(${dim(`${name}`)}) -> ${mvalue}`);
        },
    });
}

export { hookGlGetString, GL_ENUM };
