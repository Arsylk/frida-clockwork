import { EnvWrapper } from './envWrapper.js';
import { JniMethodDefinition, type jMethodID, type jclass, type jobject } from './jni.js';
import { JniInvokeMode, type JavaMethod } from './model.js';
import { resolveMethod } from './tracer.js';


function hasThisRef(mode: JniInvokeMode) {
    switch (mode) {
        case JniInvokeMode.Normal:
        case JniInvokeMode.Nonvirtual:
            return true;
        case JniInvokeMode.Static:
        case JniInvokeMode.Constructor:
            return false;
    }
}

interface JniInvokeCallback {
    tag: string;
    name: string;
    mode: JniInvokeMode;
    java: JavaMethod;

    // do some caching here
    javaArgs: NativePointer[];
}


type Optional<Type> = { [Property in keyof Type]+?: Type[Property] };

type JniInvokeContext = PortableInvocationContext & {
    env: NativePointer;
    clazz?: jclass;
    obj?: jobject;
    methodID: jMethodID;
    argStruct: NativePointer;
    method: JavaMethod | null;
    jArgs: NativeCallbackArgumentValue[] | null;
};

type JniInvokeScriptListenerCallbacks = {
    onEnter?: ((this: InvocationContext, context: JniInvokeContext) => void)
    onLeave?: ((this: InvocationContext, context: JniInvokeContext, retval: InvocationReturnValue) => void)
};

function JniInvokeCallbacks(
    envWrapper: EnvWrapper,
    def: JniMethodDefinition,
    mode: JniInvokeMode,
    predicate: (thisRef: InvocationContext) => boolean,
    callback: JniInvokeScriptListenerCallbacks,
) {
    const name = def.name;
    const cb: ScriptInvocationListenerCallbacks = {
        onEnter(rawargs) {
            if (!predicate(this)) return;

            let env: NativePointer 
            let obj: NativePointer 
            let clazz: NativePointer 
            let methodID: NativePointer
            let args: NativePointer
            if (mode === JniInvokeMode.Constructor || mode === JniInvokeMode.Static) {
                // const { 0: env, 1: clazz, 2: methodID, 3: args } = rawargs
                env = rawargs[0]
                obj = NULL;
                clazz = rawargs[1] 
                methodID = rawargs[2]
                args = rawargs[3]
            } else if (mode === JniInvokeMode.Normal) {
                // const { 0: env, 1: obj, 2: methodID, 3: args } = rawargs
                env = rawargs[0]
                obj = rawargs[1] 
                clazz = NULL;
                methodID = rawargs[2]
                args = rawargs[3]
            } else {
                // const { 0: env, 1: obj, 2: clazz, 3: methodID, 4: args } = rawargs
                env = rawargs[0]
                obj = rawargs[1]
                clazz = rawargs[2] 
                methodID = rawargs[3]
                args = rawargs[4]
            }
            const context: JniInvokeContext = {
                ...this,
                env: env,
                obj: obj,
                clazz: clazz,
                methodID: methodID,
                argStruct: args,
                method: null,
                jArgs: null,
            };
            const isStatic = (context.isStatic = mode === JniInvokeMode.Static);
            const method = (context.method = resolveMethod(env, clazz, methodID, isStatic));
            context.jArgs = envWrapper.jniInterceptor.getCallMethodArgs(name, [env, clazz, methodID, args], method);

            this._key = context;
            callback.onEnter?.call(this, context);
        },
        onLeave(retval) {
            if (!predicate(this)) return;

            const context: JniInvokeContext = this._key;
            callback?.onLeave?.call(this, context, retval);
            try {
                this._key = null;
                (context as any).env = null;
                (context as any).obj = null;
                (context as any).clazz = null;
                (context as any).methodID = null;
                (context as any).argStruct = null;
                (context as any).method = null;
                (context as any).jArgs = null;
            } catch (e) {}
        },
    };
    return cb;
}

export { JniInvokeCallbacks, JniInvokeMode, type JniInvokeScriptListenerCallbacks };
