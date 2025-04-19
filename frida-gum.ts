declare namespace ObjC {
    // tslint:disable:no-unnecessary-qualifier
    /**
     * Whether the current process has an Objective-C runtime loaded. Do not invoke any other ObjC properties or
     * methods unless this is the case.
     */
    const available: boolean;
    /**
     * Direct access to a big portion of the Objective-C runtime API.
     */
    const api: {
        [name: string]: any;
    };
    /**
     * Dynamically generated bindings for each of the currently registered classes.
     *
     * You can interact with objects by using dot notation and replacing colons with underscores, i.e.:
     *
     * ```
     *     [NSString stringWithString:@"Hello World"];
     * ```
     *
     * becomes:
     *
     * ```
     *     const NSString = ObjC.classes.NSString;
     *     NSString.stringWithString_("Hello World");
     * ```
     *
     * Note the underscore after the method name.
     */
    const classes: {
        [name: string]: ObjC.Object;
    };
    /**
     * Dynamically generated bindings for each of the currently registered protocols.
     */
    const protocols: {
        [name: string]: Protocol;
    };
    /**
     * GCD queue of the main thread.
     */
    const mainQueue: NativePointer;
    /**
     * Schedule the JavaScript function `work` on the GCD queue specified by `queue`. An NSAutoreleasePool is created
     * just before calling `work`, and cleaned up on return.
     *
     * E.g. on macOS:
     * ```
     *     const { NSSound } = ObjC.classes;
     *     ObjC.schedule(ObjC.mainQueue, () => {
     *         const sound = NSSound.alloc().initWithContentsOfFile_byReference_("/Users/oleavr/.Trash/test.mp3", true).autorelease();
     *         sound.play();
     *     });
     * ```
     *
     * @param queue GCD queue to schedule `work` on.
     * @param work Function to call on the specified `queue`.
     */
    function schedule(queue: NativePointerValue, work: () => void): void;
    /**
     * Dynamically generated wrapper for any Objective-C instance, class, or meta-class.
     */
    class Object implements ObjectWrapper, ObjectMethods {
        constructor(handle: NativePointer, protocol?: Protocol);
        handle: NativePointer;
        /**
         * Whether this is an instance, class, or meta-class.
         */
        $kind: ObjectKind;
        /**
         * Instance used for chaining up to super-class method implementations.
         */
        $super: ObjC.Object;
        /**
         * Super-class of this object's class.
         */
        $superClass: ObjC.Object;
        /**
         * Class that this object is an instance of.
         */
        $class: ObjC.Object;
        /**
         * Class name of this object.
         */
        $className: string;
        /**
         * Name of module where this object is implemented.
         */
        $moduleName: string;
        /**
         * Protocols that this object conforms to.
         */
        $protocols: {
            [name: string]: Protocol;
        };
        /**
         * Native method names exposed by this object’s class and parent classes.
         */
        $methods: string[];
        /**
         * Native method names exposed by this object’s class, not including parent classes.
         */
        $ownMethods: string[];
        /**
         * Instance variables on this object. Supports both access and assignment.
         */
        $ivars: {
            [name: string]: any;
        };
        /**
         * Determines whether two instances refer to the same underlying object.
         *
         * @param other Other object instance or address to compare to.
         */
        equals(other: ObjC.Object | NativePointer): boolean;
        [name: string]: any;
    }
    interface ObjectMethods {
        [name: string]: ObjectMethod;
    }
    interface ObjectMethod extends ObjectWrapper, AnyFunction {
        handle: NativePointer;
        /**
         * Objective-C selector. Use `ObjC.selectorAsString()` to convert it to a string.
         */
        selector: NativePointer;
        /**
         * Current implementation.
         *
         * You may replace it by assigning to this property. See `ObjC.implement()` for details.
         */
        implementation: NativePointer;
        /**
         * Return type name.
         */
        returnType: string;
        /**
         * Argument type names.
         */
        argumentTypes: string[];
        /**
         * Signature.
         */
        types: string;
        /**
         * Makes a new method wrapper with custom NativeFunction options.
         *
         * Useful for e.g. setting `traps: "all"` to perform execution tracing
         * in conjunction with Stalker.
         */
        clone: (options: NativeFunctionOptions) => ObjectMethod;
    }
    /**
     * What kind of object an ObjC.Object represents.
     */
    type ObjectKind = 'instance' | 'class' | 'meta-class';
    /**
     * Dynamically generated language binding for any Objective-C protocol.
     */
    class Protocol implements ObjectWrapper {
        constructor(handle: NativePointer);
        handle: NativePointer;
        /**
         * Name visible to the Objective-C runtime.
         */
        name: string;
        /**
         * Protocols that this protocol conforms to.
         */
        protocols: {
            [name: string]: Protocol;
        };
        /**
         * Properties declared by this protocol.
         */
        properties: {
            [name: string]: ProtocolPropertyAttributes;
        };
        /**
         * Methods declared by this protocol.
         */
        methods: {
            [name: string]: ProtocolMethodDescription;
        };
    }
    interface ProtocolPropertyAttributes {
        [name: string]: string;
    }
    interface ProtocolMethodDescription {
        /**
         * Whether this method is required or optional.
         */
        required: boolean;
        /**
         * Method signature.
         */
        types: string;
    }
    /**
     * Dynamically generated language binding for any Objective-C block.
     *
     * Also supports implementing a block from scratch by passing in an
     * implementation.
     */
    class Block implements ObjectWrapper {
        constructor(target: NativePointer | MethodSpec<BlockImplementation>, options?: NativeFunctionOptions);
        handle: NativePointer;
        /**
         * Signature, if available.
         */
        types?: string | undefined;
        /**
         * Current implementation. You may replace it by assigning to this property.
         */
        implementation: AnyFunction;
        /**
         * Declares the signature of an externally defined block. This is needed
         * when working with blocks without signature metadata, i.e. when
         * `block.types === undefined`.
         *
         * @param signature Signature to use.
         */
        declare(signature: BlockSignature): void;
    }
    type BlockImplementation = (this: Block, ...args: any[]) => any;
    type BlockSignature = SimpleBlockSignature | DetailedBlockSignature;
    interface SimpleBlockSignature {
        /**
         * Return type.
         */
        retType: string;
        /**
         * Argument types.
         */
        argTypes: string[];
    }
    interface DetailedBlockSignature {
        /**
         * Signature.
         */
        types: string;
    }
    /**
     * Creates a JavaScript implementation compatible with the signature of `method`, where `fn` is used as the
     * implementation. Returns a `NativeCallback` that you may assign to an ObjC method’s `implementation` property.
     *
     * @param method Method to implement.
     * @param fn Implementation.
     */
    function implement(method: ObjectMethod, fn: AnyFunction): NativeCallback<any, any>;
    /**
     * Creates a new class designed to act as a proxy for a target object.
     *
     * @param spec Proxy specification.
     */
    function registerProxy(spec: ProxySpec): ProxyConstructor;
    /**
     * Creates a new Objective-C class.
     *
     * @param spec Class specification.
     */
    function registerClass(spec: ClassSpec): ObjC.Object;
    /**
     * Creates a new Objective-C protocol.
     *
     * @param spec Protocol specification.
     */
    function registerProtocol(spec: ProtocolSpec): Protocol;
    /**
     * Binds some JavaScript data to an Objective-C instance.
     *
     * @param obj Objective-C instance to bind data to.
     * @param data Data to bind.
     */
    function bind(obj: ObjC.Object | NativePointer, data: InstanceData): void;
    /**
     * Unbinds previously associated JavaScript data from an Objective-C instance.
     *
     * @param obj Objective-C instance to unbind data from.
     */
    function unbind(obj: ObjC.Object | NativePointer): void;
    /**
     * Looks up previously bound data from an Objective-C object.
     *
     * @param obj Objective-C instance to look up data for.
     */
    function getBoundData(obj: ObjC.Object | NativePointer): any;
    /**
     * Enumerates loaded classes.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateLoadedClasses(callbacks: EnumerateLoadedClassesCallbacks): void;
    /**
     * Enumerates loaded classes.
     *
     * @param options Options customizing the enumeration.
     * @param callbacks Object with callbacks.
     */
    function enumerateLoadedClasses(
        options: EnumerateLoadedClassesOptions,
        callbacks: EnumerateLoadedClassesCallbacks,
    ): void;
    /**
     * Synchronous version of `enumerateLoadedClasses()`.
     *
     * @param options Options customizing the enumeration.
     */
    function enumerateLoadedClassesSync(
        options?: EnumerateLoadedClassesOptions,
    ): EnumerateLoadedClassesResult;
    interface EnumerateLoadedClassesOptions {
        /**
         * Limit enumeration to modules in the given module map.
         */
        ownedBy?: ModuleMap | undefined;
    }
    interface EnumerateLoadedClassesCallbacks {
        onMatch: (name: string, owner: string) => void;
        onComplete: () => void;
    }
    interface EnumerateLoadedClassesResult {
        /**
         * Class names grouped by name of owner module.
         */
        [owner: string]: string[];
    }
    function choose(specifier: ChooseSpecifier, callbacks: EnumerateCallbacks<ObjC.Object>): void;
    /**
     * Synchronous version of `choose()`.
     *
     * @param specifier What kind of objects to look for.
     */
    function chooseSync(specifier: ChooseSpecifier): ObjC.Object[];
    /**
     * Converts the JavaScript string `name` to a selector.
     *
     * @param name Name to turn into a selector.
     */
    function selector(name: string): NativePointer;
    /**
     * Converts the selector `sel` to a JavaScript string.
     *
     * @param sel Selector to turn into a string.
     */
    function selectorAsString(sel: NativePointerValue): string;
    interface ProxySpec<D extends ProxyData = ProxyData, T = ObjC.Object, S = ObjC.Object> {
        /**
         * Name of the proxy class.
         *
         * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
         * for you.
         */
        name?: string | undefined;
        /**
         * Protocols this proxy class conforms to.
         */
        protocols?: Protocol[] | undefined;
        /**
         * Methods to implement.
         */
        methods?:
            | {
                  [name: string]:
                      | UserMethodImplementation<D, T, S>
                      | MethodSpec<UserMethodImplementation<D, T, S>>;
              }
            | undefined;
        /**
         * Callbacks for getting notified about events.
         */
        events?: ProxyEventCallbacks<D, T, S> | undefined;
    }
    interface ProxyEventCallbacks<D, T, S> {
        /**
         * Gets notified right after the object has been deallocated.
         *
         * This is where you might clean up any associated state.
         */
        dealloc?(this: UserMethodInvocation<D, T, S>): void;
        /**
         * Gets notified about the method name that we’re about to forward
         * a call to.
         *
         * This might be where you’d start out with a temporary callback
         * that just logs the names to help you decide which methods to
         * override.
         *
         * @param name Name of method that is about to get called.
         */
        forward?(this: UserMethodInvocation<D, T, S>, name: string): void;
    }
    /**
     * Constructor for instantiating a proxy object.
     *
     * @param target Target object to proxy to.
     * @param data Object with arbitrary data.
     */
    interface ProxyConstructor {
        new (target: ObjC.Object | NativePointer, data?: InstanceData): ProxyInstance;
    }
    interface ProxyInstance {
        handle: NativePointer;
    }
    interface ProxyData extends InstanceData {
        /**
         * This proxy's target object.
         */
        target: ObjC.Object;
        /**
         * Used by the implementation.
         */
        events: {};
    }
    interface ClassSpec<D = InstanceData, T = ObjC.Object, S = ObjC.Object> {
        /**
         * Name of the class.
         *
         * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
         * for you.
         */
        name?: string | undefined;
        /**
         * Super-class, or `null` to create a new root class. Omit to inherit from `NSObject`.
         */
        super?: ObjC.Object | null | undefined;
        /**
         * Protocols this class conforms to.
         */
        protocols?: Protocol[] | undefined;
        /**
         * Methods to implement.
         */
        methods?:
            | {
                  [name: string]:
                      | UserMethodImplementation<D, T, S>
                      | MethodSpec<UserMethodImplementation<D, T, S>>;
              }
            | undefined;
    }
    type MethodSpec<I> = SimpleMethodSpec<I> | DetailedMethodSpec<I>;
    interface SimpleMethodSpec<I> {
        /**
         * Return type.
         */
        retType: string;
        /**
         * Argument types.
         */
        argTypes: string[];
        /**
         * Implementation.
         */
        implementation: I;
    }
    interface DetailedMethodSpec<I> {
        /**
         * Signature.
         */
        types: string;
        /**
         * Implementation.
         */
        implementation: I;
    }
    type UserMethodImplementation<D, T, S> = (this: UserMethodInvocation<D, T, S>, ...args: any[]) => any;
    interface UserMethodInvocation<D, T, S> {
        self: T;
        super: S;
        data: D;
    }
    /**
     * User-defined data that can be accessed from method implementations.
     */
    interface InstanceData {
        [name: string]: any;
    }
    interface ProtocolSpec {
        /**
         * Name of the protocol.
         *
         * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
         * for you.
         */
        name?: string | undefined;
        /**
         * Protocols this protocol conforms to.
         */
        protocols?: Protocol[] | undefined;
        methods?:
            | {
                  [name: string]: ProtocolMethodSpec;
              }
            | undefined;
    }
    type ProtocolMethodSpec = SimpleProtocolMethodSpec | DetailedProtocolMethodSpec;
    interface SimpleProtocolMethodSpec {
        /**
         * Return type.
         */
        retType: string;
        /**
         * Argument types.
         */
        argTypes: string[];
        /**
         * Whether this method is required or optional. Default is required.
         */
        optional?: boolean | undefined;
    }
    interface DetailedProtocolMethodSpec {
        /**
         * Method signature.
         */
        types: string;
        /**
         * Whether this method is required or optional. Default is required.
         */
        optional?: boolean | undefined;
    }
    type ChooseSpecifier = SimpleChooseSpecifier | DetailedChooseSpecifier;
    type SimpleChooseSpecifier = ObjC.Object;
    interface DetailedChooseSpecifier {
        /**
         * Which class to look for instances of. E.g.: `ObjC.classes.UIButton`.
         */
        class: ObjC.Object;
        /**
         * Whether you’re also interested in subclasses matching the given class selector.
         *
         * The default is to also include subclasses.
         */
        subclasses?: boolean | undefined;
    }
    // tslint:enable:no-unnecessary-qualifier
}
declare namespace Java {
    /**
     * Whether the current process has a Java runtime loaded. Do not invoke any other Java properties or
     * methods unless this is the case.
     */
    const available: boolean;
    /**
     * Which version of Android we're running on.
     */
    const androidVersion: string;
    const ACC_PUBLIC: number;
    const ACC_PRIVATE: number;
    const ACC_PROTECTED: number;
    const ACC_STATIC: number;
    const ACC_FINAL: number;
    const ACC_SYNCHRONIZED: number;
    const ACC_BRIDGE: number;
    const ACC_VARARGS: number;
    const ACC_NATIVE: number;
    const ACC_ABSTRACT: number;
    const ACC_STRICT: number;
    const ACC_SYNTHETIC: number;
    /**
     * Calls `func` with the `obj` lock held.
     *
     * @param obj Instance whose lock to hold.
     * @param fn Function to call with lock held.
     */
    function synchronized(obj: Wrapper, fn: () => void): void;
    /**
     * Enumerates loaded classes.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateLoadedClasses(callbacks: EnumerateLoadedClassesCallbacks): void;
    /**
     * Synchronous version of `enumerateLoadedClasses()`.
     */
    function enumerateLoadedClassesSync(): string[];
    /**
     * Enumerates class loaders.
     *
     * You may pass such a loader to `Java.ClassFactory.get()` to be able to
     * `.use()` classes on the specified class loader.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateClassLoaders(callbacks: EnumerateClassLoadersCallbacks): void;
    /**
     * Synchronous version of `enumerateClassLoaders()`.
     */
    function enumerateClassLoadersSync(): Wrapper[];
    /**
     * Enumerates methods matching `query`.
     *
     * @param query Query specified as `class!method`, with globs permitted. May
     *              also be suffixed with `/` and one or more modifiers:
     *              - `i`: Case-insensitive matching.
     *              - `s`: Include method signatures, so e.g. `"putInt"` becomes
     *                `"putInt(java.lang.String, int): void"`.
     *              - `u`: User-defined classes only, ignoring system classes.
     */
    function enumerateMethods(query: string): EnumerateMethodsMatchGroup[];
    /**
     * Runs `fn` on the main thread of the VM.
     *
     * @param fn Function to run on the main thread of the VM.
     */
    function scheduleOnMainThread(fn: () => void): void;
    /**
     * Ensures that the current thread is attached to the VM and calls `fn`.
     * (This isn't necessary in callbacks from Java.)
     *
     * Will defer calling `fn` if the app's class loader is not available yet.
     * Use `Java.performNow()` if access to the app's classes is not needed.
     *
     * @param fn Function to run while attached to the VM.
     */
    function perform(fn: () => void): void;
    /**
     * Ensures that the current thread is attached to the VM and calls `fn`.
     * (This isn't necessary in callbacks from Java.)
     *
     * @param fn Function to run while attached to the VM.
     */
    function performNow(fn: () => void): void;
    /**
     * Dynamically generates a JavaScript wrapper for `className` that you can
     * instantiate objects from by calling `$new()` on to invoke a constructor.
     * Call `$dispose()` on an instance to clean it up explicitly, or wait for
     * the JavaScript object to get garbage-collected, or script to get
     * unloaded. Static and non-static methods are available, and you can even
     * replace method implementations.
     *
     * Uses the app's class loader, but you may access classes on other loaders
     * by calling `Java.ClassFactory.get()`.
     *
     * @param className Canonical class name to get a wrapper for.
     */
    function use<T extends Members<T> = {}>(className: string): Wrapper<T>;
    /**
     * Opens the .dex file at `filePath`.
     *
     * @param filePath Path to .dex to open.
     */
    function openClassFile(filePath: string): DexFile;
    /**
     * Enumerates live instances of the `className` class by scanning the Java
     * VM's heap.
     *
     * @param className Name of class to enumerate instances of.
     * @param callbacks Object with callbacks.
     */
    function choose<T extends Members<T> = {}>(className: string, callbacks: ChooseCallbacks<T>): void;
    /**
     * Duplicates a JavaScript wrapper for later use outside replacement method.
     *
     * @param obj An existing wrapper retrieved from `this` in replacement method.
     */
    function retain<T extends Members<T> = {}>(obj: Wrapper<T>): Wrapper<T>;
    /**
     * Creates a JavaScript wrapper given the existing instance at `handle` of
     * given class `klass` as returned from `Java.use()`.
     *
     * @param handle An existing wrapper or a JNI handle.
     * @param klass Class wrapper for type to cast to.
     */
    function cast<From extends Members<From> = {}, To extends Members<To> = {}>(
        handle: Wrapper<From> | NativePointerValue,
        klass: Wrapper<To>,
    ): Wrapper<To>;
    /**
     * Creates a Java array with elements of the specified `type`, from a
     * JavaScript array `elements`. The resulting Java array behaves like
     * a JS array, but can be passed by reference to Java APIs in order to
     * allow them to modify its contents.
     *
     * @param type Type name of elements.
     * @param elements Array of JavaScript values to use for constructing the
     *                 Java array.
     */
    function array(type: string, elements: any[]): any[];
    /**
     * Generates a backtrace for the current thread.
     *
     * @param options Options to customize the stack-walking.
     */
    function backtrace(options?: BacktraceOptions): Backtrace;
    /**
     * Determines whether the caller is running on the main thread.
     */
    function isMainThread(): boolean;
    /**
     * Creates a new Java class.
     *
     * @param spec Object describing the class to be created.
     */
    function registerClass(spec: ClassSpec): Wrapper;
    /**
     * Forces the VM to execute everything with its interpreter. Necessary to
     * prevent optimizations from bypassing method hooks in some cases, and
     * allows ART's Instrumentation APIs to be used for tracing the runtime.
     */
    function deoptimizeEverything(): void;
    /**
     * Similar to deoptimizeEverything but only deoptimizes boot image code.
     * Use with `dalvik.vm.dex2oat-flags --inline-max-code-units=0` for best
     * results.
     */
    function deoptimizeBootImage(): void;
    const vm: VM;
    /**
     * The default class factory used to implement e.g. `Java.use()`.
     * Uses the application's main class loader.
     */
    const classFactory: ClassFactory;
    interface EnumerateLoadedClassesCallbacks {
        /**
         * Called with the name of each currently loaded class, and a JNI
         * reference for its Java Class object.
         *
         * Pass the `name` to `Java.use()` to get a JavaScript wrapper.
         * You may also `Java.cast()` the `handle` to `java.lang.Class`.
         */
        onMatch: (name: string, handle: NativePointer) => void;
        /**
         * Called when all loaded classes have been enumerated.
         */
        onComplete: () => void;
    }
    interface EnumerateClassLoadersCallbacks {
        /**
         * Called with a `java.lang.ClassLoader` wrapper for each class loader
         * found in the VM.
         */
        onMatch: (loader: Wrapper) => void;
        /**
         * Called when all class loaders have been enumerated.
         */
        onComplete: () => void;
    }
    /**
     * Matching methods grouped by class loader.
     */
    interface EnumerateMethodsMatchGroup {
        /**
         * Class loader, or `null` for the bootstrap class loader.
         *
         * Typically passed to `ClassFactory.get()` to interact with classes of
         * interest.
         */
        loader: Wrapper | null;
        /**
         * One or more matching classes that have one or more methods matching
         * the given query.
         */
        classes: [EnumerateMethodsMatchClass, ...EnumerateMethodsMatchClass[]];
    }
    /**
     * Class matching query which has one or more matching methods.
     */
    interface EnumerateMethodsMatchClass {
        /**
         * Class name that matched the given query.
         */
        name: string;
        /**
         * One or more matching method names, each followed by signature when
         * the `s` modifier is used.
         */
        methods: [string, ...string[]];
    }
    interface ChooseCallbacks<T extends Members<T> = {}> {
        /**
         * Called with each live instance found with a ready-to-use `instance`
         * just as if you would have called `Java.cast()` with a raw handle to
         * this particular instance.
         *
         * May return `EnumerateAction.Stop` to stop the enumeration early.
         */
        // eslint-disable-next-line @typescript-eslint/no-invalid-void-type
        onMatch: (instance: Wrapper<T>) => void | EnumerateAction;
        /**
         * Called when all instances have been enumerated.
         */
        onComplete: () => void;
    }
    /**
     * Options that may be passed to `Java.backtrace()`.
     */
    interface BacktraceOptions {
        /**
         * Limit how many frames up the stack to walk. Defaults to 16.
         */
        limit?: number;
    }
    /**
     * Backtrace returned by `Java.backtrace()`.
     */
    interface Backtrace {
        /**
         * ID that can be used for deduplicating identical backtraces.
         */
        id: string;
        /**
         * Stack frames.
         */
        frames: Frame[];
    }
    interface Frame {
        /**
         * Signature, e.g. `"Landroid/os/Looper;,loopOnce,(Landroid/os/Looper;JI)Z"`.
         */
        signature: string;
        /**
         * Where the code is from, i.e. the filesystem path to the `.dex` on Android.
         */
        origin: string;
        /**
         * Class name that method belongs to, e.g. `"android.os.Looper"`.
         */
        className: string;
        /**
         * Method name, e.g. `"loopOnce"`.
         */
        methodName: string;
        /**
         * Method flags. E.g. `Java.ACC_PUBLIC | Java.ACC_STATIC`.
         */
        methodFlags: number;
        /**
         * Source file name, e.g. `"Looper.java"`.
         */
        fileName: string;
        /**
         * Source line number, e.g. `201`.
         */
        lineNumber: number;
    }
    type Members<T> = Record<keyof T, MethodDispatcher | Field>;
    /**
     * Dynamically generated wrapper for any Java class, instance, or interface.
     */
    type Wrapper<T extends Members<T> = {}> = {
        /**
         * Automatically inject holder's type to all fields and methods
         */
        [K in keyof T]: T[K] extends Field<infer Value> ? Field<Value, T> : MethodDispatcher<T>;
    } & {
        /**
         * Allocates and initializes a new instance of the given class.
         *
         * Use this to create a new instance.
         */
        $new: MethodDispatcher<T>;
        /**
         * Allocates a new instance without initializing it.
         *
         * Call `$init()` to initialize it.
         */
        $alloc: MethodDispatcher<T>;
        /**
         * Initializes an instance that was allocated but not yet initialized.
         * This wraps the constructor(s).
         *
         * Replace the `implementation` property to hook a given constructor.
         */
        $init: MethodDispatcher<T>;
        /**
         * Eagerly deletes the underlying JNI global reference without having to
         * wait for the object to become unreachable and the JavaScript
         * runtime's garbage collector to kick in (or script to be unloaded).
         *
         * Useful when a lot of short-lived objects are created in a loop and
         * there's a risk of running out of global handles.
         */
        $dispose(): void;
        /**
         * Retrieves a `java.lang.Class` wrapper for the current class.
         */
        class: Wrapper;
        /**
         * Canonical name of class being wrapped.
         */
        $className: string;
        /**
         * Method and field names exposed by this object’s class, not including
         * parent classes.
         */
        $ownMembers: string[];
        /**
         * Instance used for chaining up to super-class method implementations.
         */
        $super: Wrapper;
        /**
         * Methods and fields.
         */
        [name: string]: any;
    };
    interface MethodDispatcher<Holder extends Members<Holder> = {}> extends Method<Holder> {
        /**
         * Available overloads.
         */
        overloads: Array<Method<Holder>>;
        /**
         * Obtains a specific overload.
         *
         * @param args Signature of the overload to obtain.
         *             For example: `"java.lang.String", "int"`.
         */
        overload(...args: string[]): Method<Holder>;
    }
    interface Method<Holder extends Members<Holder> = {}> {
        (...params: any[]): any;
        /**
         * Name of this method.
         */
        methodName: string;
        /**
         * Class that this method belongs to.
         */
        holder: Wrapper<Holder>;
        /**
         * What kind of method this is, i.e. constructor vs static vs instance.
         */
        type: MethodType;
        /**
         * Pointer to the VM's underlying method object.
         */
        handle: NativePointer;
        /**
         * Implementation. Assign a new implementation to this property to
         * replace the original implementation. Assign `null` at a future point
         * to revert back to the original implementation.
         */
        implementation: MethodImplementation<Holder> | null;
        /**
         * Method return type.
         */
        returnType: Type;
        /**
         * Method argument types.
         */
        argumentTypes: Type[];
        /**
         * Queries whether the method may be invoked with a given argument list.
         */
        canInvokeWith: (...args: any[]) => boolean;
        /**
         * Makes a new method wrapper with custom NativeFunction options.
         *
         * Useful for e.g. setting `traps: "all"` to perform execution tracing
         * in conjunction with Stalker.
         */
        clone: (options: NativeFunctionOptions) => Method<Holder>;
    }
    type MethodImplementation<This extends Members<This> = {}> = (
        this: Wrapper<This>,
        ...params: any[]
    ) => any;
    interface Field<Value = any, Holder extends Members<Holder> = {}> {
        /**
         * Current value of this field. Assign to update the field's value.
         */
        value: Value;
        /**
         * Class that this field belongs to.
         */
        holder: Wrapper<Holder>;
        /**
         * What kind of field this is, i.e. static vs instance.
         */
        fieldType: FieldType;
        /**
         * Type of value.
         */
        fieldReturnType: Type;
    }
    // eslint-disable-next-line @definitelytyped/no-const-enum
    const enum MethodType {
        Constructor = 1,
        Static = 2,
        Instance = 3,
    }
    // eslint-disable-next-line @definitelytyped/no-const-enum
    const enum FieldType {
        Static = 1,
        Instance = 2,
    }
    interface Type {
        /**
         * VM type name. For example `I` for `int`.
         */
        name: string;
        /**
         * Frida type name. For example `pointer` for a handle.
         */
        type: string;
        /**
         * Size in words.
         */
        size: number;
        /**
         * Size in bytes.
         */
        byteSize: number;
        /**
         * Class name, if applicable.
         */
        className?: string | undefined;
        /**
         * Checks whether a given JavaScript `value` is compatible.
         */
        isCompatible: (value: any) => boolean;
        /**
         * Converts `value` from a JNI value to a JavaScript value.
         */
        fromJni?: ((value: any) => any) | undefined;
        /**
         * Converts `value` from a JavaScript value to a JNI value.
         */
        toJni?: ((value: any) => any) | undefined;
        /**
         * Reads a value from memory.
         */
        read?: ((address: NativePointerValue) => any) | undefined;
        /**
         * Writes a value to memory.
         */
        write?: ((address: NativePointerValue, value: any) => void) | undefined;
    }
    interface DexFile {
        /**
         * Loads the contained classes into the VM.
         */
        load(): void;
        /**
         * Determines available class names.
         */
        getClassNames(): string[];
    }
    interface ClassSpec {
        /**
         * Name of the class.
         */
        name: string;
        /**
         * Super-class. Omit to inherit from `java.lang.Object`.
         */
        superClass?: Wrapper | undefined;
        /**
         * Interfaces implemented by this class.
         */
        implements?: Wrapper[] | undefined;
        /**
         * Name and type of each field to expose.
         */
        fields?:
            | {
                  [name: string]: string;
              }
            | undefined;
        /**
         * Methods to implement. Use the special name `$init` to define one or more constructors.
         */
        methods?:
            | {
                  [name: string]: MethodImplementation | MethodSpec | MethodSpec[];
              }
            | undefined;
    }
    interface MethodSpec {
        /**
         * Return type. Defaults to `void` if omitted.
         */
        returnType?: string | undefined;
        /**
         * Argument types. Defaults to `[]` if omitted.
         */
        argumentTypes?: string[] | undefined;
        /**
         * Implementation.
         */
        implementation: MethodImplementation;
    }
    interface VM {
        /**
         * Ensures that the current thread is attached to the VM and calls `fn`.
         * (This isn't necessary in callbacks from Java.)
         *
         * @param fn Function to run while attached to the VM.
         */
        perform(fn: () => void): void;
        /**
         * Gets a wrapper for the current thread's `JNIEnv`.
         *
         * Throws an exception if the current thread is not attached to the VM.
         */
        getEnv(): Env;
        /**
         * Tries to get a wrapper for the current thread's `JNIEnv`.
         *
         * Returns `null` if the current thread is not attached to the VM.
         */
        tryGetEnv(): Env | null;
    }
    type Env = any;
    class ClassFactory {
        /**
         * Gets the class factory instance for a given class loader, or the
         * default factory when passing `null`.
         *
         * The default class factory used behind the scenes only interacts
         * with the application's main class loader. Other class loaders
         * can be discovered through APIs such as `Java.enumerateMethods()` and
         * `Java.enumerateClassLoaders()`, and subsequently interacted with
         * through this API.
         */
        static get(classLoader: Wrapper | null): ClassFactory;
        /**
         * Class loader currently being used. For the default class factory this
         * is updated by the first call to `Java.perform()`.
         */
        readonly loader: Wrapper | null;
        /**
         * Path to cache directory currently being used. For the default class
         * factory this is updated by the first call to `Java.perform()`.
         */
        cacheDir: string;
        /**
         * Naming convention to use for temporary files.
         *
         * Defaults to `{ prefix: "frida", suffix: "dat" }`.
         */
        tempFileNaming: TempFileNaming;
        /**
         * Dynamically generates a JavaScript wrapper for `className` that you can
         * instantiate objects from by calling `$new()` on to invoke a constructor.
         * Call `$dispose()` on an instance to clean it up explicitly, or wait for
         * the JavaScript object to get garbage-collected, or script to get
         * unloaded. Static and non-static methods are available, and you can even
         * replace method implementations.
         *
         * @param className Canonical class name to get a wrapper for.
         */
        use<T extends Members<T> = {}>(className: string): Wrapper<T>;
        /**
         * Opens the .dex file at `filePath`.
         *
         * @param filePath Path to .dex to open.
         */
        openClassFile(filePath: string): DexFile;
        /**
         * Enumerates live instances of the `className` class by scanning the Java
         * VM's heap.
         *
         * @param className Name of class to enumerate instances of.
         * @param callbacks Object with callbacks.
         */
        choose<T extends Members<T> = {}>(className: string, callbacks: ChooseCallbacks<T>): void;
        /**
         * Duplicates a JavaScript wrapper for later use outside replacement method.
         *
         * @param obj An existing wrapper retrieved from `this` in replacement method.
         */
        retain<T extends Members<T> = {}>(obj: Wrapper<T>): Wrapper<T>;
        /**
         * Creates a JavaScript wrapper given the existing instance at `handle` of
         * given class `klass` as returned from `Java.use()`.
         *
         * @param handle An existing wrapper or a JNI handle.
         * @param klass Class wrapper for type to cast to.
         */
        cast<From extends Members<From> = {}, To extends Members<To> = {}>(
            handle: Wrapper<From> | NativePointerValue,
            klass: Wrapper<To>,
        ): Wrapper<To>;
        /**
         * Creates a Java array with elements of the specified `type`, from a
         * JavaScript array `elements`. The resulting Java array behaves like
         * a JS array, but can be passed by reference to Java APIs in order to
         * allow them to modify its contents.
         *
         * @param type Type name of elements.
         * @param elements Array of JavaScript values to use for constructing the
         *                 Java array.
         */
        array(type: string, elements: any[]): any[];
        /**
         * Creates a new Java class.
         *
         * @param spec Object describing the class to be created.
         */
        registerClass(spec: ClassSpec): Wrapper;
    }
    interface TempFileNaming {
        /**
         * File name prefix to use.
         *
         * For example: `frida`.
         */
        prefix: string;
        /**
         * File name suffix to use.
         *
         * For example: `dat`.
         */
        suffix: string;
    }
}
