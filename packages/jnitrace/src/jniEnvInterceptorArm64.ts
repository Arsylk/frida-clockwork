import { JNIEnvInterceptor } from './jniEnvInterceptor.js';
import type { JavaMethod } from './model.js';

class JNIEnvInterceptorARM64 extends JNIEnvInterceptor {
    private stack: NativePointer = NULL;
    private stackIndex = 0;
    private grTop: NativePointer = NULL;
    private vrTop: NativePointer = NULL;
    private grOffs = 0;
    private vrOffs = 0;

    protected setUpVaListArgExtract(vaList: NativePointer): void {
        this.stack = vaList.readPointer();
        this.stackIndex = 0;
        this.grTop = vaList.add(8).readPointer();
        this.vrTop = vaList.add(16).readPointer();
        this.grOffs = vaList.add(24).readS32();
        this.vrOffs = vaList.add(28).readS32();
    }

    protected extractVaListArgValue(method: JavaMethod, paramId: number): NativePointer {
        let currentPtr = NULL;

        if (method.jParameterTypes[paramId] === 'float' || method.jParameterTypes[paramId] === 'double') {
            if (this.vrOffs < 0) {
                currentPtr = this.vrTop.add(this.vrOffs);
                this.vrOffs += 16; // Move to next VR register
            } else {
                currentPtr = this.stack.add(this.stackIndex * 8);
                this.stackIndex++;
            }
        } else {
            if (this.grOffs < 0) {
                currentPtr = this.grTop.add(this.grOffs);
                this.grOffs += 8; // Move to next GR register
            } else {
                currentPtr = this.stack.add(this.stackIndex * 8);
                this.stackIndex++;
            }
        }
        return currentPtr;
    }

    protected resetVaListArgExtract(): void {
        this.stack = NULL;
        this.stackIndex = 0;
        this.grTop = NULL;
        this.vrTop = NULL;
        this.grOffs = 0;
        this.vrOffs = 0;
    }
}

export { JNIEnvInterceptorARM64 };
