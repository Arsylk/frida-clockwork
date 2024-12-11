import { hook } from '@clockwork/hooks';

const ROOT_PACKAGES = ['com.topjohnwu.magisk', 'me.weishu.kernelsu'];

function hookPackageManager() {
    const hookParams = {
        logging: { multiline: false, short: true },
        replace(method, ...args) {
            if (ROOT_PACKAGES.includes(`${args[0]}`)) {
                args[0] = 'come.just.test.fake.app';
            }
            return method.call(this, ...args);
        },
        //after(_method, returnValue) {
        //    const mPackage = this.mContext.value.getPackageName();
        //    if (mPackage === returnValue?.packageName?.value) {
        //    }
        //},
    };
    hook(Classes.ApplicationPackageManager, 'getPackageInfo', hookParams);
    hook(Classes.ApplicationPackageManager, 'getApplicationInfo', hookParams);

    const listHookParams = {
        logging: { multiline: false, short: true },
        replace(method, ...args) {
            const retval = method.call(this, ...args);
            retval.clear();
            return retval;
        },
    };
    hook(Classes.ApplicationPackageManager, 'getInstalledApplications', listHookParams);
    hook(Classes.ApplicationPackageManager, 'getInstalledPackages', listHookParams);
}

export { hookPackageManager };
