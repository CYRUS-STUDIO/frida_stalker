function printArg(addr) {
    // 查找给定地址所在的内存范围
    var range = Process.findRangeByAddress(addr);
    // 如果该地址属于进程中的已知内存范围（例如模块中的数据段或代码段等）
    if (range) {
        return hexdump(addr) + "\n";
    } else {
        return ptr(addr) + "\n";
    }
}


function hookNativeAddr(addr) {

    var module = Process.findModuleByAddress(ptr(addr))

    Interceptor.attach(addr, {
        onEnter: function (args) {

            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            this.logs = [];

            this.logs.push("call " + module.name + " | " + ptr(addr).sub(module.base) + "\n");
            this.logs.push("arg0:" + printArg(this.arg0));
            this.logs.push("arg1:" + printArg(this.arg1));
            this.logs.push("arg2:" + printArg(this.arg2));
            this.logs.push("arg3:" + printArg(this.arg3));
            this.logs.push("arg4:" + printArg(this.arg4));
        },

        onLeave: function (retval) {
            this.logs.push("onLeave arg0:" + printArg(this.arg0));
            this.logs.push("onLeave arg1:" + printArg(this.arg1));
            this.logs.push("onLeave arg2:" + printArg(this.arg2));
            this.logs.push("onLeave arg3:" + printArg(this.arg3));
            this.logs.push("onLeave arg4:" + printArg(this.arg4));
            this.logs.push("retval:" + printArg(retval));
            console.log(this.logs);
        }
    });
}


function main() {
    // 目标 so 基址
    var baseAddress = Module.findBaseAddress("libaes.so");

    // hookNativeAddr(baseAddress.add(0x23AD0));

    // hookNativeAddr(baseAddress.add(0x57d50)); // .malloc
    hookNativeAddr(baseAddress.add(0x23868));    // stringToSecretKey 跳转表，0x57d00 实际偏移是 0x23868
    hookNativeAddr(baseAddress.add(0x23F8C));    // _JNIEnv::NewByteArray(_JNIEnv *this, unsigned int) 跳转表，0x57dd0 实际偏移是 0x23F8C
    hookNativeAddr(baseAddress.add(0x2ABEC));    // 0x57f70 -> 0x2ABEC
    hookNativeAddr(baseAddress.add(0x2B528));    // 0x57d80 -> 0x2B528
    hookNativeAddr(baseAddress.add(0x25f60));
    hookNativeAddr(baseAddress.add(0x23F1C));    // 0x57d30 -> 0x23F1C
    hookNativeAddr(baseAddress.add(0x2400C));
    hookNativeAddr(baseAddress.add(0x25b8c));
    hookNativeAddr(baseAddress.add(0x29580));
    hookNativeAddr(baseAddress.add(0x237E0));
    hookNativeAddr(baseAddress.add(0x2AE80));    // cbc_encrypt(__int64, __int64, unsigned __int64, __int64)
    // hookNativeAddr(baseAddress.add(0x57d60));  // _memcpy_chk
    hookNativeAddr(baseAddress.add(0x253cc));
    hookNativeAddr(baseAddress.add(0x238F0));
    hookNativeAddr(baseAddress.add(0x23FC0));
    hookNativeAddr(baseAddress.add(0x25bc8));
    hookNativeAddr(baseAddress.add(0x26524));
    hookNativeAddr(baseAddress.add(0x23F58));
    // hookNativeAddr(baseAddress.add(0x2E038));    // operator new[](unsigned __int64)
    hookNativeAddr(baseAddress.add(0x2AC50));
    hookNativeAddr(baseAddress.add(0x29F6C));
    // hookNativeAddr(baseAddress.add(0x2E090));   // operator delete[](void *)
    hookNativeAddr(baseAddress.add(0x274DC));
    // hookNativeAddr(baseAddress.add(0x57da0));   // free
}

setImmediate(main)