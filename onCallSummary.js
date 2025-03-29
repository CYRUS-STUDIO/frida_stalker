function onCallSummary() {
    // 目标 so
    var soName = "libaes.so"
    // 目标 so 基址
    var baseAddress = Module.findBaseAddress(soName);
    // 目标函数地址 = 基址 + 偏移
    var targetAddr = baseAddress.add(0x23AD0);

    console.log('Target function found at:', targetAddr);

    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            console.log('Entering target function');
            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    call: true,      // 捕获函数调用
                    ret: false,       // 捕获函数返回
                    exec: false,      // 捕获指令执行
                    block: false,    // 捕获基本块
                    compile: false   // 捕获编译事件
                },
                onCallSummary: function (summary) {
                    console.log('Call Summary:');
                    Object.keys(summary).forEach(function (addr) {
                        var module = Process.getModuleByAddress(ptr(addr));
                        // 判断地址是否属于目标 so
                        if (module && module.name === soName) {
                            var offset = ptr(addr).sub(module.base);
                            console.log(`调用函数地址: ${ptr(addr)} | 模块: ${module.name} | 偏移: ${offset} | 次数: ${summary[addr]}`);
                        }
                    });
                }
            });
        },

        onLeave: function (retval) {
            console.log('Leaving target function');
            Stalker.unfollow(Process.getCurrentThreadId());
        }
    });
}

// setImmediate()：确保代码在 Frida 环境准备好后执行。
setImmediate(onCallSummary)