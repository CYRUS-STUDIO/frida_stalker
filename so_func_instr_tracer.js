function getModuleByAddressSafe(address) {
    try {
        // 尝试获取模块
        var module = Process.getModuleByAddress(address);

        // 如果模块存在，返回模块
        if (module) {
            return module;
        } else {
            // 如果没有找到模块，返回 null
            return null;
        }
    } catch (e) {
        // 捕获异常，返回 null
        return null;
    }
}

/**
 * 跟踪指令执行
 *
 * @param soName 目标模块名称
 * @param offset 函数偏移
 */
function trace(soName, offset) {
    var baseAddress = Module.findBaseAddress(soName);
    var targetAddr = baseAddress.add(offset);

    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            console.log(`Entering function at: ${targetAddr}`);

            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    exec: true
                },
                onReceive: function (events) {
                    var parsedEvents = Stalker.parse(events);
                    parsedEvents.forEach(event => {
                        if (event[0] === 'exec') {
                            const address = ptr(event[1]);
                            const instruction = Instruction.parse(address);
                            const module = getModuleByAddressSafe(address);
                            const offset = module ? address.sub(module.base) : null;

                            // 判断地址是否属于目标 so
                            if (module && module.name === soName) {
                                if (module) {
                                    const logMessage = `${address} | ${module.name} + 0x${offset.toString(16)} | ${instruction}`;
                                    console.log(logMessage)
                                } else {
                                    const logMessage = `${address} | Unknown | ${instruction}`;
                                    console.log(logMessage)
                                }
                            }
                        }
                    });
                }
            });
        },

        onLeave: function (retval) {
            console.log("Leaving function");
            Stalker.unfollow(Process.getCurrentThreadId());
        }
    });
}

setImmediate(function () {
    trace("libnative-lib.so", 0x26058)
});


// frida -H 127.0.0.1:1234 -F -l so_func_instr_tracer.js -o trace.txt
// frida -H 127.0.0.1:1234 -F -l so_func_instr_tracer.js | tee trace.txt
