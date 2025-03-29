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

function onReceive() {

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
                    ret: true,       // 捕获函数返回
                    exec: false,      // 捕获指令执行
                    block: false,    // 捕获基本块
                    compile: false   // 捕获编译事件
                },
                // 实时接收事件数据
                onReceive: function (events) {
                    var parsedEvents = Stalker.parse(events);

                    console.log(`onReceive 事件数量: ${parsedEvents.length}`);

                    parsedEvents.forEach(function (event) {
                        // console.log(`收到事件: ${event}`);
                        var caller = getModuleByAddressSafe(event[1]);
                        var target = getModuleByAddressSafe(event[2]);

                        // 判断地址是否属于目标 so
                        if (caller && caller.name === soName) {

                            var callerName = caller ? caller.name : "Unknown"
                            var targetName = target ? target.name : "Unknown"

                            var callerOffset = caller ? ptr(event[1]).sub(caller.base) : "Unknown";
                            var targetOffset = target ? ptr(event[2]).sub(target.base) : "Unknown";

                            console.log(`[${event[0]}] from: ${event[1]} | ${callerName} | ${callerOffset} -> to: ${event[2]} | ${targetName} | ${targetOffset}`);
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
setImmediate(onReceive)