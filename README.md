> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# 前言



在移动应用的安全加固中，**OLLVM（Obfuscator-LLVM）**  是一种常见的代码混淆与保护手段。它通过控制流平坦化、虚假控制流、指令替换等方式，使逆向分析者很难直接还原出原始算法逻辑。



然而，通过 Frida 提供的 **Stalker**  模块去动态分析让我们有机会对 OLLVM 的“黑盒逻辑”进行还原。



通过 Stalker 的指令级追踪能力，我们不仅能捕获 **函数调用** 、记录 **调用参数** ，还可以打印 **调用堆栈** ，最终逐步揭开 OLLVM 加固算法的真实运行流程。



比如，分析某个 so 中偏移为  0x23AD0 的加密函数。使用 IDA 反汇编 so，可以看到 so 中该函数做了混淆



![word/media/image1.png](https://gitee.com/cyrus-studio/images/raw/master/67a623e949b405628e3a6988a4a4f38a.png)


使用了控制流平坦化混淆



![word/media/image2.png](https://gitee.com/cyrus-studio/images/raw/master/2833883961c7d1298e9bc068228714c4.png)


# Frida Stalker



**Frida Stalker**  是 Frida 提供的一个强大的指令级追踪引擎，它能够在目标进程运行时，动态捕获每一条指令的执行情况。与传统的函数级 hook 不同，Stalker 可以深入到 **原生汇编层面** ，追踪寄存器变化、内存访问、函数调用关系等底层细节。



相关链接：

- Stalker 介绍：[https://frida.re/docs/stalker/](https://frida.re/docs/stalker/)

- api 文档：[https://frida.re/docs/javascript-api/#stalker](https://frida.re/docs/javascript-api/#stalker)



目前 Stalker 对于 arm64 支持比较好，但是 arm32 并不是很完善。



![word/media/image3.png](https://gitee.com/cyrus-studio/images/raw/master/db534ee780918e2346c42cf76bcedfed.png)


# onCallSummary（函数调用摘要)



**onCallSummary**  是 Frida Stalker 提供的一个回调方法，用于在 **函数调用层面**  对收集到的执行数据进行归纳和统计。



它会将某一段追踪区间内的 **调用信息进行汇总** ，例如：

- 哪些函数被调用了

- 每个函数被调用了多少次

- 调用分布和频率



简而言之，onCallSummary 像是 **函数调用的统计报表** ，让你能在混淆代码的“噪音”中看清主干逻辑。



返回数据的结构（summary）通常类似于以下格式：

```
{
  "函数地址": 调用次数
}
```


hook 目标函数，跟踪  call 事件并打印 call summary

```
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
```


启动 frida-server，附加到当前 app 并执行脚本

```
frida -H 127.0.0.1:1234 -F -l onCallSummary.js
```


输出如下：

```
Target function found at: 0x77fdf2ead0
[Remote::AndroidExample]-> Entering target function
Leaving target function
Call Summary:
调用函数地址: 0x77fdf62d50 | 模块: libaes.so | 偏移: 0x57d50 | 次数: 4
调用函数地址: 0x77fdf62d00 | 模块: libaes.so | 偏移: 0x57d00 | 次数: 1
调用函数地址: 0x77fdf62dd0 | 模块: libaes.so | 偏移: 0x57dd0 | 次数: 1
调用函数地址: 0x77fdf62f70 | 模块: libaes.so | 偏移: 0x57f70 | 次数: 3
调用函数地址: 0x77fdf62d80 | 模块: libaes.so | 偏移: 0x57d80 | 次数: 1
调用函数地址: 0x77fdf30f60 | 模块: libaes.so | 偏移: 0x25f60 | 次数: 1
调用函数地址: 0x77fdf62d30 | 模块: libaes.so | 偏移: 0x57d30 | 次数: 1
调用函数地址: 0x77fdf62e00 | 模块: libaes.so | 偏移: 0x57e00 | 次数: 1
调用函数地址: 0x77fdf30b8c | 模块: libaes.so | 偏移: 0x25b8c | 次数: 1
调用函数地址: 0x77fdf34580 | 模块: libaes.so | 偏移: 0x29580 | 次数: 10
调用函数地址: 0x77fdf62ce0 | 模块: libaes.so | 偏移: 0x57ce0 | 次数: 1
调用函数地址: 0x77fdf62db0 | 模块: libaes.so | 偏移: 0x57db0 | 次数: 1
调用函数地址: 0x77fdf62d60 | 模块: libaes.so | 偏移: 0x57d60 | 次数: 13
调用函数地址: 0x77fdf303cc | 模块: libaes.so | 偏移: 0x253cc | 次数: 1
调用函数地址: 0x77fdf62d10 | 模块: libaes.so | 偏移: 0x57d10 | 次数: 1
调用函数地址: 0x77fdf62de0 | 模块: libaes.so | 偏移: 0x57de0 | 次数: 1
调用函数地址: 0x77fdf30bc8 | 模块: libaes.so | 偏移: 0x25bc8 | 次数: 1
调用函数地址: 0x77fdf62eb0 | 模块: libaes.so | 偏移: 0x57eb0 | 次数: 1
调用函数地址: 0x77fdf62d40 | 模块: libaes.so | 偏移: 0x57d40 | 次数: 1
调用函数地址: 0x77fdf62cf0 | 模块: libaes.so | 偏移: 0x57cf0 | 次数: 2
调用函数地址: 0x77fdf62dc0 | 模块: libaes.so | 偏移: 0x57dc0 | 次数: 1
调用函数地址: 0x77fdf62d70 | 模块: libaes.so | 偏移: 0x57d70 | 次数: 1
调用函数地址: 0x77fdf62df0 | 模块: libaes.so | 偏移: 0x57df0 | 次数: 2
调用函数地址: 0x77fdf62ec0 | 模块: libaes.so | 偏移: 0x57ec0 | 次数: 1
调用函数地址: 0x77fdf62da0 | 模块: libaes.so | 偏移: 0x57da0 | 次数: 2
```


# onReceive（接收捕获的事件）



**onReceive**  是 Frida Stalker 的另一个重要回调方法，用于 **逐条接收捕获到的事件** 。与 onCallSummary 不同，它不会进行统计汇总，而是将底层指令级别的执行轨迹实时发送到回调中。



在 onReceive 中，你能拿到最原始的 **执行事件数据** ，例如：

- 每条指令的执行地址

- 寄存器变化

- 内存读写行为

- 调用的目标函数地址



简而言之，onReceive 就像一台 **显微镜** ，能把程序的执行过程逐步展现出来，配合 

onCallSummary 的宏观视角，二者结合能更高效地对抗复杂的代码混淆与保护机制。



onReceive 传递的 events 数据需要用 Stalker.parse() 解析，解析后的数据是数组类型，格式如下：

```
call,0x789143a16c,0x77a1addf1c,0
ret,0x7890000e34,0x788ff64e68,2

[事件类型], [调用方地址], [目标地址], [附加信息]
```


比如，跟踪 call 和 ret 事件 并打印日志：

```
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
```


附加到当前 app 并执行脚本

```
frida -H 127.0.0.1:1234 -F -l onReceive.js
```


输出如下：

```
Target function found at: 0x77fdf2ead0
[Remote::AndroidExample]-> Entering target function
Leaving target function
onReceive 事件数量: 390
[call] from: 0x77fdf2eb08 | libaes.so | 0x23b08 -> to: 0x77fdf62d30 | libaes.so | 0x57d30
[call] from: 0x77fdf2ef48 | libaes.so | 0x23f48 -> to: 0x780d775348 | libart.so | 0x360348
[ret] from: 0x77fdf2ef54 | libaes.so | 0x23f54 -> to: 0x77fdf2eb0c | libaes.so | 0x23b0c
[call] from: 0x77fdf2eb18 | libaes.so | 0x23b18 -> to: 0x77fdf62d40 | libaes.so | 0x57d40
[call] from: 0x77fdf2ef7c | libaes.so | 0x23f7c -> to: 0x780d773378 | libart.so | 0x35e378
[ret] from: 0x77fdf2ef88 | libaes.so | 0x23f88 -> to: 0x77fdf2eb1c | libaes.so | 0x23b1c
[call] from: 0x77fdf2eb34 | libaes.so | 0x23b34 -> to: 0x77fdf303cc | libaes.so | 0x253cc
[ret] from: 0x77fdf3048c | libaes.so | 0x2548c -> to: 0x77fdf2eb38 | libaes.so | 0x23b38
[call] from: 0x77fdf2eb3c | libaes.so | 0x23b3c -> to: 0x77fdf62d00 | libaes.so | 0x57d00
[call] from: 0x77fdf2e87c | libaes.so | 0x2387c -> to: 0x77fdf62cf0 | libaes.so | 0x57cf0
[call] from: 0x77fdf38f98 | libaes.so | 0x2df98 -> to: 0x77fdf62d50 | libaes.so | 0x57d50
[ret] from: 0x77fdf38fbc | libaes.so | 0x2dfbc -> to: 0x77fdf2e880 | libaes.so | 0x23880
[ret] from: 0x77fdf2e8ec | libaes.so | 0x238ec -> to: 0x77fdf2eb40 | libaes.so | 0x23b40
[call] from: 0x77fdf2eb4c | libaes.so | 0x23b4c -> to: 0x77fdf62ce0 | libaes.so | 0x57ce0
[call] from: 0x77fdf2e7f4 | libaes.so | 0x237f4 -> to: 0x77fdf62cf0 | libaes.so | 0x57cf0
[call] from: 0x77fdf38f98 | libaes.so | 0x2df98 -> to: 0x77fdf62d50 | libaes.so | 0x57d50
[ret] from: 0x77fdf38fbc | libaes.so | 0x2dfbc -> to: 0x77fdf2e7f8 | libaes.so | 0x237f8
[ret] from: 0x77fdf2e864 | libaes.so | 0x23864 -> to: 0x77fdf2eb50 | libaes.so | 0x23b50
[call] from: 0x77fdf2eb80 | libaes.so | 0x23b80 -> to: 0x77fdf62d50 | libaes.so | 0x57d50
[call] from: 0x77fdf2ebb8 | libaes.so | 0x23bb8 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf2ebd0 | libaes.so | 0x23bd0 -> to: 0x77fdf62d10 | libaes.so | 0x57d10
[ret] from: 0x77fdf2e9bc | libaes.so | 0x239bc -> to: 0x77fdf2ebd4 | libaes.so | 0x23bd4
[call] from: 0x77fdf2ebdc | libaes.so | 0x23bdc -> to: 0x77fdf62d70 | libaes.so | 0x57d70
[ret] from: 0x77fdf35128 | libaes.so | 0x2a128 -> to: 0x77fdf2ebe0 | libaes.so | 0x23be0
[call] from: 0x77fdf2ebfc | libaes.so | 0x23bfc -> to: 0x77fdf62d80 | libaes.so | 0x57d80
[call] from: 0x77fdf36664 | libaes.so | 0x2b664 -> to: 0x77fdf62f70 | libaes.so | 0x57f70
[ret] from: 0x77fdf35c4c | libaes.so | 0x2ac4c -> to: 0x77fdf36668 | libaes.so | 0x2b668
[call] from: 0x77fdf366b0 | libaes.so | 0x2b6b0 -> to: 0x77fdf30b8c | libaes.so | 0x25b8c
[call] from: 0x77fdf30bb8 | libaes.so | 0x25bb8 -> to: 0x77fdf62eb0 | libaes.so | 0x57eb0
[call] from: 0x77fdf31744 | libaes.so | 0x26744 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf3179c | libaes.so | 0x2679c -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf317f4 | libaes.so | 0x267f4 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf3184c | libaes.so | 0x2684c -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[call] from: 0x77fdf31898 | libaes.so | 0x26898 -> to: 0x77fdf34580 | libaes.so | 0x29580
[ret] from: 0x77fdf34640 | libaes.so | 0x29640 -> to: 0x77fdf3189c | libaes.so | 0x2689c
[ret] from: 0x77fdf324d8 | libaes.so | 0x274d8 -> to: 0x77fdf30bbc | libaes.so | 0x25bbc
[ret] from: 0x77fdf30bc4 | libaes.so | 0x25bc4 -> to: 0x77fdf366b4 | libaes.so | 0x2b6b4
[ret] from: 0x77fdf36764 | libaes.so | 0x2b764 -> to: 0x77fdf2ec00 | libaes.so | 0x23c00
[call] from: 0x77fdf2ed68 | libaes.so | 0x23d68 -> to: 0x77fdf62d50 | libaes.so | 0x57d50
[call] from: 0x77fdf2ed80 | libaes.so | 0x23d80 -> to: 0x77fdf62db0 | libaes.so | 0x57db0
[call] from: 0x77fdf35fcc | libaes.so | 0x2afcc -> to: 0x77fdf62f70 | libaes.so | 0x57f70
[ret] from: 0x77fdf35c4c | libaes.so | 0x2ac4c -> to: 0x77fdf35fd0 | libaes.so | 0x2afd0
[call] from: 0x77fdf36190 | libaes.so | 0x2b190 -> to: 0x77fdf30bc8 | libaes.so | 0x25bc8
[call] from: 0x77fdf30bec | libaes.so | 0x25bec -> to: 0x77fdf62ec0 | libaes.so | 0x57ec0
[call] from: 0x77fdf326c8 | libaes.so | 0x276c8 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf3274c | libaes.so | 0x2774c -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf327d0 | libaes.so | 0x277d0 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf32834 | libaes.so | 0x27834 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf32fa8 | libaes.so | 0x27fa8 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf330e8 | libaes.so | 0x280e8 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf33208 | libaes.so | 0x28208 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[call] from: 0x77fdf332f0 | libaes.so | 0x282f0 -> to: 0x77fdf62d60 | libaes.so | 0x57d60
[ret] from: 0x77fdf33334 | libaes.so | 0x28334 -> to: 0x77fdf30bf0 | libaes.so | 0x25bf0
[ret] from: 0x77fdf30bf8 | libaes.so | 0x25bf8 -> to: 0x77fdf36194 | libaes.so | 0x2b194
[ret] from: 0x77fdf3626c | libaes.so | 0x2b26c -> to: 0x77fdf2ed84 | libaes.so | 0x23d84
[call] from: 0x77fdf2ee08 | libaes.so | 0x23e08 -> to: 0x77fdf62dc0 | libaes.so | 0x57dc0
[call] from: 0x77fdf35cc4 | libaes.so | 0x2acc4 -> to: 0x77fdf62f70 | libaes.so | 0x57f70
[ret] from: 0x77fdf35c4c | libaes.so | 0x2ac4c -> to: 0x77fdf35cc8 | libaes.so | 0x2acc8
[call] from: 0x77fdf35d08 | libaes.so | 0x2ad08 -> to: 0x77fdf30f60 | libaes.so | 0x25f60
[ret] from: 0x77fdf30f6c | libaes.so | 0x25f6c -> to: 0x77fdf35d0c | libaes.so | 0x2ad0c
[ret] from: 0x77fdf35d20 | libaes.so | 0x2ad20 -> to: 0x77fdf2ee0c | libaes.so | 0x23e0c
[call] from: 0x77fdf2ee14 | libaes.so | 0x23e14 -> to: 0x77fdf62dd0 | libaes.so | 0x57dd0
[call] from: 0x77fdf2efb0 | libaes.so | 0x23fb0 -> to: 0x780d775280 | libart.so | 0x360280
[ret] from: 0x77fdf2efbc | libaes.so | 0x23fbc -> to: 0x77fdf2ee18 | libaes.so | 0x23e18
[call] from: 0x77fdf2ee30 | libaes.so | 0x23e30 -> to: 0x77fdf62de0 | libaes.so | 0x57de0
[call] from: 0x77fdf2effc | libaes.so | 0x23ffc -> to: 0x780d775690 | libart.so | 0x360690
[ret] from: 0x77fdf2f008 | libaes.so | 0x24008 -> to: 0x77fdf2ee34 | libaes.so | 0x23e34
[call] from: 0x77fdf2ee5c | libaes.so | 0x23e5c -> to: 0x77fdf62df0 | libaes.so | 0x57df0
[call] from: 0x77fdf2ee94 | libaes.so | 0x23e94 -> to: 0x77fdf62df0 | libaes.so | 0x57df0
[call] from: 0x77fdf2eeb4 | libaes.so | 0x23eb4 -> to: 0x77fdf62e00 | libaes.so | 0x57e00
[call] from: 0x77fdf2f040 | libaes.so | 0x24040 -> to: 0x780d775448 | libart.so | 0x360448
[ret] from: 0x77fdf2f04c | libaes.so | 0x2404c -> to: 0x77fdf2eeb8 | libaes.so | 0x23eb8
[call] from: 0x77fdf2eebc | libaes.so | 0x23ebc -> to: 0x77fdf62da0 | libaes.so | 0x57da0
[call] from: 0x77fdf2eec4 | libaes.so | 0x23ec4 -> to: 0x77fdf62da0 | libaes.so | 0x57da0
[ret] from: 0x77fdf2ef10 | libaes.so | 0x23f10 -> to: 0x789143a60c | Unknown | Unknown
```


假如汇编代码中 BLR X8 我们不知道它具体调用的是什么



![word/media/image4.png](https://gitee.com/cyrus-studio/images/raw/master/062fadf6b432ff8d5f50357beb5d163f.png)


通过 onRecive 解析可以知道 调用的是 libaes.so 偏移 0x25f60 的函数



![word/media/image5.png](https://gitee.com/cyrus-studio/images/raw/master/424949bfe7c04835d6077b9f8fdf25e5.png)


用 IDA 打开 libaes.so 并调整到对应的地址，可以找到调用的函数



![word/media/image6.png](https://gitee.com/cyrus-studio/images/raw/master/69527ac7048bd6f720ccc1c316457c47.png)


# hook 所有 call 分析参数



把所有调用到的函数 hook 分析一下；

去掉一些系统 api 的 hook；

如果是跳转表则在 IDA 找到跳转的真实偏移地址。

```
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
    hookNativeAddr(baseAddress.add(0x2AE80));
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
```


附加到当前 app 并执行脚本

```
frida -H 127.0.0.1:1234 -F -l hookNativeAddr.js
```


app 中加密结果



![word/media/image7.png](https://gitee.com/cyrus-studio/images/raw/master/cadf194389cd8668fc99fbab2996057c.png)


在日志中找到第一次出现结果的地方



![word/media/image8.png](https://gitee.com/cyrus-studio/images/raw/master/77bfebd7c93957b339d270208ca6d44f.png)


找到这个函数 call libaes.so | 0x274dc



![word/media/image9.png](https://gitee.com/cyrus-studio/images/raw/master/53f9d4d4ce88bd67b4682d367a824ad0.png)


用 IDA 看这个函数中多处引用到一个全局变量



![word/media/image10.png](https://gitee.com/cyrus-studio/images/raw/master/44a9906e3321c9c3e0569892203cdef7.png)


是一些常量值



![word/media/image11.png](https://gitee.com/cyrus-studio/images/raw/master/9b9aaa0c12cab6e787db3cda9ab41667.png)


搜索看看，是 AES 的特征



![word/media/image12.png](https://gitee.com/cyrus-studio/images/raw/master/2233a082b15cb4aa18144ce68d23e62f.png)


# 打印调用堆栈



打印该函数的调用堆栈看看

```
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

function main() {
    var addr = Module.findBaseAddress("libaes.so").add(0x274DC);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            console.log('called from:\n' +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map((address) => {
                        const symbol = DebugSymbol.fromAddress(address);

                        if (symbol && symbol.name) {
                            // 如果有符号信息，直接显示
                            return `${address} ${symbol.moduleName}!${symbol.name}+0x${symbol.address.sub(Module.findBaseAddress(symbol.moduleName)).toString(16)}`;
                        } else {
                            // 如果没有符号信息，尝试获取模块和偏移信息
                            const module = getModuleByAddressSafe(address);
                            if (module) {
                                const offset = ptr(address).sub(module.base);
                                return `${address} ${module.name} + 0x${offset.toString(16)}`;
                            } else {
                                return `${address} [Unknown]`;
                            }
                        }
                    })
                    .join('\n') + '\n');
        },

        onLeave: function (retval) {}
    });
}

setImmediate(main);
```
相关文档：[https://frida.re/docs/javascript-api/#Thread](https://frida.re/docs/javascript-api/#Thread)



附加到当前 app 并执行脚本

```
frida -H 127.0.0.1:1234 -F -l printStack.js
```


输出如下：

```
[Remote::AndroidExample]-> called from:
0x77fe5f0bf0 libaes.so + 0x25bf0
0x77fe5f0bec libaes.so + 0x25bec
0x77fe5f6190 libaes.so + 0x2b190
0x77fe5eed80 libaes.so + 0x23d80
0x780d554350 libart.so!art_quick_generic_jni_trampoline+0x90+0x13f350
0x780d54b5b8 libart.so!art_quick_invoke_static_stub+0x238+0x1365b8
0x780d55a0cc libart.so!_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+0x114+0x1450cc
0x780d6f6f98 libart.so!_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_11ShadowFrameEtPNS_6JValueE+0x180+0x2e1f98
0x780d6f2024 libart.so!_ZN3art11interpreter6DoCallILb0ELb0EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE+0x384+0x2dd024
0x780d9b81f8 libart.so!MterpInvokeStatic+0x170+0x5a31f8
0x780d545994 libart.so!mterp_op_invoke_static+0x14+0x130994
0x7fd160b0ac [Unknown]
```


开始调用的位置在 0x77fe5eed80 libaes.so + 0x23d80



![word/media/image13.png](https://gitee.com/cyrus-studio/images/raw/master/6fb2251412717fa0a06ed15f82ddf79e.png)


函数真实地址是 0x2ae80



![word/media/image14.png](https://gitee.com/cyrus-studio/images/raw/master/1738e0e620d146f37db5fa441b431f70.png)


在 call libaes.so | 0x2ae80 的 arg3 中找到 key / iv



![word/media/image15.png](https://gitee.com/cyrus-studio/images/raw/master/a74610f9bd72cf12fab78fe1e9038a87.png)


# 验证算法



把 arg3 的 hexdump 复制到 CyberChef 



![word/media/image16.png](https://gitee.com/cyrus-studio/images/raw/master/ecd088c6b859779ce7a657b514c896e8.png)
得到 key / iv 应该是 “CYRUS STUDIO    ”



使用 CyberChef  的 AES CBC 算法加密得到结果和 app 的是一样的。



![word/media/image17.png](https://gitee.com/cyrus-studio/images/raw/master/1268e0ecfa816d78397875d07dbbde34.png)
所有这就是一个标准的 AES CBC 算法，key 和 iv 都是  “CYRUS STUDIO    ”



# Frida Trace



把 exec 设置为 true 也可以当 trace 用

```
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


function main(soName, offset) {
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
    main("libaes.so", 0x274DC)
});
```


附加到当前 app 并执行脚本，并把日志保存到 trace.txt

```
frida -H 127.0.0.1:1234 -F -l trace.js | tee trace.txt
```


效果如下：



![word/media/image18.png](https://gitee.com/cyrus-studio/images/raw/master/6b1f2f80184917ad1c88daabc38345e1.png)


# 完整源码



开源地址：[https://github.com/CYRUS-STUDIO/frida_stalker](https://github.com/CYRUS-STUDIO/frida_stalker)





