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
 * 寄存器变化跟踪，获取当前与上一次相比，返回发生变化的寄存器
 *
 * @param {CpuContext} context
 * @param {CpuContext} lastRegs 上一次寄存器的值
 * @returns {[string, string]} 寄存器名和当前值的数组
 */
function getDiffRegisters(context, lastRegs) {
    const changed = [];

    const regs = Object.entries(JSON.parse(JSON.stringify(context)))

    for (const [key, value] of regs) {

        // 判断寄存器值是否发生变化（不包括 pc 寄存器）
        if ("pc" !== key && value !== lastRegs[key]) {
            changed.push([key, value]);
        }

        // 更新寄存器快照
        lastRegs[key] = value;
    }

    return changed;
}


/**
 * 跟踪指令执行和寄存器变化
 *
 * @param targetModuleName 目标模块名称
 * @param targetSymbol 函数偏移（或导出名）
 */
function traceInstructionAndRegisters(targetModuleName, targetSymbol) {

    // 获取模块基地址
    const base = Module.findBaseAddress(targetModuleName);
    if (base === null) {
        console.error("模块未加载：" + targetModuleName);
        return;
    }

    let targetFuncAddr;

    if (typeof targetSymbol === "string") {
        targetFuncAddr = Module.findExportByName(targetModuleName, targetSymbol);
    } else {
        targetFuncAddr = base.add(ptr(targetSymbol));
    }

    if (!targetFuncAddr) {
        console.error("找不到函数地址");
        return;
    }

    const baseAddr = Module.findBaseAddress(targetModuleName);
    const offset = targetFuncAddr.sub(baseAddr);

    console.log(`🎯 目标函数信息：
      📦 模块名称: ${targetModuleName}
      🧱 模块基址: ${baseAddr}
      📍 函数地址: ${targetFuncAddr}
      🔢 函数偏移: ${offset}`);

    const lastRegs = {};

    // 拦截目标函数，开始跟踪当前线程
    Interceptor.attach(targetFuncAddr, {
        onEnter(args) {
            // 线程 id
            let tid = Process.getCurrentThreadId()
            this.tid = tid
            console.log(`进入函数，开始 trace [${tid}]`);

            // 打印寄存器初始状态
            console.log('寄存器初始状态：' + JSON.stringify(getDiffRegisters(this.context, lastRegs)))

            Stalker.follow(tid, {
                events: {
                    call: false,
                    ret: false,
                    exec: true,
                    block: false,
                    compile: false
                },
                transform(iterator) {
                    let instruction = iterator.next();

                    do {
                        let address = instruction.address

                        const module = getModuleByAddressSafe(address);

                        // 判断是否目标 so 的指令
                        if (module && module.name === targetModuleName) {

                            let modInfo = "";

                            const offset = ptr(address).sub(module.base);

                            // 模块信息
                            modInfo = `[${module.name}!${offset}]`;

                            // 通过 putCallout 拿到 运行时环境（寄存器）
                            iterator.putCallout(function (context) {

                                const instruction = Instruction.parse(ptr(context.pc));

                                let diffRegisters = getDiffRegisters(context, lastRegs)

                                let registers = ''

                                if (diffRegisters.length > 0) {
                                    registers = JSON.stringify(diffRegisters)
                                }

                                console.log(
                                    `[${instruction.address}] ${modInfo} ${instruction.mnemonic} ${instruction.opStr} ${registers}`
                                );
                            })
                        }

                        iterator.keep();

                    } while ((instruction = iterator.next()) !== null);
                },
            });
        },

        onLeave(retval) {
            console.log(`函数退出，停止 trace [${this.tid}]`);
            Stalker.unfollow(this.tid);
        }
    });
}


setImmediate(function () {
    traceInstructionAndRegisters("libnative-lib.so", 0x26058)
});


// frida -H 127.0.0.1:1234 -F -l so_func_tracer.js
