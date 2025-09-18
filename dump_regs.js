function getModuleByAddressSafe(address) {
    try {
        // 尝试获取模块
        let module = Process.getModuleByAddress(address);
        // 如果模块存在，返回模块
        if (module) {
            return module;
        }
        // 如果没有找到模块，返回 null
    } catch (e) {
        // 捕获异常，返回 null
    }
    return null;
}

/**
 * 自动分析寄存器 JSON 字符串
 * 对每个值尝试解析为地址，如果能获取到模块信息，则在原值后追加模块信息和偏移
 *
 * @param {string} contextJsonStr - JSON.stringify(this.context)
 * @returns {Object} 新对象，每个 key 的 value 保留原始值，并在可解析地址的情况下附加模块信息
 *   例如：
 *   {
 *     pc: "0x7799b0b614 [module: librsig.so, base: 0x7799b00000, size: 0x123456, offset: 0xb614]",
 *     sp: "0x7799ea85d0",
 *     ...
 *   }
 */
function annotateContextWithModule(contextJsonStr) {
    const dict = JSON.parse(contextJsonStr);

    const isBareHex = s => /^[0-9a-fA-F]+$/.test(s);

    const normalizeToPtr = v => {
        const s = v.toString().trim();
        if (s.indexOf('0x') === 0 || s.indexOf('0X') === 0) return ptr(s);
        if (isBareHex(s)) return ptr('0x' + s);
        return ptr(s);
    };

    const out = {};

    Object.keys(dict).forEach(k => {
        const rawVal = dict[k];
        let newVal = rawVal;

        try {
            const p = normalizeToPtr(rawVal);
            const m = getModuleByAddressSafe(p);
            if (m) {
                const offset = p.sub(m.base);
                newVal = `${rawVal} [module: ${m.name}, base: ${m.base}, size: ${m.size}, offset: ${offset}]`;
            }
        } catch (e) {
            // 无法转地址或找不到模块，保留原始值
        }

        out[k] = newVal;
    });

    return out;
}


/**
 * 打印寄存器
 *
 * @param moduleName 目标模块名称
 * @param offset_list 函数偏移列表
 */
function dumpRegs(moduleName, offset_list) {

    // 获取模块基地址（只打印一次模块信息）
    const moduleObj = Process.getModuleByName(moduleName);

    if (moduleObj === null) {
        console.error("模块未加载：" + moduleName);
        return;
    }

    console.log(`📦 模块信息：
      模块名称: ${moduleObj.name}
      模块基址: ${moduleObj.base}
      模块大小: ${moduleObj.size}
      模块路径: ${moduleObj.path}
      `);

    offset_list.forEach(function (off) {

        let target = moduleObj.base.add(ptr(off));

        if (!target) {
            console.error("找不到函数地址: " + off);
            return;
        }

        const offset = target.sub(moduleObj.base);

        // 函数相关信息
        console.log(`🎯 目标函数信息：
          📍 函数地址: ${target}
          🔢 函数偏移: ${offset}`);

        // Hook目标地址
        Interceptor.attach(target, {
            onEnter(args) {
                // 获取寄存器信息
                const annotated = annotateContextWithModule(JSON.stringify(this.context));
                // 格式化打印
                console.log(JSON.stringify(annotated, null, 2));
            },
            onLeave(retval) {
            }
        })
    })
}


setImmediate(function () {
    // 秀动
    dumpRegs("librsig.so", [0xB55B8, 0xB5614])
});


// frida -H 127.0.0.1:1234 -F -l dump_regs.js -o dump_regs.txt
// frida -H 127.0.0.1:1234 -F -l dump_regs.js -o dump_regs.txt --runtime=v8 --debug