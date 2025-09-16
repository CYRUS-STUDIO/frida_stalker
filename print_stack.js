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
