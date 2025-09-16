#!/usr/bin/env python3
# gen_frida_hooks_fixed.py
# Usage: python gen_on_call_summary_hooks.py on_call_summary.txt
# 输出： on_call_summary_hooks.js （与 on_call_summary.txt 同目录）

import sys
import re
from pathlib import Path

TEMPLATE_HEADER = """// Auto-generated Frida hook script
// Generated from: {src}
"""

# 注意这里保持双大括号以避免早期 .format 替换导致问题，
# 但是最后我们会把 '{{' '}}' 替换为 '{' '}' 再写出文件
TEMPLATE_PRINTARG_AND_HOOK = """
function printArg(addr) {{
    // 查找给定地址所在的内存范围
    var range = Process.findRangeByAddress(addr);
    // 如果该地址属于进程中的已知内存范围（例如模块中的数据段或代码段等）
    if (range) {{
        return hexdump(addr) + "\\n";
    }} else {{
        return ptr(addr) + "\\n";
    }}
}}


function hookNativeAddr(addr) {{

    var module = Process.findModuleByAddress(ptr(addr))

    Interceptor.attach(addr, {{
        onEnter: function (args) {{

            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            this.logs = [];

            this.logs.push("call " + (module ? module.name : "unknown") + " | " + (module ? ptr(addr).sub(module.base) : ptr(addr)) + "\\n");
            this.logs.push("arg0:" + printArg(this.arg0));
            this.logs.push("arg1:" + printArg(this.arg1));
            this.logs.push("arg2:" + printArg(this.arg2));
            this.logs.push("arg3:" + printArg(this.arg3));
            this.logs.push("arg4:" + printArg(this.arg4));
        }},

        onLeave: function (retval) {{
            this.logs.push("onLeave arg0:" + printArg(this.arg0));
            this.logs.push("onLeave arg1:" + printArg(this.arg1));
            this.logs.push("onLeave arg2:" + printArg(this.arg2));
            this.logs.push("onLeave arg3:" + printArg(this.arg3));
            this.logs.push("onLeave arg4:" + printArg(this.arg4));
            this.logs.push("retval:" + printArg(retval));
            console.log(this.logs);
        }}
    }});
}}
"""

TEMPLATE_MAIN_MODULE = """
function main() {{
    // 目标 so 基址
    var baseAddress = Module.findBaseAddress("{mod}");

{hooks}
}}

setImmediate(main);
"""


def parse_input(file_path: Path):
    text = file_path.read_text(encoding='utf-8', errors='ignore')
    mods = set(re.findall(r'soName\s*:\s*([^\s]+)', text))
    more_mods = set(re.findall(r'模块\s*:\s*([^\s|]+)', text))
    mods.update(more_mods)
    if not mods:
        maybe = re.findall(r'([A-Za-z0-9_\-]+\.so)', text)
        if maybe:
            mods.update(maybe)

    offsets_by_mod = {}
    call_lines = re.findall(r'调用函数地址:.*', text)
    for line in call_lines:
        m_mod = re.search(r'模块\s*:\s*([^\s|]+)', line)
        modname = m_mod.group(1) if m_mod else None
        m_off = re.search(r'偏移\s*:\s*(0x[0-9a-fA-F]+)', line)
        if m_off:
            off = m_off.group(1).lower()
            if not modname:
                modname = (list(mods)[0] if mods else 'module')
            offsets_by_mod.setdefault(modname, set()).add(off)

    if not offsets_by_mod:
        all_offs = set(re.findall(r'偏移\s*:\s*(0x[0-9a-fA-F]+)', text))
        if all_offs:
            modname = (list(mods)[0] if mods else 'module')
            offsets_by_mod[modname] = set([o.lower() for o in all_offs])

    header_offs = re.findall(r'offset\s*:\s*(0x[0-9a-fA-F]+)', text)
    if header_offs:
        target_mod = (list(mods)[0] if mods else 'module')
        for o in header_offs:
            offsets_by_mod.setdefault(target_mod, set()).add(o.lower())

    for m in mods:
        offsets_by_mod.setdefault(m, set())

    for m in list(offsets_by_mod.keys()):
        offsets_by_mod[m] = sorted(offsets_by_mod[m], key=lambda x: int(x, 16))

    return mods, offsets_by_mod


def gen_hooks_js(src_path: Path, mods, offsets_by_mod):
    out_lines = []
    out_lines.append(TEMPLATE_HEADER.format(src=str(src_path)))
    out_lines.append(TEMPLATE_PRINTARG_AND_HOOK)

    main_blocks = []
    for mod in offsets_by_mod:
        offs = offsets_by_mod[mod]
        if not offs:
            continue
        hook_calls = []
        for off in offs:
            # 这里直接把偏移写成 baseAddress.add(0x...) 形式
            hook_calls.append('    hookNativeAddr(baseAddress.add({}));'.format(off))
        main_block = TEMPLATE_MAIN_MODULE.format(mod=mod, hooks="\n".join(hook_calls))
        main_blocks.append(main_block)

    out_lines.extend(main_blocks)

    # 最终合并并把 '{{' '}}' 还原为 '{' '}'
    final_text = "\n".join(out_lines)
    final_text = final_text.replace("{{", "{").replace("}}", "}")
    return final_text


def main():
    if len(sys.argv) < 2:
        print("Usage: python gen_frida_hooks_fixed.py <input.txt>")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    if not in_path.exists():
        print("Input file not found:", in_path)
        sys.exit(2)

    mods, offsets_by_mod = parse_input(in_path)
    js_text = gen_hooks_js(in_path, mods, offsets_by_mod)

    out_path = in_path.with_name(in_path.stem + "_hooks.js")
    out_path.write_text(js_text, encoding='utf-8')
    print("Generated JS saved to:", out_path)
    print("Modules found:", ", ".join(sorted(mods)) if mods else "(none)")
    print("Offsets by module:")
    for m, offs in offsets_by_mod.items():
        print("  {}: {}".format(m, ", ".join(offs) if offs else "(none)"))


if __name__ == "__main__":
    main()
