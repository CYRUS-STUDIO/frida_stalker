#!/usr/bin/env python3
# gen_frida_hooks_single_main.py
# Usage: python gen_on_receive_hooks.py on_receive.txt
# Output: <input_stem>_hooks.js

import sys
import re
from pathlib import Path
from string import Template

JS_HEADER = Template("""// Auto-generated Frida hook script (generated from: $src)

function printArg(addr) {
    var range = Process.findRangeByAddress(addr);
    if (range) {
        return hexdump(addr) + "\\n";
    } else {
        return ptr(addr) + "\\n";
    }
}

function hookNativeAddr(addr) {
    var module = Process.findModuleByAddress(ptr(addr));
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.arg0 = args[0]; this.arg1 = args[1]; this.arg2 = args[2];
            this.arg3 = args[3]; this.arg4 = args[4];
            this.logs = [];
            this.logs.push("call " + (module ? module.name : "unknown") + " | " + (module ? ptr(addr).sub(module.base) : ptr(addr)) + "\\n");
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

""")

MAIN_TMPL = Template("""
function main() {
$base_vars

$hook_calls
}

setImmediate(main);
""")

def sanitize_varname(modname):
    v = re.sub(r'[^0-9a-zA-Z_]', '_', modname)
    if re.match(r'^[0-9]', v):
        v = '_' + v
    return "base_" + v

def parse_to_entries(text):
    """
    Parse in-file occurrences of "to: 0xADDR | modulename | 0xOFFSET"
    Only consider lines that contain '[call]' (case-insensitive).
    Return list of tuples in original order: [(mod, offset, orig_line), ...]
    """
    pattern = re.compile(r'\bto:\s*(0x[0-9a-fA-F]+)\s*\|\s*([^\s|]+)\s*\|\s*(0x[0-9a-fA-F]+)', re.IGNORECASE)
    entries = []
    for line in text.splitlines():
        if '[call]' not in line.lower():
            continue  # skip non-call lines (including [ret])
        m = pattern.search(line)
        if m:
            mod = m.group(2)
            off = m.group(3).lower()
            orig = line.strip()
            entries.append((mod, off, orig))
    return entries

def unique_preserve_order(entries):
    """
    entries: list of (mod, off, orig_line)
    returns deduped list preserving first occurrence order
    """
    seen = set()
    out = []
    for mod, off, orig in entries:
        key = (mod, off)
        if key in seen:
            continue
        seen.add(key)
        out.append((mod, off, orig))
    return out

def gen_js(src_path: Path, ordered_entries):
    # collect unique modules preserving first-appearance order
    mods_in_order = []
    for mod, _, _ in ordered_entries:
        if mod not in mods_in_order:
            mods_in_order.append(mod)

    # build base variable declarations
    base_lines = []
    for mod in mods_in_order:
        var = sanitize_varname(mod)
        base_lines.append(f"    var {var} = Module.findBaseAddress(\"{mod}\");")
    base_block = "\n".join(base_lines) if base_lines else "    // no modules found"

    # build hook calls in original order, using the original matched line as comment
    hook_lines = []
    for mod, off, orig in ordered_entries:
        var = sanitize_varname(mod)
        # Escape '/*' and '*/' defensively to avoid breaking comment blocks
        safe_comment = orig.replace("/*", "/ *").replace("*/", "* /")
        hook_lines.append(f"    // {safe_comment}")
        hook_lines.append(f"    hookNativeAddr({var}.add({off}));")
    hook_block = "\n".join(hook_lines) if hook_lines else "    // no hooks generated"

    main = MAIN_TMPL.substitute(base_vars=base_block, hook_calls=hook_block)
    full = JS_HEADER.substitute(src=str(src_path)) + main
    return full

def main():
    if len(sys.argv) < 2:
        print("Usage: python gen_frida_hooks_single_main.py <input.txt>")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    if not in_path.exists():
        print("Input file not found:", in_path)
        sys.exit(2)

    text = in_path.read_text(encoding='utf-8', errors='ignore')
    entries = parse_to_entries(text)
    if not entries:
        print("No '[call]' to:' entries found in file.")
        sys.exit(0)

    ordered = unique_preserve_order(entries)
    js_text = gen_js(in_path, ordered)

    out_path = in_path.with_name(in_path.stem + "_hooks.js")
    out_path.write_text(js_text, encoding='utf-8')
    print("Generated:", out_path)
    print("Entries (in order):")
    for mod, off, orig in ordered:
        print(f"  {mod} {off}  // {orig}")

if __name__ == "__main__":
    main()
