from pymem import Pymem
from pymem.memory import read_int, read_uchar
from pymem.pattern import pattern_scan_all

def scanFunc(process, pattern, isCall):
    # Find an occurance of the pattern.
    address = pattern_scan_all(process.process_handle, pattern)
    if isCall:
        # The address will be relative to the instruction, also add 5 for the instruction size itself.
        address += read_int(process.process_handle, address + 1) + 5
    # Rebase and return the address.
    return address - process.base_address

try:
    # Get the process.
    process = Pymem("Windows10Universal.exe")
    handle = process.process_handle

    # Find functions.
    print("\033[1m" + "Function offsets:" + "\033[0m")
    print("get_scheduler ", hex(scanFunc(process, b"\\xE8....\\x8D\\x7E\\x68", True)))
    print("get_state     ", hex(scanFunc(process, b"\\xE8....\\x8B\\xF0\\x8D\\x8D\\xA8\\xFD\\xFF\\xFF", True)))
    print("luavm_load    ", hex(scanFunc(process, b"\\xE8....\\x8B\\xD0\\x64\\xA1", True)))
    print("task_spawn    ", hex(scanFunc(process, b"\\x55\\x8B\\xEC\\x6A\\xFF\\x68....\\x64\\xA1\\x00\\x00\\x00\\x00\\x50\\x83\\xEC.\\xA1....\\x33\\xC5\\x89\\x45\\xEC\\x56\\x57\\x50\\x8D\\x45\\xF4\\x64\\xA3\\x00\\x00\\x00\\x00\\x8B\\x75.\\xC7\\x45\\xE8", False)))
    print("print         ", hex(scanFunc(process, b"\\xE8....\\x0F\\xBF\\x45\\xF8", True)))

    # Find offsets.
    top_base = pattern_scan_all(handle, b"\\x8B\\x47.\\x2B\\x47.\\xC1\\xF8\\x04\\x3B\\xC1")
    extraspace_identity = pattern_scan_all(handle, b"\\x8B\\x47.\\x0F\\x10\\x40.\\x0F\\x11\\x85\\x68\\xFF\\xFF\\xFF")

    print("\n\033[1m" + "Other offsets:" + "\033[0m")
    print("top           ", read_uchar(handle, top_base + 2))
    print("base          ", read_uchar(handle, top_base + 5))
    print("extra_space   ", read_uchar(handle, extraspace_identity + 2))
    print("identity      ", read_uchar(handle, extraspace_identity + 6))
except:
    # This usually happens when roblox isn't opened or the patterns are wrong.
    print("Something went wrong, is roblox opened?")
