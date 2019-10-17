import idc
import idaapi
import ida_idd
import ida_name
import ida_bytes
import ida_kernwin


# import types for the given macros
idaapi.import_type(idaapi.cvar.idati, 0, "MACRO_NULL")  # for NULL
idaapi.import_type(idaapi.cvar.idati, 0, "MACRO_PAGE")  # for PAGE_EXECUTE_READWRITE
idaapi.import_type(idaapi.cvar.idati, 0, "MACRO_MEM")   # for MEM_COMMIT

# shortcut to constants
c = ida_idd.Appcall.Consts


def allocate_rwx(size):
    # this is the explicit way to create an Appcall callable
    # see also: `Appcall.proto`
    VirtualAlloc = ida_idd.Appcall.typedobj("int __stdcall VirtualAlloc( int lpAddress, DWORD dwSize, DWORD flAllocationType, DWORD flProtect);")
    VirtualAlloc.ea = ida_name.get_name_ea(0, "kernel32_VirtualAlloc")
    ptr = VirtualAlloc(c.NULL, int(size), c.MEM_COMMIT, c.PAGE_EXECUTE_READWRITE)
    if ptr == 0:
        print("VirtualAlloc failed: 0x%x" % GetLastError())
        raise ValueError("VirtualAlloc failed: 0x%x" % GetLastError())
    idc.RefreshDebuggerMemory()
    return ptr
    
    
def GetLastError():
    # this is the concise way to create an Appcall callable.
    # symbol name as found in the workspace and function prototype.
    return ida_idd.Appcall.proto("kernel32_GetLastError", "DWORD __stdcall GetLastError();")()
    
    
LoadLibraryA = ida_idd.Appcall.proto("kernel32_LoadLibraryA", "HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName);")
GetProcAddress = ida_idd.Appcall.proto("kernel32_GetProcAddress", "FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName);")


def get_winapi_decl(name):
    '''
    fetch the C function declaration for the given Windows API function.
    '''
    tup = idaapi.get_named_type(None, name, idaapi.NTF_SYMM)
    if tup is None:
        raise ValueError("failed to fetch type")
    code, type_str, fields_str, cmt, field_cmts, sclass, value = tup
    ti = idaapi.tinfo_t()
    ti.deserialize(None, type_str, fields_str, cmt)

    # the rendered declaration from IDA doesn't include the function name,
    # so insert the function name, naively.
    #
    # for example;
    #
    #    > DWORD (DWORD a, DWORD b)
    #    < DWORD foo(DWORD a, DWORD b);
    decl = str(ti).replace("(", " " + name + "(") + ";"

    return decl


def api(dll, proc):
    '''
    get a callable Windows API function.

    Python>idaapi.require("idawilli.dbg")
    Python>idawilli.dbg.api("kernel32.dll", "SetLastError")(0x31337)
    0x0L
    Python>idawilli.dbg.api("kernel32.dll", "GetLastError")()
    0x31337L
    '''
    hmod = LoadLibraryA(dll)
    pfunc = GetProcAddress(hmod, proc)
    decl = get_winapi_decl(proc)
    return ida_idd.Appcall.proto(pfunc.value, decl)


class _Module(object):
    ''' loaded DLL that supports calling procedures via Appcall '''

    def __init__(self, dll):
        super(_Module, self).__init__()
        self.dll = dll if dll.lower().endswith('.dll') else (dll + '.dll')
        self.hmod = LoadLibraryA(dll).value

    def __getattr__(self, proc):
        if proc == 'dll':
            return super(self, _Module).__getattr__(proc)
        elif proc == 'hmod':
            return super(self, _Module).__getattr__(proc)

        pfunc = GetProcAddress(self.hmod, proc).value
        return ida_idd.Appcall.proto(pfunc, get_winapi_decl(proc))


class _API(object):
    ''' fake object that creates a _Module on demand '''

    def __getattr__(self, dll):
        return _Module(dll)


'''
Python>idaapi.require("idawilli.dbg")
Python>idawilli.dbg.winapi.kernel32.SetLastError(0x31337)
0x0L
Python>idawilli.dbg.winapi.kernel32.GetLastError()
0x31337L
'''
winapi = _API()


def patch_bytes(ea, buf):
    for i, b in enumerate(buf):
        ida_bytes.patch_byte(ea + i, b)
