# This script prompts for the path to a file
#   which contains a two column, whitespace-delimited list
#   
#   addr     function
#   00bca02c ADVAPI32!InitializeSecurityDescriptor
import ida_kernwin
import ida_idaapi
import ida_bytes
import ida_name

    
def get_bitness():
    info = ida_idaapi.get_inf_structure()

    if info.is_64bit():
        return 64
    elif info.is_32bit():
        return 32
    else:
        return 16
      

def make_pointer(ea):
    if get_bitness() == 16:
        ida_bytes.create_word(ea, 2)

    elif get_bitness() == 32:
        ida_bytes.create_dword(ea, 4)

    elif get_bitness() == 64:
        ida_bytes.create_qword(ea, 8)

    else:
        raise RuntimeError("unexpected bitness")
    
# --------------------------------------------------------------------------
class MyForm(ida_kernwin.Form):
    def __init__(self):
        ida_kernwin.Form.__init__(self, r"""select map file
        <#Select an annotation file to open#Browse to open:{iFileOpen}>
        """,
        { 'iFileOpen': ida_kernwin.Form.FileInput(open=True)})      

    def OnFormChange(self, fid):
        return 1

def prompt_file():
    f = ida_kernwin.Form(
        r"""select map file
            <#Select an annotation file to open#Browse to open:{iFileOpen}>
        """,
        { 'iFileOpen': ida_kernwin.Form.FileInput(open=True)})      
    f.Compile()
    f.iFileOpen.value = ""
    ok = f.Execute()
    assert(ok == 1)
    path = f.iFileOpen.value
    f.Free()
    return path
    

with open(prompt_file(), "rb") as f:
    for line in f.read().decode("utf-8").split("\n"):
        line = line.replace("`", "")

        # split by any whitespace
        parts = line.split()

        if len(parts) != 2:
            print("skipping line: " + line)
            continue

        try:
            address = int(parts[0], 0x10)
        except:
            print("skipping line: " + line)
            continue

        function = parts[1].strip()
        if "!" in function:
            dll, _, name = function.partition("!")
        else:
            name = function

        print("%s %s" % (hex(address), name))
        
        make_pointer(address)
        ida_name.set_name(address, name)

print("Done.")