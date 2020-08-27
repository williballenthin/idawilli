from idaapi import *
from idc import *

# This script prompts for the path to a file
#   which contains a three column, whitespace-delimited list
#   
#   addr      deref'd  function
#   00bca02c  77dd79c6 ADVAPI32!InitializeSecurityDescriptor


def SetName(ea, s):    
    idaapi.set_name(ea, s)
    
    
def is_32():
    try:
        _ = __EA64__
        return False
    except:
        return True
      

def make_pointer(ea):
    if is_32():
        MakeUnkn(ea, 4)
        MakeDword(ea)
    else:
        MakeUnkn(ea, 8)
        MakeQword(ea)
    
# --------------------------------------------------------------------------
class MyForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM
<#Select an annotation file to open#Browse to open:{iFileOpen}>
""", { 'iFileOpen': Form.FileInput(open=True), })      

    def OnFormChange(self, fid):
        return 1
    
try:
    f = MyForm()
    f.Compile()
    f.iFileOpen.value = ""
    ok = f.Execute()
    if ok == 1:
        print f.iFileOpen.value
        with open(f.iFileOpen.value, "rb") as g:
            for line in g.read().split("\n"):
                line = line.replace("`", "")
                parts = line.split(" ")
                if len(parts) != 4:
                    continue
                try:
                    address = int(parts[0], 0x10)
                except:
                    continue
                function = parts[3].strip()
                dll, _, name = function.partition("!")
                print "%s %s" % (hex(address), name)
                
                make_pointer(address)
                SetName(address, name)
    f.Free()
except Exception as e:
    print "Unexpected error: ", e
print "Done."
