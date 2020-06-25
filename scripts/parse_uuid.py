import uuid

import ida_bytes
import ida_kernwin


buf = ida_bytes.get_bytes(ida_kernwin.get_screen_ea(), 0x10)
uid = uuid.UUID(bytes_le=buf)
print(uid)
