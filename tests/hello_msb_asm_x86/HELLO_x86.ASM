format PE GUI; at 0xfe0000

include '..\include\win32ax.inc'

.code

  start:
        invoke  MessageBox,HWND_DESKTOP,"Hi! I'm the example program from .code!",invoke GetCommandLine,MB_OK
        db 4096 dup(0x90)
        invoke  MessageBox,HWND_DESKTOP,"Hi! I'm the example program from .code!",invoke GetCommandLine,MB_OK
        db 4096 dup(0x90)
        invoke  MessageBox,HWND_DESKTOP,"Hi! I'm the example program from .code!",invoke GetCommandLine,MB_OK
        jmp Start2

.end start

section 'code2' readable writeable executable
 Start2:
        invoke  MessageBox,HWND_DESKTOP,"Hi! I'm the example program from code2!",invoke GetCommandLine,MB_OK
        invoke  ExitProcess,0

section '.reloc' fixups data readable discardable       ; needed for Win32s