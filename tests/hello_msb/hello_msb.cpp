#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[]) {
    MessageBoxA(
        HWND_DESKTOP,
        (LPCSTR)"Hi! I'm the example program from .code!",
        (LPCSTR)GetCommandLineA(),
        MB_OK
    );

    return 0;
}
