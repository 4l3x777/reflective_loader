# Reflective Loader

## Задача - реализовать простейший PE Loader, который будет считывать с диска PE (EXE) и запускать его из памяти

## Основная функция загрузчика

```C++
HANDLE ReflectiveLoader::native_reflective_execution() {
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK* callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    DWORD                       rva;
    PDWORD                      adr;
    PDWORD                      sym;
    PWORD                       ord;
    PBYTE                       ofs;
    PCHAR                       str, name;
    HMODULE                     dll;
    ULONG_PTR                   ptr;
    Start_t                     Start;              // EXE
    LPVOID                      cs = NULL, base, host;
    DWORD                       i, cnt;
    HANDLE                      hThread;
    WCHAR                       buf[MAX_PATH + 1];
    DWORD                       size_of_img;

    base = PE.data();
    dos = (PIMAGE_DOS_HEADER)base;
    nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);

    // before doing anything. check compatibility between exe/dll and host process.
    host = GetModuleHandleA(NULL);
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);

    if (nt->FileHeader.Machine != nthost->FileHeader.Machine) {
        printf("Host process %08lx and file %08lx are not compatible...cannot load.\n",
            nthost->FileHeader.Machine, nt->FileHeader.Machine);
        return NULL;
    }

    printf("Allocating %" PRIi32 " (0x%" PRIx32 ") bytes of RWX memory for file\n",
        nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfImage);

    cs = VirtualAlloc(
        NULL, nt->OptionalHeader.SizeOfImage + 4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (cs == NULL) return NULL;

    printf("Copying Headers\n");
    memcpy(cs, base, nt->OptionalHeader.SizeOfHeaders);

    printf("Copying each section to RWX memory %p\n", cs);
    sh = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy((PBYTE)cs + sh[i].VirtualAddress,
            (PBYTE)base + sh[i].PointerToRawData,
            sh[i].SizeOfRawData);
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    if (rva != 0) {
        printf("Applying Relocations\n");

        ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
        ofs = (PBYTE)cs - nt->OptionalHeader.ImageBase;

        while (ibr->VirtualAddress != 0) {
            list = (PIMAGE_RELOC)(ibr + 1);

            while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
                if (list->type == IMAGE_REL_TYPE) {
                    *(ULONG_PTR*)((PBYTE)cs + ibr->VirtualAddress + list->offset) += (ULONG_PTR)ofs;
                }
                else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
                    printf("ERROR: Unrecognized Relocation type %08lx.\n", list->type);
                    goto pe_cleanup;
                }
                list++;
            }
            ibr = (PIMAGE_BASE_RELOCATION)list;
        }
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (rva != 0) {
        printf("Processing the Import Table\n");

        imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);

        // For each DLL
        for (; imp->Name != 0; imp++) {
            name = RVA2VA(PCHAR, cs, imp->Name);

            printf("Loading %s\n", name);
            dll = LoadLibraryA(name);

            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk);
            ft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);

            // For each API
            for (;; oft++, ft++) {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;

                // Resolve by ordinal?
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    ft->u1.Function = (ULONG_PTR)GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
                }
                else {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)GetProcAddress(dll, ibn->Name);
                }
            }
        }
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;

    if (rva != 0) {
        printf("Processing Delayed Import Table\n");

        del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);

        // For each DLL
        for (; del->DllNameRVA != 0; del++) {
            name = RVA2VA(PCHAR, cs, del->DllNameRVA);

            printf("Loading %s\n", name);
            dll = LoadLibraryA(name);

            if (dll == NULL) continue;

            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
            ft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);

            // For each API
            for (;; oft++, ft++) {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;

                // Resolve by ordinal?
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    ft->u1.Function = (ULONG_PTR)GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
                }
                else {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)GetProcAddress(dll, ibn->Name);
                }
            }
        }
    }

    /**
      Execute TLS callbacks. These are only called when the process starts, not when a thread begins, ends
      or when the process ends. TLS is not fully supported.
    */
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (rva != 0) {
        printf("Processing TLS directory\n");

        tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);

        // address of callbacks is absolute. requires relocation information
        callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        printf("AddressOfCallBacks : %p\n", callbacks);

        if (callbacks) {
            while (*callbacks != NULL) {
                // call function
                printf("Calling %p\n", *callbacks);
                (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    size_of_img = nt->OptionalHeader.SizeOfImage;
    Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);

    printf("Wiping Headers from memory\n");
    memset(cs, 0, nt->OptionalHeader.SizeOfHeaders);
    memset(base, 0, nt->OptionalHeader.SizeOfHeaders);

    // Create a new thread for this process.
    // Since we replaced exit-related API with RtlExitUserThread in IAT, once an exit-related API is called, the
    // thread will simply terminate and return back here. Of course, this doesn't work
    // if the exit-related API is resolved dynamically.
    printf("Creating thread for entrypoint of EXE : %p\n\n", (PVOID)Start);
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);

    if (hThread != NULL) {
        return hThread;
    }
pe_cleanup:
    // if memory allocated
    if (cs != NULL) {
        // release
        printf("Releasing memory\n");
        VirtualFree(cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    }
```

## Tests

### Проверочный MessageBox ASM x86

```C++
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
```

### Проверочный MessageBox x86_64

```C++
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
```

## bin

+ содержит рефлективные загрузчики x86_64 и набор тестовых PE

## Пример работы

![alt text](/img/reflective_loader.gif)
