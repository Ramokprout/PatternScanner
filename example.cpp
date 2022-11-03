#define PATTERNSCAN_VERBOSE
#include "include/patternScanner.h"


DWORD WINAPI Main(HMODULE hModule) {
    
    AllocConsole();
    FILE* File;
    freopen_s(&File, "CONOUT$", "w", stdout);

    PatternScanner *scanner = new PatternScanner(nullptr, ".text");
    uintptr_t address = scanner->scanPattern("48 8B 05 ?? ?? ?? ?? C1 F9 10 48 63 C9 48 8B 14 C8 4B 8D 0C 40 4C 8D 04 CA", 0, true, 7);
    printf("addr: 0x%llX\n", address);

    FreeConsole();
    FreeLibraryAndExitThread(hModule, 1);

    return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  reason,
                       LPVOID lpReserved
                     )
{
    if (reason == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Main, hModule, 0, nullptr);
    }
    return TRUE;
}

