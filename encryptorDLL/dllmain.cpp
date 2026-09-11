#include <Windows.h>

//help from: https://www.youtube.com/watch?v=ru5VzUigKqw

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID)
{

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "DLL_PROCESS_ATTACH", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        MessageBoxA(NULL, "DLL_PROCESS_DETACH", "DLL_PROCESS_DETACH", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
