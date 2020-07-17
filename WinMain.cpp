//https://medium.com/@yogeshojha/reverse-engineering-wannacry-ransomware-using-ghidra-finding-the-killswitch-a212807e9354
//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/

#include <Windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

int RealMain()
{
  //check Args
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    char szUrl[] = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";
    HINTERNET hInternet;
    HINTERNET hUrl;
    hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    hUrl = InternetOpenUrl(hInternet, szUrl, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, NULL);
    if (hUrl)
    {
      InternetCloseHandle(hUrl);
      ExitProcess(0);
    }
    else {
      RealMain();
    }
    InternetCloseHandle(hInternet);
    return 0;
}
