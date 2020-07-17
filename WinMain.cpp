#include <Windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

int RealMain()
{
  //check Args
}

int checkUrl()
{
  HANDLE hInt;
  HANDLE hUrl;
  hInt = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
  hUrl = InternetOpenUrl(hInt, L"http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, NULL);
  if (hUrl)
  {
    InternetCloseHandle(hUrl);
    ExitProcess(0);
  }
  else {
    RealMain();
  }
  InternetCloseHandle(hInt);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    return 0;
}
