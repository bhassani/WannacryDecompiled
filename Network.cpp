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
