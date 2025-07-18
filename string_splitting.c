#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

int main(){
	
	

	char full_string_1[10];	// cmd.exe
	char part_string_1_1[] = "c";
	char part_string_1_2[] = "m";
	char part_string_1_3[] = "d";
	char part_string_1_4[] = ".";
	char part_string_1_5[] = "e";
	char part_string_1_6[] = "x";
	char part_string_1_7[] = "e";
	
	/*
	char part_string_1_8[] = "nd";
	char part_string_1_9[] = "ow";
	char part_string_1_10[] = "s\\";
	char part_string_1_11[] = "T";
	char part_string_1_12[] = "e";
	char part_string_1_13[] = "mp\\";
	char part_string_1_14[] = "SSS";
	char part_string_1_15[] = "_";
	char part_string_1_16[] = "ce";
	char part_string_1_17[] = "1";
	char part_string_1_18[] = "aaa";
	char part_string_1_19[] = "99ce";
	char part_string_1_20[] = "4bdb";
	char part_string_1_21[] = "0101";
	char part_string_1_22[] = "000000";
	char part_string_1_23[] = "984b2414";
	char part_string_1_24[] = "aa";
	char part_string_1_25[] = "\\";
	char part_string_1_26[] = "d";
	char part_string_1_27[] = "u";
	char part_string_1_28[] = "m";
	char part_string_1_29[] = "p";
	char part_string_1_30[] = "f";
	char part_string_1_31[] = "i";
	char part_string_1_32[] = "l";
	char part_string_1_33[] = "e";
	char part_string_1_34[] = ".";
	char part_string_1_35[] = "d";
	char part_string_1_36[] = "m";
	char part_string_1_37[] = "p";
	*/
	
	strcpy(full_string_1, part_string_1_1);
	strcat(full_string_1, part_string_1_2);
	strcat(full_string_1, part_string_1_3);
	strcat(full_string_1, part_string_1_4);
	strcat(full_string_1, part_string_1_5);
	strcat(full_string_1, part_string_1_6);
	strcat(full_string_1, part_string_1_7);
	
	/*
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
	*/

	printf("%s\n",full_string_1);
	
	/*
	wchar_t full_string_1[10];	// L"Kernel32"
	wchar_t part_1_1[] = L"K";
	wchar_t part_1_2[] = L"e";
	wchar_t part_1_3[] = L"r";
	wchar_t part_1_4[] = L"n";
	wchar_t part_1_5[] = L"e";
	wchar_t part_1_6[] = L"l";
	wchar_t part_1_7[] = L"3";
	wchar_t part_1_8[] = L"2";
	//wchar_t part_1_9[] = L"";
	//wchar_t part_1_10[] = L"";
	//wchar_t part_1_11[] = L"";
	printf("size of Kernel32 -> %d\n",sizeof(L"Kernel32"));
	wcscpy(full_string_1, part_1_1);
	wcscat(full_string_1, part_1_2);
	wcscat(full_string_1, part_1_3);
	wcscat(full_string_1, part_1_4);
	wcscat(full_string_1, part_1_5);
	wcscat(full_string_1, part_1_6);
	wcscat(full_string_1, part_1_7);
	wcscat(full_string_1, part_1_8);
	//wcscat(full_string_1, part_1_9);
	//wcscat(full_string_1, part_1_10);
	//wcscat(full_string_1, part_1_11);
	printf("size of Kernel32 after concat-> %d\n",sizeof(full_string_1));
	wprintf(L"%s\n",full_string_1);
	*/




	
	
	//printf("[+] the full string -> %s\n",full_string_1);
	
	return 0;
}