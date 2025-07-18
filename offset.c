#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


void obfuscate(ALL_ALPHANUM,original)
	char * ALL_ALPHANUM;
	char * original;
{
	for (int i=0; i<strlen(original); i++){
		for (int j=0; j<strlen(ALL_ALPHANUM); j++){
			if (original[i] == ALL_ALPHANUM[j]){
				printf("%d,",j);
			}
		}
	}
	return;
}


char *GetOriginal(int offsets[],char * ALL_ALPHANUM, int sizeof_offset){
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char *empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
        printf("Memory allocation failed\n");
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

int main(void){
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
	
	// the obfuscate function is responsible for giving u the offset
	char offset[]="NtFreeVirtualMemory";
	obfuscate(ALL_ALPHANUM,offset);
	
	// the GetOriginal function is responsible for returning the obfuscated offset into the original form
	int get_offset[] = {39,19,31,17,4,4,47,8,17,19,20,0,11,38,4,12,14,17,24};
	char *TESTING = GetOriginal(get_offset,ALL_ALPHANUM,sizeof(get_offset));
	printf("\n");
	for (int i = 0; i < strlen(TESTING); i++){
		printf("%c",TESTING[i]);
	}
	return 0;

}