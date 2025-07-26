#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

BOOL DownloadFile(const char *url, const char *output_path) {
    HINTERNET hInternet = InternetOpenA("MyDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    FILE *file = fopen(output_path, "wb");
    if (!file) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    BYTE buffer[4096];
    DWORD bytes_read;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
        fwrite(buffer, 1, bytes_read, file);
    }

    fclose(file);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return TRUE;
}

int main() {
    if (DownloadFile("http://192.168.100.5:8000/win_service32.exe", "downloaded.exe")) {
        printf("Download successful!\n");
    } else {
        printf("Download failed!\n");
    }
    return 0;
}