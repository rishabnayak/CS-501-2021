#include <windows.h>
#include <string>
#include <iostream>
#include <winhttp.h>

wchar_t *charToWChar(char *text)
{
    const size_t size = strlen(text) + 1;
    wchar_t *wText = new wchar_t[size];
    mbstowcs(wText, text, size);
    return wText;
}

std::wstring makeHttpRequest(std::wstring fqdn, int port, std::wstring uri, bool useTLS)
{
    std::wstring result;
    WINHTTPAPI HINTERNET httpSession = WinHttpOpen(L"501_Client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    WINHTTPAPI HINTERNET httpConnection = WinHttpConnect(httpSession, fqdn.c_str(), port, 0);
    unsigned long tlsFlag;
    if (useTLS)
    {
        tlsFlag = WINHTTP_FLAG_SECURE;
    }
    else
    {
        tlsFlag = 0;
    }
    WINHTTPAPI HINTERNET httpRequest = WinHttpOpenRequest(httpConnection, L"GET", NULL, uri.c_str(), WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, tlsFlag);
    DWORD dwflags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    BOOL opt = WinHttpSetOption(httpRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwflags, sizeof(dwflags));
    BOOL req = WinHttpSendRequest(httpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!req)
    {
        printf("%u\n", GetLastError());
        result.append(L"Request Send Failure");
        WinHttpCloseHandle(httpSession);
        WinHttpCloseHandle(httpConnection);
        WinHttpCloseHandle(httpRequest);
        return result;
    }
    BOOL res = WinHttpReceiveResponse(httpRequest, NULL);
    if (!res)
    {
        printf("%u\n", GetLastError());
        result.append(L"Request Response Failure");
        WinHttpCloseHandle(httpSession);
        WinHttpCloseHandle(httpConnection);
        WinHttpCloseHandle(httpRequest);
        return result;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    char *pszOutBuffer;
    do
    {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(httpRequest, &dwSize))
        {
            printf("%u\n", GetLastError());
            result.append(L"WinHttpQueryDataAvailable Error");
        }
        pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer)
        {
            printf("OOM Error\n");
            dwSize = 0;
        }
        else
        {
            ZeroMemory(pszOutBuffer, dwSize + 1);
            if (!WinHttpReadData(httpRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
            {
                printf("%u\n", GetLastError());
                result.append(L"WinHttpReadData Error");
            }
            else
            {
                result.append(charToWChar(pszOutBuffer));
            }
            delete[] pszOutBuffer;
        }
    } while (dwSize > 0);
    WinHttpCloseHandle(httpSession);
    WinHttpCloseHandle(httpConnection);
    WinHttpCloseHandle(httpRequest);
    return result;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 5)
    {
        std::wcout << L"Incorrect number of arguments: you need 4 positional arguemts" << std::endl;
        return 0;
    }

    std::wstring fqdn = std::wstring(argv[1]);
    int port = std::stoi(argv[2]);
    std::wstring uri = std::wstring(argv[3]);
    int useTLS = std::stoi(argv[4]);
    bool tls;
    if (useTLS == 1)
    {
        tls = true;
    }
    else if (useTLS == 0)
    {
        tls = false;
    }
    else
    {
        std::wcout << L"bad value for useTls" << std::endl;
        return 0;
    }
    std::wcout << makeHttpRequest(fqdn, port, uri, tls) << std::endl;
    return 0;
}