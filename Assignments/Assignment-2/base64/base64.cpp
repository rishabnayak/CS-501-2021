#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <cstdint>

//hint: use CRYPT_STRING_BASE64

std::wstring b64Encode(std::vector<uint8_t> binaryData)
{
    // note that this will convert your std::string into a c string.
    auto rawData = binaryData.data();
    std::wstring returnBuff;
    // your code here
    // Hint: you should make two calls to ::CryptBinaryToStringW
    // One to get the right size for the buffer
    // Then one to copy the data over
    // std::vector<uint8_t> is a perfectly fine container for raw binary  data
    // as it is allocated in contiguous chunks of memory
    // you can also easily convert it to raw data via returnBuff.data()

    //change me
    DWORD buffLength = 0;
    BOOL bRet;

    bRet = CryptBinaryToStringW(rawData, binaryData.size(), CRYPT_STRING_BASE64, NULL, &buffLength);
    if (bRet)
    {
        returnBuff.resize(buffLength);
        CryptBinaryToStringW(rawData, binaryData.size(), CRYPT_STRING_BASE64, &returnBuff[0], &buffLength);
    }
    else
    {
        printf("%u\n", GetLastError());
    }

    return returnBuff;
}

std::vector<uint8_t> b64Decode(std::wstring myString)
{
    // as before you should make two calls to ::CryptStringToBinaryW
    DWORD binaryBuffLength = 0;
    std::vector<uint8_t> binaryData;
    BOOL bRet;
    bRet = CryptStringToBinaryW(myString.c_str(), myString.length(), CRYPT_STRING_BASE64, NULL, &binaryBuffLength, NULL, NULL);
    if (bRet)
    {
        binaryData.resize(binaryBuffLength);
        CryptStringToBinaryW(myString.c_str(), myString.length(), CRYPT_STRING_BASE64, &binaryData[0], &binaryBuffLength, NULL, NULL);
    }
    else
    {
        printf("%u\n", GetLastError());
    }
    return binaryData;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 3)
    {
        std::wcout << L"Incorrect number of arguments" << std::endl;
        return 0;
    }
    std::wstring action = std::wstring(argv[1]);

    std::wstring dataString = std::wstring(argv[2]);

    if (action == L"decode")
    {
        // in this case, we assume the raw data happens to also be a string
        auto resultVector = b64Decode(dataString);
        std::wstring resultStr(resultVector.begin(), resultVector.end());
        // note needs to be none null
        std::wcout << resultStr << std::endl;
    }
    else if (action == L"encode")
    {
        // note this removes the null terminator
        std::vector<uint8_t> stringData(dataString.begin(), dataString.end());

        std::wcout << b64Encode(stringData) << std::endl;
    }
    else
    {
        std::wcout << L"Wrong action: use either decode of encode" << std::endl;
    }
    return 0;
}