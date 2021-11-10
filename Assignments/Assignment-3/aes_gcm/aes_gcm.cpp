#include "aes_gcm.h"
#include <vector>

AESGCM::~AESGCM()
{
    Cleanup();
}

// Freebie: initialize AES class
AESGCM::AESGCM(BYTE key[AES_256_KEY_SIZE])
{
    hAlg = 0;
    hKey = NULL;

    // create a handle to an AES-GCM provider
    nStatus = ::BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", nStatus);
        Cleanup();
        return;
    }
    if (!hAlg)
    {
        wprintf(L"Invalid handle!\n");
    }
    nStatus = ::BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (BYTE *)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty ><\n", nStatus);
        Cleanup();
        return;
    }
    //        bcryptResult = BCryptGenerateSymmetricKey(algHandle, &keyHandle, 0, 0, (PUCHAR)&key[0], key.size(), 0);

    nStatus = ::BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        NULL,
        0,
        key,
        AES_256_KEY_SIZE,
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", nStatus);
        Cleanup();
        return;
    }
    DWORD cbResult = 0;
    nStatus = ::BCryptGetProperty(
        hAlg,
        BCRYPT_AUTH_TAG_LENGTH,
        (BYTE *)&authTagLengths,
        sizeof(authTagLengths),
        &cbResult,
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty when calculating auth tag len\n", nStatus);
    }
}

void AESGCM::Decrypt(BYTE *nonce, size_t nonceLen, BYTE *data, size_t dataLen, BYTE *macTag, size_t macTagLen)
{
    // change me
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag = &tag[0];
    authInfo.cbTag = macTagLen;

    auto status = BCryptDecrypt(hKey, data, dataLen, &authInfo, nonce, nonceLen, NULL, ptBufferSize, &ptBufferSize, 0);
    plaintext = new BYTE[ptBufferSize];
    printf("0x%x\n", status);
    status = BCryptDecrypt(hKey, data, dataLen, &authInfo, nonce, nonceLen, &plaintext[0], ptBufferSize, &ptBufferSize, 0);
    printf("0x%x\n", status);
}

void AESGCM::Encrypt(BYTE *nonce, size_t nonceLen, BYTE *data, size_t dataLen)
{
    // change me

    DWORD encrypted_len = 0;
    tag = new BYTE[authTagLengths.dwMinLength];

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag = &tag[0];
    authInfo.cbTag = authTagLengths.dwMinLength;

    BCryptEncrypt(hKey, data, dataLen, &authInfo, nonce, nonceLen, NULL, encrypted_len, &encrypted_len, 0);
    ciphertext = new BYTE[encrypted_len];
    BCryptEncrypt(hKey, data, dataLen, &authInfo, nonce, nonceLen, &ciphertext[0], encrypted_len, &encrypted_len, 0);
}

void AESGCM::Cleanup()
{
    if (hAlg)
    {
        ::BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    if (hKey)
    {
        ::BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if (tag)
    {
        ::HeapFree(GetProcessHeap(), 0, tag);
        tag = NULL;
    }
    if (ciphertext)
    {
        ::HeapFree(GetProcessHeap(), 0, tag);
        ciphertext = NULL;
    }
    if (plaintext)
    {
        ::HeapFree(GetProcessHeap(), 0, plaintext);
        plaintext = NULL;
    }
}
