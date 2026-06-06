VOID Xor(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE bKey, SIZE_T sKeySize)
{
    int j = 0;
    for (size_t i = 0; i < sShellcodeSize; i++) {
        pShellcode[i] ^= bKey[j % sKeySize];
        j++;
    }
}

unsigned char Shellcode[] = {
    // Replace this with encrypted Shellcode
};

unsigned char Key[] = {
    // Replace this with Key
};
