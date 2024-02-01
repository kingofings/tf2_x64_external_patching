#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>

#define FUNCTION_ADDRESS 0x0000000000aeab90

#define PATCH_OFFSET 9245


unsigned long GetBaseAddress(pid_t pid)
{
    char mapsFile[256];
    snprintf(mapsFile, sizeof(mapsFile), "/proc/%d/maps", pid);

    FILE* pFile = fopen(mapsFile, "r");
    if (!pFile)
    {
        perror("Failed to open maps file");
        return 0;
    }

    char line[256];
    unsigned long baseAddress = 0;

    while (fgets(line, sizeof(line), pFile))
    {
        if (strstr(line, "server_srv.so") != NULL && strstr(line, "r--p") != NULL)
        {
            baseAddress = strtoul(line, NULL, 16);
            break;
        }
    }

    fclose(pFile);
    return baseAddress;
}


int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <pid to attach>\n", argv[0]);
        return 1;
    }


    printf("PID ARG: %s\n", argv[1]);
    pid_t targetPid = atoi(argv[1]);

    printf("Target pid %d\n", targetPid);

    if (ptrace(PTRACE_ATTACH, targetPid, NULL, NULL) == -1)
    {
        perror("ptrace attach");
        return 1;
    }

    printf("Attached to %d\n", targetPid);
    printf("Waiting for %d\n", targetPid);
    waitpid(targetPid, NULL, 0);


    unsigned long baseAddress = GetBaseAddress(targetPid);

    printf("Base Address of pid %d is 0x%lx\n", targetPid, baseAddress);

    unsigned long jumpPatch = baseAddress + FUNCTION_ADDRESS + PATCH_OFFSET;

    printf("JumpPatch address of pid %d is 0x%lx\n", targetPid, jumpPatch);

    long originalWord = ptrace(PTRACE_PEEKDATA, targetPid, jumpPatch, NULL);

    unsigned char* bytePointer = (unsigned char*)&originalWord;
    //Patch the 2nd byte to change jbe to jo

    printf("Byte Pointer Sequence Pre: ");
    for (int i = 0; i < sizeof(originalWord); ++i)
    {
        if (i > 1)break;

        switch (i)
        {
            case 0:
                if (bytePointer[i] != 0x0F)
                {
                    printf("Byte sequence does not match exiting!");
                    exit(1);
                }
                break;

            case 1:
                if (bytePointer[i] != 0x86)
                {
                    printf("Byte sequence does not match exiting!");
                    exit(1);
                }
                break;
        }
        printf("%02x ", bytePointer[i]);
    }
    printf("\n");

    bytePointer[1] = 0x80;

    printf("Byte Pointer Sequence Post: ");
    for (int i = 0; i < sizeof(originalWord); ++i)
    {
        printf("%02x ", bytePointer[i]);
    }

    if (ptrace(PTRACE_POKEDATA, targetPid, jumpPatch, originalWord) == -1)
    {
        if (errno == EIO)
        {
            perror("ptrace POKEDATA - Write Error");
        }


        perror("ptrace POKEDATA");
        exit(1);
    }

    printf("Wrote 0x80 to function address at the 2nd byte!\n");

    if (ptrace(PTRACE_DETACH, targetPid, NULL, NULL) == -1)
    {
        perror("ptrace detach");
        exit(1);
    }

    printf("Detached from process %d\n", targetPid);

    return 0;
}
