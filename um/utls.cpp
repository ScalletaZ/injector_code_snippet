#include "utls.h"
#include <Windows.h>
#include <TlHelp32.h>

#ifdef DEBUG
unsigned long long GetModuleBaseAddress(unsigned long procId, const wchar_t* modName)
{
	unsigned long long modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (unsigned long long)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}
unsigned long long get_var_offset(void* var)
{
	return unsigned long long(var) - GetModuleBaseAddress(GetCurrentProcessId(), L"ConsoleApplication1.exe");// IQ || too lazy to look for how to get the base address of executable, it was the easiest way
}
//template T
unsigned long long get_updated_var(void* var)
{
	return *(unsigned long long*)((unsigned long long)var);
}
#endif // DEBUG

