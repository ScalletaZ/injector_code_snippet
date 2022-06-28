#pragma once
#define DEBUG // if you remove it, then all static offsets will shift to an unknown value :)
#ifdef DEBUG
unsigned long long GetModuleBaseAddress(unsigned long procId, const wchar_t* modName);
unsigned long long get_var_offset(void* var);
unsigned long long get_updated_var(void* var);
#endif // DEBUG