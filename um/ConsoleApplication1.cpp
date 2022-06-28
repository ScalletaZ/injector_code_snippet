static unsigned long	  target_pid		= 0;
static unsigned long long asm_executor_base	= 0;
static unsigned long long execute_status	= 0;
#pragma optimize("", off)

#include "utls.h"

#include <iostream>
#include <Windows.h>

#include "crypter.h"
using namespace std;


int main()
{
	unsigned long target_thread_id = GetWindowThreadProcessId(FindWindow(E(L"UnityWndClass"), NULL), &target_pid);

	#ifdef DEBUG
	cout << E("#define target_pid_offset 0x")			<< uppercase << hex << get_var_offset(&target_pid) << endl;
	cout << E("#define asm_executor_base_offset 0x")	<< uppercase << hex << get_var_offset(&asm_executor_base) << endl;
	cout << E("#define execute_status_offset 0x")		<< uppercase << hex << get_var_offset(&execute_status) << endl;
	#endif // DEBUG

	if (target_pid && target_thread_id) 
	{
		while (!get_updated_var(&asm_executor_base)); 

		HMODULE nt_dll = LoadLibraryW(E(L"ntdll.dll"));
		cout << E("[info] Ready to trigger memory: 0x") << hex << asm_executor_base << endl;

		HHOOK h_hook = SetWindowsHookEx(WH_MOUSE, (HOOKPROC)asm_executor_base, nt_dll, target_thread_id);
		//WH_MOUSE
	
		execute_status = 0x10101;
		while (get_updated_var(&execute_status) == 0x10101);

		UnhookWindowsHookEx(h_hook);

		cout << E("[info] Memory triggered") << endl;
	}
	cin.get();
}