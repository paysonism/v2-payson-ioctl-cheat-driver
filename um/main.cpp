#include <iostream>
#include "driver.h"

using namespace std;

auto main() -> void
{
	SetConsoleTitleA("usermode - Payson's ioctl base");
	if (!t1drv::Init()) {
		system("color 2");
		cout << "\n driver communications not initialized.\n";
	}

	t1drv::ProcessIdentifier = t1drv::FindProcessID("explorer.exe");
	
	virtualaddy = t1drv::GetBaseAddress();

	cout << "Process BaseAddress -> " << virtualaddy << "\n";

	/*
	*
	* Example Handling
	*
	* 	read<__int64>(vaworld);
	*	read<uintptr_t>(pointer->uworld + offsets::gameinstance);
	* 
	*/

	cin.get();
}