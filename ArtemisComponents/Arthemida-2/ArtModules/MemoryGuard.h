/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
/**
* Assignee: holmes0
* Done: 
*		Hook NtProtectVirtualMemory and block changes to executable memory
*		Keep constantly updated list of memory page rights in order to detect any external modifications
*			This still allows fast external protection changing and writing, impossible to perfectly protect from usermode.
* 
*		(FIXED) Bug: Page containing NtProtectVirtualMemory remains with PAGE_READWRITE_EXECUTE rights for hook library to remove and place hook back (consider switching to another library).
*
* TBD:
*		WIP Enhancement: Multithreaded (faster) scanning to detect and prevent patching.
*/
#include "../API/ArtemisInterface.h"
#include "xxh3.h"

void __stdcall MemoryGuardScanner(ArtemisConfig* cfg);
