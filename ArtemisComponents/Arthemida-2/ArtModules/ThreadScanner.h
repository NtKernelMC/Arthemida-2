/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
void __stdcall ScanForDllThreads(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->ThreadScanner) return;
	cfg->ThreadScanner = true;
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ScanForDllThreads!\n");
#endif
	typedef NTSTATUS(__stdcall* tNtQueryInformationThread)(HANDLE ThreadHandle, 
	THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	HANDLE targetThread = nullptr; tNtQueryInformationThread NtQueryInformationThread = nullptr;
	PVOID mAddrr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
	if (mAddrr != nullptr) NtQueryInformationThread = (tNtQueryInformationThread)mAddrr;
	while (true) 
	{
		THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
				{
					targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); 
					if (targetThread != nullptr)
					{
						SuspendThread(targetThread); DWORD_PTR tempBase = 0x0;
						NtQueryInformationThread(targetThread, (THREADINFOCLASS)9, &tempBase, sizeof(DWORD_PTR), NULL);  
						ResumeThread(targetThread); CloseHandle(targetThread); 
						if (!Utils::IsMemoryInModuledRange((LPVOID)tempBase) && 
						!Utils::IsVecContain(cfg->ExcludedThreads, (LPVOID)tempBase))
						{
							MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data; data.EmptyVersionInfo = true;
							VirtualQuery((LPCVOID)tempBase, &mme, sizeof(MEMORY_BASIC_INFORMATION)); 
							data.baseAddr = (LPVOID)tempBase; 
							data.MemoryRights = mme.AllocationProtect; 
							data.regionSize = mme.RegionSize;
							data.type = DetectionType::ART_ILLEGAL_THREAD;
							data.dllName = "unknown"; data.dllPath = "unknown";
							cfg->callback(&data); cfg->ExcludedThreads.push_back((LPVOID)tempBase);
							break;
						}
					}
				}
			} while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
		Sleep(cfg->ThreadScanDelay);
	}
}