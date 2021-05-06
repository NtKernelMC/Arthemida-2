/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC
*/
void __stdcall ThreatReport(ArtemisConfig* cfg, const DWORD &caller, 
const std::string& possible_name, const std::string& MappedName, bool &cloacked)
{
	if (cfg == nullptr) return; if (cfg->callback == nullptr) return;
	MEMORY_BASIC_INFORMATION mme { 0 }; ARTEMIS_DATA data;
	VirtualQuery((PVOID)caller, &mme, sizeof(MEMORY_BASIC_INFORMATION));
	data.baseAddr = (PVOID)caller; data.MemoryRights = mme.AllocationProtect;
	data.regionSize = mme.RegionSize; data.type = 
	(cloacked ? DetectionType::ART_DLL_CLOACKING : DetectionType::ART_ILLEGAL_THREAD);
	data.dllName = cloacked ? possible_name : " "; data.dllPath = cloacked ? MappedName : " ";
	cfg->callback(&data); cfg->ExcludedThreads.push_back((PVOID)caller);
}
void __stdcall LdrInitializeThunk(PCONTEXT Context)
{
	PVOID TEP = reinterpret_cast<PVOID>(Context->Eax);
	PVOID ARG = reinterpret_cast<PVOID>(Context->Ebx);
	ArtemisConfig* cfg = IArtemisInterface::GetConfig();
	if (cfg == nullptr) __asm jmp memTramplin
	char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
	lpGetMappedFileNameA(cfg->CurrProc, TEP, MappedName, sizeof(MappedName));
	std::string possible_name = Utils::GetDllName(MappedName); bool cloacked = false;
	if (!Utils::IsMemoryInModuledRange((DWORD)TEP, possible_name, &cloacked) &&
	!Utils::IsVecContain(cfg->ExcludedThreads, TEP))
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG,
		"[LdrInitializeThunk] Intercepted Thread Initialization! EP: 0x%X | Arg: 0x%X\n", (DWORD)TEP, (DWORD)ARG);
#endif
		ThreatReport(cfg, (DWORD)TEP, possible_name, MappedName, cloacked);
	}
	__asm jmp memTramplin
}
void __stdcall ScanForDllThreads(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->ThreadScanner) return;
	cfg->ThreadScanner = true;
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ScanForDllThreads! Thread id: %d\n", GetCurrentThreadId());
#endif
	using tsmMJM = MiniJumper::CustomHooks;
	memTramplin = tsmMJM::MakeJump((DWORD)callLdrInitializeThunk, (DWORD)LdrInitializeThunk, Prolog, 5);
	if (memTramplin != NULL) // в дальнейшем весь менеджмент потоками переходит в хук-инициализатора (Callback-Style)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[INSTALLER] Hook for thread-interception's -> installed!\n");
#endif
	}
	else
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[TROUBLE] By some reasons, hook is not exist in to the list!\n");
		Utils::LogInFile(ARTEMIS_LOG, "[REPORT] System Error Code: %d\n", GetLastError());
#endif
	}
	while (true)
	{
		THREADENTRY32 th32 { 0 }; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
				{
					HANDLE targetThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, th32.th32ThreadID);
					if (targetThread != nullptr)
					{
						if (Utils::IsVecContain(cfg->OwnThreads, targetThread)) continue;
						DWORD tempBase = NULL; pNtQueryInformationThread(targetThread, (THREADINFOCLASS)
						Utils::ThreadQuerySetWin32StartAddress, &tempBase, sizeof(DWORD), 0);
						CloseHandle(targetThread); char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
						lpGetMappedFileNameA(cfg->CurrProc, (PVOID)tempBase, MappedName, sizeof(MappedName));
						std::string possible_name = Utils::GetDllName(MappedName); bool cloacked = false;
						if (!Utils::IsMemoryInModuledRange(tempBase, possible_name, &cloacked) &&
						!Utils::IsVecContain(cfg->ExcludedThreads, (PVOID)tempBase))
						{
							ThreatReport(cfg, tempBase, possible_name, MappedName, cloacked);
							break;
						}
					}
				}
			}
			while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
		Sleep(cfg->ThreadScanDelay);
	}
}