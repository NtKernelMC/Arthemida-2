/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
void __stdcall ThreatReport(ArtemisConfig* cfg, const DWORD &caller, 
const std::string& possible_name, const std::string& MappedName, bool &cloacked,
const std::string& hack_name = "")
{
	if (cfg == nullptr) return; if (cfg->callback == nullptr) return;
	MEMORY_BASIC_INFORMATION mme { 0 }; ARTEMIS_DATA data;
	VirtualQuery((PVOID)caller, &mme, sizeof(MEMORY_BASIC_INFORMATION));
	// SHARED MEMORY can bring to us a couple of false-positives from Wow64 addreses!
	data.baseAddr = (PVOID)caller; data.MemoryRights = mme.AllocationProtect;
	data.regionSize = mme.RegionSize; data.HackName = hack_name; 
	data.type = (cloacked ? DetectionType::ART_DLL_CLOACKING : DetectionType::ART_ILLEGAL_THREAD);
	data.dllName = cloacked ? possible_name : " "; data.dllPath = cloacked ? MappedName : " ";
	cfg->callback(&data); cfg->ExcludedThreads.push_back((PVOID)caller);
}
void __stdcall LdrInitializeThunk(PCONTEXT Context)
{
	PVOID TEP = reinterpret_cast<PVOID>(Context->Eax);
	PVOID ARG = reinterpret_cast<PVOID>(Context->Ebx);
	ArtemisConfig* cfg = IArtemisInterface::GetConfig();
	if (cfg == nullptr) __asm jmp memTramplin
	bool cloacked = false;
	char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
	lpGetMappedFileNameA(cfg->CurrProc, TEP, MappedName, sizeof(MappedName));
	std::string possible_name = Utils::GetDllName(MappedName);
	DWORD true_base = (DWORD)GetModuleHandleA(possible_name.c_str()); // figure out with peb hide (dll cloacking)
	if (!Utils::IsMemoryInModuledRange(true_base, possible_name, &cloacked) && !Utils::IsVecContain(cfg->ExcludedThreads, TEP))
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG,
		"[LdrInitializeThunk] Intercepted Thread Initialization! EP: 0x%X | Arg: 0x%X | Cloacking: %d\n", 
		(DWORD)TEP, (DWORD)ARG, (BYTE)cloacked);
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
	cfg->ThreadScanner = true; DWORD dwCurrentScanTID = GetCurrentThreadId();
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ScanForDllThreads! Thread id: %d\n", dwCurrentScanTID);
#endif
	/*using tsmMJM = MiniJumper::CustomHooks;
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
	}*/
	static DWORD DestroyedCount = cfg->OwnThreads.size(), sec_count = 0x0, tmpSizer = cfg->OwnThreads.size(); 
	bool cloacked = false; while (true)
	{
		THREADENTRY32 th32 { 0 }; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				static DWORD myProcID = GetProcessId(cfg->CurrProc);
				if (th32.th32OwnerProcessID == myProcID)
				{
					HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
					if (targetThread != nullptr)
					{
						DWORD tempBase = NULL; pNtQueryInformationThread(targetThread, (THREADINFOCLASS)
						Utils::ThreadQuerySetWin32StartAddress, &tempBase, sizeof(DWORD), 0);
						CloseHandle(targetThread); char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
						lpGetMappedFileNameA(cfg->CurrProc, (PVOID)tempBase, MappedName, sizeof(MappedName));
						std::string possible_name = Utils::GetDllName(MappedName);
						DWORD true_base = (DWORD)GetModuleHandleA(possible_name.c_str()); // figure out with peb hide (dll cloacking)
						if (!Utils::IsMemoryInModuledRange(true_base, possible_name, &cloacked) &&
						!Utils::IsVecContain(cfg->ExcludedThreads, (PVOID)tempBase))
						{
							ThreatReport(cfg, tempBase, possible_name, MappedName, cloacked);
							CloseHandle(targetThread); break;
						}
						if (targetThread != nullptr) CloseHandle(targetThread);
					}
				}
			}
			while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
		Sleep(cfg->ThreadScanDelay);
	}
}