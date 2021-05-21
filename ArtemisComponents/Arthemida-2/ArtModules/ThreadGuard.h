/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
bool IsOurThreadsAlive(ArtemisConfig* cfg)
{
    if (cfg == nullptr || cfg->OwnThreads.empty()) return false;
    THREADENTRY32 th32{ 0 }; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD DestroyedCount = cfg->OwnThreads.size(), sec_count = 0x0, tmpSizer = cfg->OwnThreads.size();
    if (Thread32First(hSnapshot, &th32))
    {
        do
        {
            DWORD myProcID = GetProcessId(cfg->CurrProc);
            if (th32.th32OwnerProcessID == myProcID)
            {
                HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
                if (targetThread != nullptr)
                {
                    if (Utils::Contains(cfg->OwnThreads, th32.th32ThreadID) && !cfg->ThreadViolationDiscovered)
                    {
                       //Thread Guard implementation 
                    }
                    CloseHandle(targetThread);
                }
            }
        } while (Thread32Next(hSnapshot, &th32));
        if (hSnapshot != NULL) CloseHandle(hSnapshot);
    }
    if (DestroyedCount == NULL) return true;
    return false;
}
// [x32/x86] Кража контекста основного потока для выполнения своего стаба 
// Coded By NtKernelMC (ntharbinger)
void HijackThreadContext(HANDLE hProcess, DWORD ProcID, DWORD struct_address, DWORD loader_address)
{
    DWORD retAddr = 0x0; LPVOID ShellCode = VirtualAllocEx(hProcess, 0, 20, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    auto GetThreadID = [&, ProcID]() -> DWORD
    {
        THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (Thread32First(hSnapshot, &th32))
        {
            do
            {
                if (th32.th32OwnerProcessID != ProcID) continue;
                return th32.th32ThreadID;
            } while (Thread32Next(hSnapshot, &th32));
        }
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
        return 0;
    };
    HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetThreadID());
    if (pThread)
    {
        SuspendThread(pThread); CONTEXT ctx; ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(pThread, &ctx); retAddr = ctx.Eip; ctx.Eip = (DWORD)ShellCode;
        BYTE SaveRegisters[] = { 0x60, 0x66, 0x60 };
        BYTE PushEAX[] = { 0x68, 0x90, 0x90, 0x90, 0x90 };
        BYTE CallDWORD[] = { 0xE8, 0x54, 0x50, 0xCE, 0x0F };
        BYTE RestoreRegisters[] = { 0x66, 0x61, 0x61 };
        BYTE JmpEIP[] = { 0xE9, 0x25, 0x00, 0xA8, 0xCE };
        auto FindDelta = [](DWORD DestinyAddress, DWORD SourceAddress, size_t InstructionLength) -> uint32_t
        {
            return DestinyAddress - (SourceAddress + InstructionLength);
        };
        memcpy(&PushEAX[1], &struct_address, 4); DWORD Delta = FindDelta(loader_address,
        ((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX)), sizeof(CallDWORD));
        memcpy(&CallDWORD[1], &Delta, 4); Delta = FindDelta(retAddr, ((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX) +
        sizeof(CallDWORD) + sizeof(RestoreRegisters)), sizeof(JmpEIP)); memcpy(&JmpEIP[1], &Delta, 4);
        WriteProcessMemory(hProcess, ShellCode, SaveRegisters, sizeof(SaveRegisters), NULL);
        WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode + sizeof(SaveRegisters)), PushEAX, sizeof(PushEAX), NULL);
        WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode + sizeof(SaveRegisters) + 
        sizeof(PushEAX)), CallDWORD, sizeof(CallDWORD), NULL);
        WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode + sizeof(SaveRegisters) + sizeof(PushEAX) + sizeof(CallDWORD)),
        RestoreRegisters, sizeof(RestoreRegisters), NULL); WriteProcessMemory(hProcess, (PVOID)((DWORD)ShellCode +
        sizeof(SaveRegisters) + sizeof(PushEAX) + sizeof(CallDWORD) + sizeof(RestoreRegisters)), JmpEIP, sizeof(JmpEIP), NULL);
        SetThreadContext(pThread, &ctx); ResumeThread(pThread); CloseHandle(pThread);
    }
}