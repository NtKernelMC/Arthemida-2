// Проверка на наличие секретного байта в памяти, который должен выставить лаунчер
void __stdcall ConfirmLegitLaunch(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to CheckLauncher\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for CheckLauncher!\n");
#endif
	THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hSnapshot, &th32))
	{
		do
		{
			if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
			{
				HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
				if (pThread)
				{
					SuspendThread(pThread); CONTEXT context = { 0 };
					context.ContextFlags = CONTEXT_ALL;
					GetThreadContext(pThread, &context);
					ARTEMIS_DATA data; data.type = DetectionType::ART_FAKE_LAUNCHER;
					if (context.Dr2 != NULL)
					{
						DWORD_PTR ctrlAddr = context.Dr2;
						if (ctrlAddr != 0x90)
						{
							context.Dr2 = 0x0; context.Dr7 = 0x0;
							SetThreadContext(pThread, &context);
							ResumeThread(pThread); CloseHandle(pThread);
							cfg->callback(&data); if (hSnapshot != NULL)
							CloseHandle(hSnapshot); return;
						}
					}
					ResumeThread(pThread); CloseHandle(pThread);
				}
			}
		} while (Thread32Next(hSnapshot, &th32));
	}
	if (hSnapshot != NULL) CloseHandle(hSnapshot);
}