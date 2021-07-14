#include "../ArtUtils/Utils.h"
#include "ArtThreading.h"

void __stdcall ThreadGuard::ThreadScanner(ArtemisConfig* cfg) // declaration in ArtThreading.h
{
	pfnNtQueryInformationThread fnNtQueryInformationThread = (pfnNtQueryInformationThread)Utils::RuntimeIatResolver("ntdll.dll", "NtQueryInformationThread");
	if (!fnNtQueryInformationThread) return;

	auto CallDetect = [&cfg](HANDLE hThread)
	{
		ARTEMIS_DATA data;
		data.type = DetectionType::ART_THREAD_FLAGS_CHANGED;
		data.baseAddr = (PVOID)hThread;
		cfg->callback(&data);
	};

	while (true)
	{
		for (auto& thread : cfg->OwnThreads)
		{
#ifndef ARTEMIS_DEBUG
			{
				ULONG bCheck = 0;
				NTSTATUS ntStatTBOT = fnNtQueryInformationThread(thread, Utils::ThreadBreakOnTermination, &bCheck, sizeof(bCheck), 0);
				//if (ntStatTBOT != 0)
				//	Utils::LogInFile(ARTEMIS_LOG, "[ERROR/ThreadGuard] ThreadBreakOnTermination Failed to query thread info! NTSTATUS: %08X\n", ntStatTBOT);
				if (!bCheck)
					CallDetect(thread);
            }

			{
				bool     bCheck = false;
				NTSTATUS ntStatTHFD = fnNtQueryInformationThread(thread, Utils::ThreadHideFromDebugger, &bCheck, sizeof(bCheck), 0);
				//if (ntStatTHFD != 0)
				//	Utils::LogInFile(ARTEMIS_LOG, "[ERROR/ThreadGuard] ThreadHideFromDebugger Failed to query thread info! NTSTATUS: %08X\n", ntStatTHFD);
				if (!bCheck)
					CallDetect(thread);
			}
#endif
		}

		Sleep(cfg->ThreadGuardDelay);
	}
}