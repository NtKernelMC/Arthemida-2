#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable : 4477)
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <direct.h>
#include <iostream>
#include "MMAP.h"
#include "..\..\Arthemida-2\LauncherInclude\ArtSafeLaunch.h"
using namespace std;
using namespace SafeLaunch;
int main()
{
	system("color 06"); SetConsoleTitleA("[Artemis-2] Invasion Terminal");
	printf("Invasion Terminal started!\n\n");
	SafeLaunch::ProcessGate procGate(CreateProcessW);
	STARTUPINFOW info = { sizeof(info) }; PROCESS_INFORMATION processInfo;
	if (procGate.SafeProcess<const wchar_t*, LPSTARTUPINFOW>
	(L"ArtemisHost.exe", L"", NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
	{
		char tst_dll[256]; memset(tst_dll, 0, sizeof(tst_dll));
		char* cvr = _getcwd(tst_dll, sizeof(tst_dll)); strcat(tst_dll, "\\test_2.dll");
		MmapDLL(processInfo.hProcess, tst_dll);
		printf("Process created. Press any key to exit.\n");
		int anykey = getchar(); ExitProcess(0x0);
	}
	else printf("Error: %d\nPress any key to exit.", GetLastError());
	while (true) { Sleep(1000); }
	return 1;
}