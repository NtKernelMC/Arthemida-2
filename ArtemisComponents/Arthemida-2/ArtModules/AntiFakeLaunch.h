/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#define AFL_BUF_SIZE 22
constexpr wchar_t AFL_SM_NAME[] = L"Global\\NT";
constexpr unsigned char AFL_SECRET_GUID[] = {
	0x6d, 0x7a, 0x19, 0x29, 0xfa, 0xe2, 0x4f, 0x1d, 0x96, 0x32, 0x48, 0xad, 0x02, 0x71, 0x48, 0x46
};

void AFL_XOR(void* pBuffer, size_t size, DWORD dwKey)
{
	BYTE* pMask = new BYTE[size];
	for (size_t i = 0; i < size; i+=4)
	{
		memcpy(&pMask[i], (BYTE*)&dwKey, 4);
	}

	for (size_t i = 0; i < size; i++)
	{
		((BYTE*)pBuffer)[i] ^= pMask[i];
	}

	delete[] pMask;
}

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
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Checking launcher... | Thread id: %d\n", GetCurrentThreadId());
#endif
	decltype(auto) Detect = [&]() -> void
	{
		ARTEMIS_DATA data;
		data.type = DetectionType::ART_FAKE_LAUNCHER;
		cfg->callback(&data);
	};
	
	DWORD dwHash = 0x0;
	using namespace winreg;
	RegKey key{};
	try
	{
		key.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Multi Theft Auto: Province All\\1.5\\Settings\\diagnostics", KEY_READ | KEY_WRITE);
		dwHash = key.GetDwordValue(L"last-dump-hash");
	} catch (RegException& e) {
#ifdef ARTEMIS_DEBUG
		printf("Registry operations failed with error [%s]\n", e.what());
#endif
		Detect();
		return;
	}

	HANDLE hMapMem;
	hMapMem = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, AFL_SM_NAME);
	if (hMapMem == NULL)
	{
#ifdef ARTEMIS_DEBUG
		printf("Couldn't open memory mapping [%d]\n", GetLastError());
#endif
		Detect();
		return;
	}
	
	BYTE* pMappedData = (BYTE*)MapViewOfFile(hMapMem, FILE_MAP_ALL_ACCESS, 0, 0, AFL_BUF_SIZE);
	if (pMappedData == NULL)
	{
#ifdef ARTEMIS_DEBUG
		printf("Couldn't map memory [%d]\n", GetLastError());
#endif
		CloseHandle(hMapMem);
		Detect();
		return;
	}

	pMappedData += 6;
	AFL_XOR(pMappedData, sizeof(AFL_SECRET_GUID), dwHash);
	if (memcmp(AFL_SECRET_GUID, pMappedData, sizeof(AFL_SECRET_GUID)) != 0)
	{
		Detect();
	}

	key.DeleteValue(L"last-dump-hash");

	UnmapViewOfFile(pMappedData);
	CloseHandle(hMapMem);
}