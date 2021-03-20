#include "ArtemisInterface.h"
// ������� ������� �� PEB (������ �����������, �� ���������� ������) �� ������� ��������� ����������� ���������
void __stdcall SigScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to SigScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for SigScanner!\n");
#endif
	if (cfg->IllegalPatterns.empty())
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Empty hack patterns list for SigScanner!\n");
#endif
		return;
	}
	if (cfg->SignatureScanner) return;
	cfg->SignatureScanner = true;
	// ���� ��������
	while (true) 
	{
		// ���������� ����� ����������� � ������� �������
		std::map<LPVOID, DWORD> ModuleMap = Utils::BuildModuledMemoryMap();
		// KeyValuePair �������� � ���� �������� ���� � ������ � ��������� � ������, ��� ����������� � �������
		for (const auto& KeyValuePair : cfg->IllegalPatterns)
		{
			for (const auto& it : ModuleMap)
			{
				// ������� kernel32.dll, �������� ��������� ������, ��������� �������� � ������� �������/������� �� ������� ��������� ������������
				if (it.first == GetModuleHandleA("kernel32.dll")) continue;
				DWORD scanAddr = SigScan::FindPatternExplicit((DWORD)it.first, it.second,
				std::get<0>(KeyValuePair.second), std::get<1>(KeyValuePair.second));
				if (scanAddr != NULL && !Utils::IsVecContain(cfg->ExcludedSigAddresses, it.first))
				{
					CHAR szFilePath[MAX_PATH + 1]; 
					GetModuleFileNameA((HMODULE)it.first, szFilePath, MAX_PATH + 1);
					std::string NameOfDLL = Utils::GetDllName(szFilePath);
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
					VirtualQueryEx(GetCurrentProcess(), it.first, &mme, it.second); // ��������� ��������� ���������� � ������� ������ ������
					data.baseAddr = it.first; // ������ �������� ������ ������ � data
					data.MemoryRights = mme.AllocationProtect; // ������ ���� ������� ������� � data
					data.regionSize = mme.RegionSize; // ������ ������� ������� � data
					data.dllName = NameOfDLL; // ������ ����� ����� 
					data.dllPath = szFilePath; // ������ ���� � �����
					data.HackName = KeyValuePair.first; // ��� ���������� ����
					data.type = DetectionType::ART_SIGNATURE_DETECT; // ����������� ���� ������� 
					cfg->callback(&data); cfg->ExcludedSigAddresses.push_back(it.first);
				}
			}
		}
		Sleep(cfg->PatternScanDelay);
	}
}