#include "ArtemisInterface.h"
// ������� �������
void __stdcall ModuleScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to ModuleScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ModuleScanner!\n");
#endif
	if (cfg->ModuleScanner) return;
	cfg->ModuleScanner = true;
	auto LegalModule = [&, cfg](HMODULE mdl) -> bool
	{
		char moduleName[256]; memset(moduleName, 0, sizeof(moduleName));
		cfg->lpGetMappedFileNameA(GetCurrentProcess(), mdl, moduleName, sizeof(moduleName));
		if (Utils::CheckCRC32(mdl, cfg->ModuleSnapshot)) return true;
		return false;
	};
	while (true)
	{
		std::map<LPVOID, DWORD> NewModuleMap = Utils::BuildModuledMemoryMap(); // ��������� ������ ������� ������� ����������� ������� � �� �������
		for (const auto& it : NewModuleMap)
		{
			if ((it.first != GetModuleHandleA(NULL) && it.first != cfg->hSelfModule) && // �������: 1. ������ �� �������� ������� ���������; 2. ������ �� �������� ������� ������� (� ������� ������������ �������)
			!Utils::IsVecContain(cfg->ExcludedModules, it.first)) // 3. ������ ��� �� ��������
			{
				CHAR szFileName[MAX_PATH + 1]; std::multimap<PVOID, std::string> ExportsList;
				GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				std::string NameOfDLL = Utils::GetDllName(szFileName);
				Utils::DumpExportTable(GetModuleHandleA(NameOfDLL.c_str()), ExportsList); // ��������� ������ ��������� ������
				if (!LegalModule((HMODULE)it.first) || (std::find(cfg->ModulesWhitelist.begin(), cfg->ModulesWhitelist.end(), NameOfDLL) == cfg->ModulesWhitelist.end() && ExportsList.size() < 2)) // ���� ������ ����������� (������ ���� ������ �� ��������� ��� (������)) ��� �� � ���� ������ ���� ��������� � �� �� � ����� ������, ���� � if
				{
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
					VirtualQueryEx(GetCurrentProcess(), it.first, &mme, it.second); // ��������� ��������� ���������� � ������� ������ ������
					data.baseAddr = it.first; // ������ �������� ������ ������ � data
					data.MemoryRights = mme.AllocationProtect; // ������ ���� ������� ������� � data
					data.regionSize = mme.RegionSize; // ������ ������� ������� � data
					data.dllName = NameOfDLL; data.dllPath = szFileName;
					data.type = DetectionType::ART_ILLEGAL_MODULE; // ����������� ���� ������� �� ����������� ������
					cfg->callback(&data); cfg->ExcludedModules.push_back(it.first); // ����� �������� � ���������� ������ � ������ ��� �����������
				}
			}
		}
		Sleep(cfg->MemoryScanDelay);
	}
}