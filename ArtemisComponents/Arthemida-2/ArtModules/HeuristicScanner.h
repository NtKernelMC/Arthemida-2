/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
char* SearchStringInMemory(const std::string& data, size_t len, PVOID from, PVOID to, size_t &out_len)
{
	MEMORY_BASIC_INFORMATION info { 0 }; std::vector<char> chunk;
	char* p = (char*)from; while (p < (PVOID)((DWORD)from + (DWORD)to))
	{
		if (VirtualQuery(p, &info, sizeof(info)) == sizeof(info))
		{
			p = (char*)info.BaseAddress; chunk.resize(info.RegionSize);
			if (memcpy(&chunk[0], p, info.RegionSize) != nullptr)
			{
				for (size_t i = 0; i < (info.RegionSize - len); ++i)
				{
					if (Utils::findStringIC(data.c_str(), std::string(&chunk[i], len)))
					{
						char* fnd_ptr = (char*)p + i;
						while (*fnd_ptr != '\0') fnd_ptr++;
						out_len = fnd_ptr - ((char*)p + i);
						return (char*)p + i;
					}
				}
			}
			p += info.RegionSize;
		}
	}
	return nullptr;
}
bool __stdcall IsModulePacked(HMODULE hModule, const std::vector<std::string>& ExcludedModules)
{
	if (hModule == nullptr) return false;
	else
	{
		std::string strModuleName = Utils::GetLibNameFromHandle(hModule);
		for (auto& strExcluded : ExcludedModules)
			if (Utils::findStringIC(strModuleName, strExcluded)) return false;
		bool ContainTextSection = false; PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(hModule);
		WORD NumSections = NtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
		for (WORD i = 0; i < NumSections; i++)
		{
			if (Utils::findStringIC((const char*)Section->Name, ".vmp") || 
			Utils::findStringIC((const char*)Section->Name, ".upx")) return true;
			if (Utils::findStringIC((const char*)Section->Name, ".text"))
			{
				ContainTextSection = true;
				if (NtHeader->OptionalHeader.AddressOfEntryPoint < Section->VirtualAddress || 
				NtHeader->OptionalHeader.AddressOfEntryPoint >
				(Section->VirtualAddress + Section->Misc.VirtualSize)) return true;
			}
			Section++;
		}
		if (!ContainTextSection) return true;
	}
	return false;
}