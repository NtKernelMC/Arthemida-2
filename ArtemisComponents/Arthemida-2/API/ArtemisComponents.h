/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#pragma once
#include "../../Arthemida-2/API/ArtemisInterface.h"
namespace ArtComponent
{
	static void __stdcall TestThreadFunc() {};
	using namespace ARTEMIS_INTERFACE;
	class ArtemisIncapsulator sealed final : protected IArtemisInterface
	{
	public:
		ArtemisIncapsulator();
		~ArtemisIncapsulator();
	private:
		friend IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg);
	};
}