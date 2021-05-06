/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC
*/
#pragma once
#include "../../Arthemida-2/API/ArtemisInterface.h"
namespace ArtComponent
{
	using namespace ARTEMIS_INTERFACE;
	class ArtemisIncapsulator sealed final : protected IArtemisInterface
	{
	private:
		ArtemisIncapsulator(ArtemisConfig* cfg);
		~ArtemisIncapsulator();
		friend IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg);
	};
}