/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#pragma once
#include "../../Arthemida-2/API/ArtemisInterface.h"
namespace ArtComponent
{
	using namespace ARTEMIS_INTERFACE;
	class ArtemisFiller final : private IArtemisInterface 
	{
	private:
		ArtemisFiller();
	protected:
		~ArtemisFiller();
	public:
		friend IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg);
	};
}