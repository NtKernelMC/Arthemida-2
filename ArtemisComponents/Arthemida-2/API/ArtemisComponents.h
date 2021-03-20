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
		void ReleaseInstance() override;
		friend IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg);
	};
}