project "Client Webbrowser"
	language "C++"
	kind "SharedLib"
	targetname "cefweb"
	targetdir(buildpath("mta"))

	filter "system:windows"
		includedirs { "../../vendor/sparsehash/src/windows" }
		linkoptions { "/SAFESEH:NO" }
		buildoptions { "-Zm130" }

	filter {}
		includedirs {
			".",
			"../sdk",
			"../../vendor/cef3",
			"../../vendor/sparsehash/src/"
		}

	libdirs {
		"../../vendor/cef3/Release"
	}


	pchheader "StdInc.h"
	pchsource "StdInc.cpp"

	vpaths {
		["Headers/*"] = "**.h",
		["Sources/*"] = "**.cpp",
		["*"] = "premake5.lua"
	}

	files {
		"premake5.lua",
		"**.h",
		"**.cpp"
	}

	links {
		"libcef", "CEF", "Psapi.lib", "version.lib", "Winmm.lib", "Ws2_32.lib", "DbgHelp.lib"
	}

	defines {
		"PSAPI_VERSION=1"
	}

	filter "architecture:x64"
		flags { "ExcludeFromBuild" }

	filter "system:not windows"
		flags { "ExcludeFromBuild" }
