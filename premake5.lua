outputdir = "%{cfg.buildcfg}-%{cfg.system}"

workspace "R"
	configurations
	{
		"Debug",
		"Release",
		"Dist"
	}

	project "TestProject"
		kind "ConsoleApp"
		language "C++"
		cppdialect "C++20"
	
		targetdir ("%{wks.location}/bin/" .. outputdir .. "/")
		objdir ("%{wks.location}/bin/bin-int/" .. outputdir .. "/%{prj.name}")

		files
		{
			"%{wks.location}/R/Source/**.h",
			"%{wks.location}/R/Source/**.cpp",
			
		}
		includedirs
		{
			"%{wks.location}/R/Source",
			"%{wks.location}/R/Source/Net",

		}