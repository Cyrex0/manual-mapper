#pragma once
#include "imports.h"



namespace mapper
{
	PBYTE manualMap(Process& target, Image& pe);
	PBYTE manualMap(Process& target, std::filesystem::path& path);

	BOOL callEntryPoint(Process& target, PBYTE entryPoint);
	BOOL callEntryPoint32(Process& target, PBYTE entryPoint);
}
