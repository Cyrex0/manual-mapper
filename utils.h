#pragma once
#include "imports.h"

namespace utils
{
	BOOL load_dll_raw(const std::filesystem::path dllPath, std::vector<BYTE>* outVector);

	std::string wide_to_mb(const std::wstring& wstr);
	std::wstring mb_to_wide(const std::string& str);

	std::filesystem::path NameResolve(std::string dllName, Process& target, bool is64bit);
}
