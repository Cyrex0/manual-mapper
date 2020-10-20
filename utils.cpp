#include "utils.h"

BOOL utils::load_dll_raw(const std::filesystem::path dllPath, std::vector<BYTE> *outVector)
{
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);

	if (file.fail())
	{
		printf_s("[-] Failed to open dll at %s for reading\n", dllPath.string().c_str());
		return FALSE;
	}

	// get length of file and set vector size
	size_t len = static_cast<size_t>(file.tellg());
	file.seekg(0, file.beg);
	outVector->resize(len);
	
	// read whole file into buffer
	file.read(reinterpret_cast<char*>(outVector->data()), len);
	file.close();

	return TRUE;
}

std::string utils::wide_to_mb(const std::wstring &wstr)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.to_bytes(wstr);
}

std::wstring utils::mb_to_wide(const std::string &str)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(str);
}

std::filesystem::path utils::NameResolve(std::string dllName, Process& target, bool is64bit)
{
	// TODO: Only need to finish this if I decide to make 32 bit dlls injectable from a 64 bit process

		/*
		Search order: (for non SxS dlls)
			application directory
			system directory (change depending on wow64)
			16-bit system directory ?
			windows directory
			current directory
			directories in path	
		*/
	std::filesystem::path path = "";

	std::string appDir = target.getProcessExePath();
	
	// check application directory
	if (!appDir.empty())
	{
		path.assign(appDir);
		path.remove_filename();
		path.append(dllName);
		
		if (std::filesystem::exists(path))
		{
			return path.string();
		}
	}

	// check system directory
	if (is64bit)
	{
		path.assign("C:\\Windows\\System32\\");
	}
	else
	{
		path.assign("C:\\Windows\\SysWow64\\");
	}
	path.append(dllName);
	if (std::filesystem::exists(path))
	{
		return path.string();
	}

	//check windows directory
	path.assign("C:\\Windows\\");
	path.append(dllName);
	if (std::filesystem::exists(path))
	{
		return path.string();
	}

	
	//TODO: check all path directories

	return std::string();
}
