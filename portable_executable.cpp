#include "portable_executable.h"


Image::Image(std::filesystem::path path)
{
	if (!utils::load_dll_raw(path, &raw))
	{
		printf_s("[-] Failed to read dll\n");
		return;
	}

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(raw.data());

	if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf_s("[-] Inavlid dos signature\n");
		return;
	}

	nt = reinterpret_cast<PIMAGE_NT_HEADERS>(raw.data() + dos->e_lfanew);

	if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf_s("[-] Invalid nt signature\n");
		return;
	}

	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		is64bits = FALSE;
		nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt);
	}
	else
	{
		is64bits = TRUE;
	}

	if (is64bits)
	{
		mapped.resize(nt->OptionalHeader.SizeOfImage);
	}
	else
	{
		mapped.resize(nt32->OptionalHeader.SizeOfImage);
	}

	dos->e_magic = nt->Signature = 0;
	mapImage();
	name = path.filename().string();
	isValid = TRUE;
}

Image::Image(const std::vector<BYTE>& dllBytes)
{
	raw.reserve(dllBytes.size());
	std::copy(dllBytes.begin(), dllBytes.end(), raw.data());

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(raw.data());

	if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf_s("[-] Inavlid dos signature\n");
		return;
	}

	nt = reinterpret_cast<PIMAGE_NT_HEADERS>(raw.data() + dos->e_lfanew);

	if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
	{
		printf_s("[-] Invalid nt signature\n");
		return;
	}

	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		is64bits = FALSE;
		nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt);
	}
	else
	{
		is64bits = TRUE;
	}

	if (is64bits)
	{
		mapped.resize(nt->OptionalHeader.SizeOfImage);
	}
	else
	{
		mapped.resize(nt32->OptionalHeader.SizeOfImage);
	}

	dos->e_magic = nt->Signature = 0;
	mapImage();
	name = "";
	isValid = TRUE;
}

PBYTE Image::resolveRVA(ULONGLONG rva)
{
	return mapped.data() + rva;
}

PBYTE Image::rebase(ULONGLONG va)
{
	auto imageBase = is64bits ? nt->OptionalHeader.ImageBase : nt32->OptionalHeader.ImageBase;
	return reinterpret_cast<PBYTE>(va - imageBase + reinterpret_cast<ULONGLONG>(mapped.data()));
}

VOID Image::mapImage()
{
	auto sizeOfHeaders = is64bits ? nt->OptionalHeader.SizeOfHeaders : nt32->OptionalHeader.SizeOfHeaders;

	// Copy headers
	memcpy(mapped.data(), raw.data(), nt->OptionalHeader.SizeOfHeaders);

	// Copy sections to correct virtual address
	auto section = IMAGE_FIRST_SECTION(nt);
	for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
	{
		auto localSection = mapped.data() + section->VirtualAddress;
		memcpy(localSection, (raw.data() + section->PointerToRawData), section->SizeOfRawData);
	}
}

BOOL Image::resolveImports(Process& target)
{
	// Get import data directory
	auto importDir = is64bits ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importDir.VirtualAddress)
	{
		return TRUE;
	}

	// Iterate through all import descriptors

	for (auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(resolveRVA(importDir.VirtualAddress)); importDescriptor->Characteristics != NULL; ++importDescriptor)
	{
		auto dllName = reinterpret_cast<PCHAR>(resolveRVA(importDescriptor->Name));

		auto module = LoadLibrary(dllName);
		if (!module)
		{
			printf_s("[-] Failed to load module %s\n", dllName);
			return FALSE;
		}

		auto remoteBase = target.getModuleBase(dllName, module);
		if (!remoteBase)
		{
			printf_s("[-] Failed to get remote base of module %s\n", dllName);
			return FALSE;
		}

		// Get proc addresses of imports in target process and fill in IAT
		if (is64bits)
		{
			for (auto thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(resolveRVA(importDescriptor->FirstThunk)); thunkData->u1.AddressOfData != NULL; ++thunkData)
			{
				auto addressTable = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(resolveRVA(thunkData->u1.AddressOfData));
				auto procAddr = GetProcAddress(module, addressTable->Name);

				if (!procAddr)
				{
					printf_s("[-] Failed to get proc address for %s in module %s\n", addressTable->Name, dllName);
					return FALSE;
				}
				thunkData->u1.Function = reinterpret_cast<ULONGLONG>(procAddr) - reinterpret_cast<ULONGLONG>(module) + reinterpret_cast<ULONGLONG>(remoteBase);
			}
		}
		else
		{
			for (auto thunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(resolveRVA(importDescriptor->FirstThunk)); thunkData->u1.AddressOfData != NULL; ++thunkData)
			{
				auto addressTable = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(resolveRVA(thunkData->u1.AddressOfData));
				auto procAddr = GetProcAddress(module, addressTable->Name);

				if (!procAddr)
				{
					printf_s("[-] Failed to get proc address for %s in module %s\n", addressTable->Name, dllName);
					return FALSE;
				}
				thunkData->u1.Function = reinterpret_cast<ULONG>(remoteBase) + (reinterpret_cast<ULONG>(procAddr) - reinterpret_cast<ULONG>(module));
			}
		}
	}
	return TRUE;
}

VOID Image::resolveRelocations(PBYTE base)
{
	// Get relocation data directory
	auto relocDir = is64bits ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	auto delta = reinterpret_cast<ULONGLONG>(base - (is64bits ? nt->OptionalHeader.ImageBase : nt32->OptionalHeader.ImageBase));

	if (!relocDir.VirtualAddress)
	{
		return;
	}

	// Iterate through all relocations and apply them
	auto baseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(resolveRVA(relocDir.VirtualAddress));
	if (!baseReloc)
	{
		return;
	}

	while (baseReloc->SizeOfBlock != 0)
	{
		ULONGLONG relocCount = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto relocData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(baseReloc) + sizeof(IMAGE_BASE_RELOCATION));
		auto relocBase = reinterpret_cast<PBYTE>(resolveRVA(baseReloc->VirtualAddress));

		for (auto i = 0; i < relocCount; ++relocData, ++i)
		{
			auto data = *relocData;
			auto type = data >> 12;
			auto offset = data & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW)
			{
				if (is64bits)
				{
					*reinterpret_cast<PBYTE*>(relocBase + offset) += delta;
				}
				else
				{
					*reinterpret_cast<uint32_t*>(relocBase + offset) += static_cast<DWORD>(delta);
				}

			}
		}
	
		baseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(baseReloc) + baseReloc->SizeOfBlock);
	}
	return;
}

VOID Image::initSecurityCookie(Process& target)
{
	// Generate a security cookie using MSVC's generation and set it in load config

	auto loadConfigDir = is64bits ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	if (!loadConfigDir.VirtualAddress)
	{
		return;
	}

	ULONGLONG cookie = NULL;
	FILETIME time;
	LARGE_INTEGER performanceCount;
	
	GetSystemTimeAsFileTime(&time);
	QueryPerformanceCounter(&performanceCount);

	cookie = GetCurrentThreadId() ^ target.getProcessId() ^ reinterpret_cast<ULONGLONG>(&cookie);
	cookie ^= *reinterpret_cast<ULONGLONG*>(&time);
	cookie ^= (static_cast<ULONGLONG>(performanceCount.QuadPart) << 0x20) ^ static_cast<ULONGLONG>(performanceCount.QuadPart);
	cookie &= 0xFFFFFFFFFFFF;


	if (is64bits)
	{
		auto loadConfig = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(resolveRVA(loadConfigDir.VirtualAddress));

		if (!loadConfig->SecurityCookie)
		{
			return;
		}
		*reinterpret_cast<PULONGLONG>(rebase(loadConfig->SecurityCookie)) = cookie;
	}
	else
	{
		auto loadConfig = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY32>(resolveRVA(loadConfigDir.VirtualAddress));

		if (!loadConfig->SecurityCookie)
		{
			return;
		}
		*reinterpret_cast<PULONG>(rebase(loadConfig->SecurityCookie)) = static_cast<ULONG>(cookie);
	}
}

VOID Image::protectSections(Process& target, PBYTE base)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	WORD numOfSections = nt->FileHeader.NumberOfSections;

	for (WORD i = 0; i < numOfSections; ++section, ++i)
	{
		DWORD prot = NULL;
		if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			prot |= IMAGE_SCN_MEM_EXECUTE;

		if (section->Characteristics & IMAGE_SCN_MEM_READ)
			prot |= IMAGE_SCN_MEM_READ;

		if (section->Characteristics & IMAGE_SCN_MEM_WRITE)
			prot |= IMAGE_SCN_MEM_WRITE;

		if (!prot)
		{
			target.free(base + section->VirtualAddress, section->Misc.VirtualSize, MEM_DECOMMIT);
		}
		else
		{
			target.protect(base + section->VirtualAddress, &prot, section->Misc.VirtualSize);
		}
	}
}

BOOL Image::resolveStaticTLS(Process& target, PBYTE base)
{
	// Get tls data directory
	auto tlsDir = is64bits ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (!tlsDir.VirtualAddress)
	{
		return TRUE;
	}

	PIMAGE_TLS_DIRECTORY32 tls32;
	PIMAGE_TLS_DIRECTORY64 tls64;
	size_t tlsDataSize = NULL;

	if (is64bits)
	{
		tls64 = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(resolveRVA(tlsDir.VirtualAddress));
		tls32 = nullptr;

		tlsDataSize = tls64->EndAddressOfRawData - tls64->StartAddressOfRawData;
	}
	else
	{
		tls64 = nullptr;
		tls32 = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(resolveRVA(tlsDir.VirtualAddress));

		tlsDataSize = tls32->EndAddressOfRawData - tls32->StartAddressOfRawData;
	}

	// Allocate space for tls data
	auto tlsDataAddr = target.alloc(NULL, tlsDataSize);
	if (!tlsDataAddr)
	{
		printf_s("[-] Failed to allocate memory for TLS data\n");
		return FALSE;
	}

	// Usually would have to determine our module's TLS index, but darthton said he just uses 0 and it works so that's what I'll do
	if (is64bits)
	{
		*reinterpret_cast<PULONGLONG>(rebase(tls64->AddressOfIndex)) = NULL;
	}
	else
	{
		*reinterpret_cast<PDWORD>(rebase(tls32->AddressOfIndex)) = NULL;
	}

	return TRUE;
}

BOOL Image::isImageValid()
{
	return isValid;
}

BOOL Image::isImage64bits()
{
	return is64bits;
}

DWORD Image::getImageSize()
{
	return nt->OptionalHeader.SizeOfImage;
}

PBYTE Image::getProcAddress(PBYTE imageBase, std::string funcName)
{
	// Get export directory
	auto exportDir = is64bits ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!exportDir.VirtualAddress)
	{
		printf_s("[-] Attempted to get proc address on dll with no exports");
		return nullptr;
	}

	// Iteratate through export table to find requested function
	auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(resolveRVA(exportDir.VirtualAddress));

	auto namePtrTable = reinterpret_cast<PDWORD>(resolveRVA(exports->AddressOfNames));
	auto addrPtrTable = reinterpret_cast<PDWORD>(resolveRVA(exports->AddressOfFunctions));
	auto ordiPtrTable = reinterpret_cast<PWORD>(resolveRVA(exports->AddressOfNameOrdinals));

	for (auto i = 0UL; i < exports->NumberOfNames; ++i)
	{
		PCHAR name = reinterpret_cast<PCHAR>(resolveRVA(namePtrTable[i]));

		if (_stricmp(funcName.c_str(), name) == 0)
		{
			return imageBase + addrPtrTable[ordiPtrTable[i]];
		}
	}
	return nullptr;
}

PBYTE Image::getPreferredBase()
{
	return reinterpret_cast<PBYTE>(nt->OptionalHeader.ImageBase);
}

PBYTE Image::getAddressOfEntryPoint(PBYTE base)
{
	return base + nt->OptionalHeader.AddressOfEntryPoint;
}

PBYTE Image::getData()
{
	return mapped.data();
}

std::string Image::getImageName()
{
	return name;
}