#pragma once
#pragma warning(disable:4302 4311 6387 28160)

#include <Windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdarg>
#include <TlHelp32.h>
#include <codecvt>
#include <locale>


class Process;
class Image;


#include "utils.h"
#include "process.h"
#include "portable_executable.h"
#include "mmap.h"
