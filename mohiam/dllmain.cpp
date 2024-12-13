#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

void initialize_console()
{
	BOOL result = AllocConsole();
	if (!result)
		throw std::exception("AllocConsole failed");
	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);
	std::cout.sync_with_stdio();
	std::cin.sync_with_stdio();
}

int connect_patched(SOCKET socket, const sockaddr *name, int name_length)
{
	ADDRESS_FAMILY family = name->sa_family;
	if (family == AF_INET || family == AF_INET6)
	{
		char node[NI_MAXHOST];
		char service[NI_MAXSERV];
		int name_result = getnameinfo(name, sizeof(sockaddr_in), node, sizeof(node), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV);
		if (!name_result)
			std::cout << "Intercepted connect call to " << node << ":" << service << std::endl;
		else
			std::cout << "getnameinfo error (WSAGetLastError " << WSAGetLastError() << ")" << std::endl;
	}
	int connect_result = connect(socket, name, name_length);
	return connect_result;
}

IMAGE_SECTION_HEADER *find_section(const char *section_name, HMODULE module)
{
	IMAGE_DOS_HEADER *dos_headers = reinterpret_cast<IMAGE_DOS_HEADER *>(module);
	IMAGE_NT_HEADERS *nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<BYTE *>(module) + dos_headers->e_lfanew);
	IMAGE_SECTION_HEADER *section_header = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<BYTE *>(&nt_headers->OptionalHeader) + nt_headers->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		if (strncmp((char *)section_header->Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0)
			return section_header;
		section_header++;
	}
	throw std::exception("Unable to find section");
}

void apply_patch(const char *dll_name)
{
	HMODULE module = GetModuleHandleA(dll_name);
	if (module == 0)
		throw std::exception("Unable to find DLL");
	IMAGE_SECTION_HEADER *section_header = find_section(".rdata", module);
	void **section_data = reinterpret_cast<void **>(reinterpret_cast<BYTE *>(module) + section_header->VirtualAddress);
	size_t count = section_header->SizeOfRawData / sizeof(void *);
	for (size_t i = 0; i < count; i++)
	{
		void **iat_pointer = section_data + i;
		if (*iat_pointer == &connect)
		{
			HANDLE process = GetCurrentProcess();
			SIZE_T size = sizeof(void *);
			DWORD old_protect;
			BOOL write_result = VirtualProtectEx(process, iat_pointer, size, PAGE_READWRITE, &old_protect);
			if (!write_result)
				throw std::exception("Failed to make IAT writable");
			*iat_pointer = &connect_patched;
			DWORD unused_protect;
			BOOL revert_result = VirtualProtectEx(process, iat_pointer, size, old_protect, &unused_protect);
			if (!revert_result)
				throw std::exception("Failed to restore IAT protection");
			return;
		}
	}
	throw new std::exception("Failed to find connect in IAT");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved)
{
	try
	{
		switch (fdwReason)
		{
		case DLL_PROCESS_ATTACH:
			initialize_console();
			std::cout << "Attached to process" << std::endl;
			apply_patch("unityplayer.dll");
			std::cout << "Patched connect" << std::endl;
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
		}
	}
	catch (std::exception &exception)
	{
		std::cout << exception.what() << " (GetLastError " << GetLastError() << ")" << std::endl;
	}
	return TRUE;
}