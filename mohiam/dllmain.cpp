#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

extern "C" int (*connect_indirect)(SOCKET, const sockaddr *, int);
extern "C" int (*connect_patch)(SOCKET, const sockaddr *, int);
extern "C" int (*connect_original)(SOCKET, const sockaddr *, int);

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
	// int connect_result = connect_original(socket, name, name_length);
	int connect_result = connect_indirect(socket, name, name_length);
	return connect_result;
}

void apply_patch()
{
	HANDLE process = GetCurrentProcess();
	LPVOID connect_address = &connect;
	SIZE_T patch_size = reinterpret_cast<SIZE_T>(&connect_original) - reinterpret_cast<SIZE_T>(&connect_patch);
	DWORD old_protect;
	BOOL writable_result = VirtualProtectEx(process, connect_address, patch_size, PAGE_EXECUTE_READWRITE, &old_protect);
	if (!writable_result)
		throw new std::exception("Failed to make patch location writable");
	std::memcpy(&connect, &connect_patch, patch_size);
	std::cout << "Executed memcpy" << std::endl;
	void **address_offset = reinterpret_cast<void **>(reinterpret_cast<uint8_t *>(&connect) + 6);
	*address_offset = &connect_patched;
	connect_indirect = connect_original;
	std::cout << "Modified mov rax constant" << std::endl;
	DWORD new_old_protect;
	BOOL revert_result = VirtualProtectEx(process, connect_address, patch_size, old_protect, &new_old_protect);
	if (!revert_result)
		throw new std::exception("Failed to revert protection");
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
			/*
			std::cout << "Waiting for debugger" << std::endl;
			while (true)
				Sleep(100);
			*/
			apply_patch();
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