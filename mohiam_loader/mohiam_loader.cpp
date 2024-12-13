#include <windows.h>

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	HMODULE module = LoadLibraryW(L"mohiam.dll");
	DWORD error = GetLastError();
	return 0;
}