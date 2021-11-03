#include <windows.h>
#include <stdlib.h>


// Here so I remember how to compile it.
// x86_64-w64-mingw32-gcc -shared -o evil.dll evildll.cpp


void printEntry(){
     ::MessageBoxW(NULL, L"I am the test DLL!", L"Big test!", MB_OK);
}

// C++ will mangle names in exported functions. This is why we use edtern "C"
extern "C" __declspec(dllexport) int PrintMsg()
{
    ::MessageBoxW(NULL, L"I am an Exported function!", L"Big test!", MB_OK);
  return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        printEntry();
        ::OutputDebugStringW(L"DLL_PROCESS_ATTACH");
        break;

    case DLL_THREAD_ATTACH:
        ::OutputDebugStringW(L"DLL_THREAD_ATTACH");
        break;

    case DLL_THREAD_DETACH:
        ::OutputDebugStringW(L"DLL_THREAD_DETACH");
        break;

    case DLL_PROCESS_DETACH:
        ::OutputDebugStringW(L"DLL_PROCESS_DETACH");
         ::MessageBoxW(NULL, L"Later Nerds!", L"Peace :-)", MB_OK);
        break;
    }

    return TRUE;
}