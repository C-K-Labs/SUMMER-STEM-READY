#include <windows.h>
#include <iostream>
#include "ScreenLocker.h"

// 필요한 라이브러리 링크
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib") 
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    ScreenLocker locker(hInstance);

    if (!locker.Initialize()) {
        MessageBox(NULL, L"Failed to initialize screen locker", L"Error", MB_OK);
        return -1;
    }

    return locker.Run();
}