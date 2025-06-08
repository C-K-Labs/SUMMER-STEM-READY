#include "remover.h"
#include <iostream>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    Remover remover;
    
    if (!remover.Initialize()) {
        MessageBoxA(NULL, "Failed to initialize remover", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    
    return remover.Run();
}