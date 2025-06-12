// ScreenLockerPoC/remover_lib/include/remover.h

#pragma once

#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>

class Remover {
private:
    std::string targetExecutablePath;
    bool isUsbRemover; // [FIX] Added to track if running in USB mode.

    // Internal functions
    bool IsRunningAsAdmin();
    void ShowCompletionMessage();
    bool RemoveScreenLockerFiles();
    void LogAction(const std::string& action);

    bool FindAndTerminateProcess();
    std::string GetProcessExecutablePath(DWORD processId);
    bool TerminateProcessSafely(DWORD processId);

    bool DeleteMainExecutable();
    bool DeleteLogFolders();
    bool DeleteFolderRecursively(const std::string& folderPath);
    std::string GetExecutableDirectory();
    bool RemoveAutoStartEntry();

    // ↓↓↓ System state restoration functions ↓↓↓
    bool RestorePowerManagementSettings();
    bool RestoreSystemExecutionState();
    bool CleanupSystemHooks();

    std::string WideStringToString(const std::wstring& wstr);
    std::wstring StringToWideString(const std::string& str);

    bool SelfDelete();
    std::string CreateSelfDeleteBatch();

public:
    // [FIX] Constructor now accepts a flag to determine its mode.
    Remover(bool usbMode = false);
    ~Remover();
    
    // Main functions
    bool Initialize();
    bool ExecuteRemoval();
    int Run();
};