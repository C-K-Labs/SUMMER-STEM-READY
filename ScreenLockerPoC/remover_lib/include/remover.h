// ScreenLockerPoC/remover_lib/include/remover.h

#pragma once

#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>

class Remover {
private:
    std::string targetExecutablePath;

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

    // System state restoration functions
    bool RestorePowerManagementSettings();
    bool RestoreSystemExecutionState();
    bool CleanupSystemHooks();

    bool SelfDelete();
    std::string CreateSelfDeleteBatch();

public:
    Remover();
    ~Remover();
    
    // Main functions
    bool Initialize();
    bool ExecuteRemoval();
    int Run();
};