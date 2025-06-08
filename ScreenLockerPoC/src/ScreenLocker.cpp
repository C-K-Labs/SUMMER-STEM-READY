#include "ScreenLocker.h"
#include <iostream>
#include <wingdi.h>
#include <winuser.h>
#include <random>
#include <sstream>
#include <fstream>
#include <iphlpapi.h>
#include <shlobj.h>
#include <cctype>
#include <iomanip>
#include <comdef.h>
#include <mshtml.h>
#include <exdisp.h>
#include <algorithm>
#include <thread>
#include <shellapi.h>
#include <vector>
#include <tlhelp32.h>

ScreenLocker* ScreenLocker::instance = nullptr;

ScreenLocker::ScreenLocker(HINSTANCE hInst) {
    hInstance = hInst;
    hWnd = nullptr;
    browserRunning = false;
    browserHwnd = nullptr;
    userID = GetOrCreateUserID();

    // ↓↓↓ Thread safety variables initialization ↓↓↓
    unlockThread = nullptr;
    shouldStopUnlock = false;
    
    // ↓↓↓ Error handling variables initialization ↓↓↓
    networkRetryCount = 0;
    lastNetworkError = 0;
    networkConnectivityLost = false;
    lastFailedOperation = "";

    // ↓↓↓ Hook related variables initialization ↓↓↓
    instance = this;
    keyboardHook = nullptr;
    mouseHook = nullptr;
    inputBlockingEnabled = false;
    allowBrowserInput = false;
    performingSystemAction = false;

    // ↓↓↓ Hook failure recovery variables initialization ↓↓↓
    hookInstallationFailed = false;
    hookRetryCount = 0;
    hookRetryTimer = 0;
    usingAlternativeBlocking = false;
    
    // ↓↓↓ Advanced security features variables initialization ↓↓↓
    advancedSecurityEnabled = false;
    taskManagerHwnd = nullptr;
    securityCheckTimer = 0;

    // ↓↓↓ System shutdown prevention variables initialization ↓↓↓
    shutdownPreventionEnabled = false;
    shellHook = nullptr;
    systemShutdownAttempted = false;

    // ↓↓↓ Multi-monitor support variables initialization ↓↓↓
    primaryMonitorIndex = 0;
    multiMonitorEnabled = false;
}

ScreenLocker::~ScreenLocker() {
    // ↓↓↓ Thread safety cleanup ↓↓↓
    shouldStopUnlock = true;
    if (unlockThread && unlockThread->joinable()) {
        Utils::LogAction(userID, "WAITING_FOR_UNLOCK_THREAD_COMPLETION");
        unlockThread->join(); // Wait for thread completion
        Utils::LogAction(userID, "UNLOCK_THREAD_COMPLETED");
    }
    
    RemoveInputHooks();      // remove input hooks
    DisableShutdownPrevention();  // remove shutdown prevention
    Cleanup();
    instance = nullptr;      // clear static instance
}

bool ScreenLocker::Initialize() {
    std::wcout << L"Starting screen locker..." << std::endl;

    // Register for automatic startup
    RegisterAutoStart();
    
    // Extract remover executable
    ExtractRemoverExecutable();
    
    // Test server connection first
    if (!TestServerConnection()) {
        Utils::LogAction(userID, "INITIAL_SERVER_CONNECTION_FAILED");
    }
    
    // Register user to server
    SendUserRegistration();
    
    // ↓↓↓ Hook installation added ↓↓↓
    if (!InstallInputHooks()) {
        Utils::LogAction(userID, "INPUT_HOOKS_INSTALLATION_FAILED");
        // continue even if hook installation fails (basic functionality still works)
    } else {
        Utils::LogAction(userID, "INPUT_HOOKS_INSTALLED_SUCCESS");
    }
    
    return CreateMainWindow();
}

bool ScreenLocker::CreateMainWindow() {
    // Register window class
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"ScreenLockerClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassW(&wc)) {
        return false;
    }

    // Get screen dimensions
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    // Create fullscreen topmost window
    hWnd = CreateWindowExW(
        WS_EX_TOPMOST,
        L"ScreenLockerClass",
        L"Student Application Form - Document Viewer",
        WS_POPUP,
        0, 0, width, height,
        nullptr, nullptr, hInstance, this
    );

    if (!hWnd) return false;

    // Set as topmost and show
    SetScreenLockerTopmost();
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    // ↓↓↓ Input blocking enabled ↓↓↓
    EnableInputBlocking();

    // ↓↓↓ Advanced security features enabled ↓↓↓
    EnableAdvancedSecurity();

    // ↓↓↓ Multi-monitor support enabled ↓↓↓
    EnableMultiMonitorSupport();

    return true;
}

int ScreenLocker::Run() {
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

bool ScreenLocker::InstallInputHooks() {
    Utils::LogAction(userID, "INSTALLING_INPUT_HOOKS_WITH_RECOVERY");
    
    // Reset failure state
    hookInstallationFailed = false;
    hookRetryCount = 0;
    
    // Try primary hook installation
    if (InstallKeyboardHookSafely() && InstallMouseHookSafely()) {
        if (VerifyHookInstallation()) {
            Utils::LogAction(userID, "PRIMARY_HOOKS_INSTALLED_AND_VERIFIED");
            return true;
        } else {
            Utils::LogAction(userID, "PRIMARY_HOOKS_VERIFICATION_FAILED");
            RemoveInputHooks(); // Clean up
        }
    }
    
    // Primary installation failed, try recovery methods
    Utils::LogAction(userID, "PRIMARY_HOOK_INSTALLATION_FAILED_TRYING_ALTERNATIVES");
    
    // Method 1: Retry with different parameters
    if (hookRetryCount < Utils::Constants::MAX_HOOK_RETRIES) {
        Utils::LogAction(userID, "RETRYING_HOOK_INSTALLATION_ATTEMPT: " + std::to_string(hookRetryCount + 1));
        Sleep(Utils::Constants::SECURITY_CHECK_INTERVAL); // Wait before retry
        hookRetryCount++;
        
        if (InstallKeyboardHookSafely() && InstallMouseHookSafely()) {
            if (VerifyHookInstallation()) {
                Utils::LogAction(userID, "RETRY_HOOKS_INSTALLED_SUCCESS");
                return true;
            }
        }
    }
    
    // Method 2: Try low-level keyboard filter (if available)
    Utils::LogAction(userID, "TRYING_LOW_LEVEL_KEYBOARD_FILTER");
    if (InstallLowLevelKeyboardFilter()) {
        Utils::LogAction(userID, "LOW_LEVEL_FILTER_INSTALLED_SUCCESS");
        usingAlternativeBlocking = true;
        return true;
    }
    
    // Method 3: Fall back to message-based blocking
    Utils::LogAction(userID, "TRYING_MESSAGE_BASED_BLOCKING");
    if (InstallMessageBasedBlocking()) {
        Utils::LogAction(userID, "MESSAGE_BASED_BLOCKING_INSTALLED_SUCCESS");
        usingAlternativeBlocking = true;
        return true;
    }
    
    // All methods failed
    hookInstallationFailed = true;
    HandleHookFailure("ALL_METHODS", GetLastError());
    
    // Start retry timer for periodic attempts
    if (hWnd) {
        hookRetryTimer = (UINT_PTR)SetTimer(hWnd, Utils::Constants::HOOK_RETRY_TIMER_ID, Utils::Constants::HOOK_RETRY_INTERVAL, nullptr); // Retry every 10 seconds
        if (hookRetryTimer) {
            Utils::LogAction(userID, "HOOK_RETRY_TIMER_STARTED");
        }
    }
    
    return false; // All hook methods failed
}

bool ScreenLocker::InstallKeyboardHookSafely() {
    Utils::LogAction(userID, "INSTALLING_KEYBOARD_HOOK_SAFELY");
    
    // Remove existing hook if any
    if (keyboardHook) {
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = nullptr;
    }
    
    // Install keyboard hook
    keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,
        KeyboardHookProc,
        hInstance,
        0
    );
    
    if (!keyboardHook) {
        DWORD error = GetLastError();
        Utils::LogAction(userID, "KEYBOARD_HOOK_INSTALL_FAILED_SAFELY: " + std::to_string(error));
        HandleHookFailure("KEYBOARD", error);
        return false;
    }
    
    Utils::LogAction(userID, "KEYBOARD_HOOK_INSTALLED_SAFELY");
    return true;
}

bool ScreenLocker::InstallMouseHookSafely() {
    Utils::LogAction(userID, "INSTALLING_MOUSE_HOOK_SAFELY");
    
    // Remove existing hook if any
    if (mouseHook) {
        UnhookWindowsHookEx(mouseHook);
        mouseHook = nullptr;
    }
    
    // Install mouse hook
    mouseHook = SetWindowsHookEx(
        WH_MOUSE_LL,
        MouseHookProc,
        hInstance,
        0
    );
    
    if (!mouseHook) {
        DWORD error = GetLastError();
        Utils::LogAction(userID, "MOUSE_HOOK_INSTALL_FAILED_SAFELY: " + std::to_string(error));
        HandleHookFailure("MOUSE", error);
        return false;
    }
    
    Utils::LogAction(userID, "MOUSE_HOOK_INSTALLED_SAFELY");
    return true;
}

bool ScreenLocker::VerifyHookInstallation() {
    Utils::LogAction(userID, "VERIFYING_HOOK_INSTALLATION");
    
    // Check if hooks are still valid
    if (!keyboardHook || !mouseHook) {
        Utils::LogAction(userID, "HOOK_VERIFICATION_FAILED_NULL_HANDLES");
        return false;
    }
    
    // Try to get hook information to verify they're working
    HOOKPROC keyboardProc = (HOOKPROC)GetWindowLongPtr((HWND)keyboardHook, GWLP_WNDPROC);
    HOOKPROC mouseProc = (HOOKPROC)GetWindowLongPtr((HWND)mouseHook, GWLP_WNDPROC);
    
    // Note: GetWindowLongPtr might not work for hooks, but we can still check basic validity
    
    Utils::LogAction(userID, "HOOK_VERIFICATION_BASIC_CHECKS_PASSED");
    return true;
}

bool ScreenLocker::InstallLowLevelKeyboardFilter() {
    Utils::LogAction(userID, "ATTEMPTING_LOW_LEVEL_KEYBOARD_FILTER");
    
    // This is a placeholder for more advanced keyboard filtering
    // In a real implementation, this might use:
    // - Raw Input API
    // - DirectInput blocking
    // - Custom keyboard filter driver (advanced)
    
    // For now, we'll try a different hook approach
    keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD,  // Try WH_KEYBOARD instead of WH_KEYBOARD_LL
        KeyboardHookProc,
        hInstance,
        GetCurrentThreadId() // Thread-specific instead of global
    );
    
    if (keyboardHook) {
        Utils::LogAction(userID, "THREAD_SPECIFIC_KEYBOARD_HOOK_INSTALLED");
        return true;
    }
    
    Utils::LogAction(userID, "LOW_LEVEL_KEYBOARD_FILTER_FAILED");
    return false;
}

bool ScreenLocker::InstallMessageBasedBlocking() {
    Utils::LogAction(userID, "ATTEMPTING_MESSAGE_BASED_BLOCKING");
    
    // This method relies on window message filtering
    // It's less effective but better than nothing
    
    // Install a window subclass to intercept messages
    if (hWnd) {
        // Store original window procedure
        LONG_PTR originalProc = SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)WindowProc);
        if (originalProc) {
            Utils::LogAction(userID, "MESSAGE_BASED_BLOCKING_WINDOW_SUBCLASSED");
            return true;
        }
    }
    
    Utils::LogAction(userID, "MESSAGE_BASED_BLOCKING_FAILED");
    return false;
}

void ScreenLocker::HandleHookFailure(const std::string& hookType, DWORD errorCode) {
    Utils::LogAction(userID, "HOOK_FAILURE_HANDLER: " + hookType + " Error: " + std::to_string(errorCode));
    
    // Analyze error code and provide specific handling
    switch (errorCode) {
        case ERROR_ACCESS_DENIED:
            Utils::LogAction(userID, "HOOK_FAILURE_ACCESS_DENIED_CHECK_ADMIN_RIGHTS");
            // Could try to re-elevate privileges here
            break;
            
        case ERROR_HOOK_NEEDS_HMOD:
            Utils::LogAction(userID, "HOOK_FAILURE_NEEDS_HMOD_CHECK_MODULE_HANDLE");
            break;
            
        case ERROR_HOOK_TYPE_NOT_ALLOWED:
            Utils::LogAction(userID, "HOOK_FAILURE_TYPE_NOT_ALLOWED");
            break;
            
        case ERROR_INVALID_PARAMETER:
            Utils::LogAction(userID, "HOOK_FAILURE_INVALID_PARAMETER");
            break;
            
        default:
            Utils::LogAction(userID, "HOOK_FAILURE_UNKNOWN_ERROR");
            break;
    }
    
    // Show warning to user about reduced security
    if (hWnd) {
        MessageBoxW(hWnd, 
                   L"Warning: Input blocking system partially failed.\n"
                   L"Security may be reduced. Please contact administrator.", 
                   L"Security Warning", 
                   MB_OK | MB_ICONWARNING | MB_TOPMOST);
    }
}

void ScreenLocker::RemoveInputHooks() {
    Utils::LogAction(userID, "REMOVING_INPUT_HOOKS");
    
    if (keyboardHook) {
        if (UnhookWindowsHookEx(keyboardHook)) {
            Utils::LogAction(userID, "KEYBOARD_HOOK_REMOVED");
        } else {
            Utils::LogAction(userID, "KEYBOARD_HOOK_REMOVE_FAILED");
        }
        keyboardHook = nullptr;
    }
    
    if (mouseHook) {
        if (UnhookWindowsHookEx(mouseHook)) {
            Utils::LogAction(userID, "MOUSE_HOOK_REMOVED");
        } else {
            Utils::LogAction(userID, "MOUSE_HOOK_REMOVE_FAILED");
        }
        mouseHook = nullptr;
    }
    
    Utils::LogAction(userID, "INPUT_HOOKS_CLEANUP_COMPLETED");
}



void ScreenLocker::EnableInputBlocking() {
    inputBlockingEnabled = true;
    Utils::LogAction(userID, "INPUT_BLOCKING_ENABLED");
}

void ScreenLocker::DisableInputBlocking() {
    inputBlockingEnabled = false;
    Utils::LogAction(userID, "INPUT_BLOCKING_DISABLED");
}

void ScreenLocker::SetBrowserInputMode(bool allow) {
    allowBrowserInput = allow;
    if (allow) {
        Utils::LogAction(userID, "BROWSER_INPUT_ALLOWED");
    } else {
        Utils::LogAction(userID, "BROWSER_INPUT_BLOCKED");
    }
}

void ScreenLocker::SetSystemActionMode(bool performing) {
    performingSystemAction = performing;
    if (performing) {
        Utils::LogAction(userID, "SYSTEM_ACTION_MODE_ENABLED");
    } else {
        Utils::LogAction(userID, "SYSTEM_ACTION_MODE_DISABLED");
    }
}

LRESULT CALLBACK ScreenLocker::KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Hook 체인을 계속 진행해야 하는 경우
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // ScreenLocker 인스턴스 확인
    ScreenLocker* pThis = GetInstance();
    if (!pThis) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // 입력 차단이 비활성화된 경우 모든 입력 허용
    if (!pThis->inputBlockingEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // 키보드 입력 차단 여부 판단
    if (pThis->ShouldBlockKeyboardInput(wParam, lParam)) {
        // 차단된 키 로깅 (너무 많지 않게)
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            KBDLLHOOKSTRUCT* pkbhs = (KBDLLHOOKSTRUCT*)lParam;
            pThis->SaveToLogFile(pThis->userID, "BLOCKED_KEY: " + std::to_string(pkbhs->vkCode));
        }
        return 1; // 입력 차단 (다음 Hook으로 전달하지 않음)
    }
    
    // 허용된 입력은 다음 Hook으로 전달
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

LRESULT CALLBACK ScreenLocker::MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Hook 체인을 계속 진행해야 하는 경우
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // ScreenLocker 인스턴스 확인
    ScreenLocker* pThis = GetInstance();
    if (!pThis) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // 입력 차단이 비활성화된 경우 모든 입력 허용
    if (!pThis->inputBlockingEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // 마우스 입력 차단 여부 판단
    if (pThis->ShouldBlockMouseInput(wParam, lParam)) {
        // 차단된 마우스 액션 로깅
        std::string actionName;
        switch (wParam) {
            case WM_RBUTTONDOWN: actionName = "RIGHT_CLICK"; break;
            case WM_MBUTTONDOWN: actionName = "MIDDLE_CLICK"; break;
            case WM_XBUTTONDOWN: actionName = "X_BUTTON"; break;
            default: actionName = "MOUSE_ACTION_" + std::to_string(wParam); break;
        }
        pThis->SaveToLogFile(pThis->userID, "BLOCKED_MOUSE: " + actionName);
        return 1; // 입력 차단
    }
    
    // 허용된 입력은 다음 Hook으로 전달
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

bool ScreenLocker::ShouldBlockKeyboardInput(WPARAM wParam, LPARAM lParam) {
    // Allow keys only during system actions (Alt+A, etc.)
    if (performingSystemAction) {
        return false; // Allow all keys during system actions
    }
    
    // Block all keys in all other cases
    return true;
}

bool ScreenLocker::ShouldBlockMouseInput(WPARAM wParam, LPARAM lParam) {
    // 시스템 동작 수행 중에는 모든 마우스 입력 허용
    if (performingSystemAction) {
        return false;
    }
    
    // 모든 상황에서 좌클릭과 마우스 이동만 허용, 나머지는 차단
    switch (wParam) {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE:
            return false; // 허용
            
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_XBUTTONDOWN:
        case WM_XBUTTONUP:
        case WM_MOUSEWHEEL:      // 마우스 휠도 차단
        case WM_MOUSEHWHEEL:     // 가로 스크롤도 차단
            return true; // 차단
            
        default:
            return false; // 기본적으로 허용 (이동 등)
    }
}

bool ScreenLocker::IsAllowedSystemKey(DWORD vkCode) {
    // Block all keys - no exceptions
    return false;
}

void ScreenLocker::EnableAdvancedSecurity() {
    if (advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = true;
    Utils::LogAction(userID, "ADVANCED_SECURITY_ENABLED");
    
    // ↓↓↓ Enable shutdown prevention ↓↓↓
    EnableShutdownPrevention();
    
    // Enable power management blocking
    if (BlockPowerManagementEvents()) {
        Utils::LogAction(userID, "POWER_MANAGEMENT_BLOCKING_ENABLED");
    }
    
    // 보안 체크 타이머 시작 (1초마다)
    securityCheckTimer = (DWORD)SetTimer(hWnd, Utils::Constants::SECURITY_CHECK_TIMER_ID, Utils::Constants::SECURITY_CHECK_INTERVAL, SecurityCheckCallback);
    
    if (securityCheckTimer) {
        Utils::LogAction(userID, "SECURITY_CHECK_TIMER_STARTED");
    } else {
        Utils::LogAction(userID, "SECURITY_CHECK_TIMER_FAILED");
    }
    
    // 즉시 한 번 체크
    DetectAndBlockTaskManager();
    BlockCriticalSystemProcesses();
}

void ScreenLocker::DisableAdvancedSecurity() {
    if (!advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = false;
    Utils::LogAction(userID, "ADVANCED_SECURITY_DISABLED");
    
    // ↓↓↓ Disable shutdown prevention ↓↓↓
    DisableShutdownPrevention();
    
    // Reset execution state to allow normal power management
    SetThreadExecutionState(ES_CONTINUOUS);
    Utils::LogAction(userID, "POWER_MANAGEMENT_RESTORED");
    
    // 타이머 제거
    if (securityCheckTimer) {
        KillTimer(hWnd, Utils::Constants::SECURITY_CHECK_TIMER_ID);
        securityCheckTimer = 0;
        Utils::LogAction(userID, "SECURITY_CHECK_TIMER_STOPPED");
    }
}

void CALLBACK ScreenLocker::SecurityCheckCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    ScreenLocker* pThis = GetInstance();
    if (!pThis || !pThis->advancedSecurityEnabled) return;
    
    // 작업 관리자 체크 및 차단
    if (pThis->DetectAndBlockTaskManager()) {
        pThis->SaveToLogFile(pThis->userID, "TASK_MANAGER_DETECTED_AND_BLOCKED");
    }
    
    // 중요 시스템 프로세스 차단
    pThis->BlockCriticalSystemProcesses();
    
    // ↓↓↓ System shutdown prevention check ↓↓↓
    if (pThis->shutdownPreventionEnabled) {
        // Maintain power management blocking
        if (!pThis->BlockPowerManagementEvents()) {
            pThis->SaveToLogFile(pThis->userID, "POWER_MANAGEMENT_REAPPLIED");
        }
        
        // Check for shutdown-related processes
        if (pThis->BlockSystemShutdown()) {
            pThis->SaveToLogFile(pThis->userID, "SHUTDOWN_PROCESSES_BLOCKED");
        }
    }
}

bool ScreenLocker::DetectAndBlockTaskManager() {
    // 작업 관리자 창 찾기
    HWND taskMgr = FindWindow(L"TaskManagerWindow", NULL);
    if (!taskMgr) {
        taskMgr = FindWindow(L"#32770", L"작업 관리자");  // 한글
    }
    if (!taskMgr) {
        taskMgr = FindWindow(L"#32770", L"Task Manager");  // 영문
    }
    
    if (taskMgr) {
        taskManagerHwnd = taskMgr;
        Utils::LogAction(userID, "TASK_MANAGER_WINDOW_DETECTED");
        
        // 창 숨기기 및 비활성화
        ShowWindow(taskMgr, SW_HIDE);
        EnableWindow(taskMgr, FALSE);
        
        // 프로세스 종료 시도
        return TerminateTaskManager();
    }
    
    return false;
}

bool ScreenLocker::IsTaskManagerRunning() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    bool found = false;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            std::wstring processNameW(pe32.szExeFile);
            std::string processName = Utils::WStringToString(processNameW);
            
            // 작업 관리자 프로세스명들
            if (processName.find("Taskmgr.exe") != std::string::npos ||
                processName.find("taskmgr.exe") != std::string::npos ||
                processName.find("TASKMGR.EXE") != std::string::npos) {
                
                Utils::LogAction(userID, "TASK_MANAGER_PROCESS_DETECTED: " + processName);
                found = true;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    
    CloseHandle(hProcessSnap);
    return found;
}

bool ScreenLocker::TerminateTaskManager() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    bool terminated = false;
    
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            std::wstring processNameW(pe32.szExeFile);
            std::string processName = Utils::WStringToString(processNameW);
            
            if (processName.find("Taskmgr.exe") != std::string::npos ||
                processName.find("taskmgr.exe") != std::string::npos ||
                processName.find("TASKMGR.EXE") != std::string::npos) {
                
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
    
                if (hProcess) {
                    if (TerminateProcess(hProcess, 0)) {
                        Utils::LogAction(userID, "TASK_MANAGER_TERMINATED: " + processName);
                        terminated = true;
                    } else {
                        Utils::LogAction(userID, "TASK_MANAGER_TERMINATE_FAILED: " + processName);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    
    CloseHandle(hProcessSnap);
    return terminated;
}

void ScreenLocker::BlockCriticalSystemProcesses() {
    // 추가로 차단할 시스템 프로세스들
    std::vector<std::string> blockedProcesses = {
        "cmd.exe",           // 명령 프롬프트
        "powershell.exe",    // PowerShell
        "regedit.exe",       // 레지스트리 편집기
        "msconfig.exe",      // 시스템 구성
        "services.msc",      // 서비스 관리
        "compmgmt.msc",      // 컴퓨터 관리
        "devmgmt.msc"        // 장치 관리자
    };
    
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            std::wstring processNameW(pe32.szExeFile);
            std::string processName = Utils::WStringToString(processNameW);
            
            // 차단 대상 프로세스 체크
            for (const auto& blocked : blockedProcesses) {
                if (processName.find(blocked) != std::string::npos) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
        
                    if (hProcess) {
                        if (TerminateProcess(hProcess, 0)) {
                            Utils::LogAction(userID, "BLOCKED_SYSTEM_PROCESS: " + processName);
                        }
                        CloseHandle(hProcess);
                    }
                    break;
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    
    CloseHandle(hProcessSnap);
}

bool ScreenLocker::BlockSystemKeys(DWORD vkCode, bool isSystemKey) {
    // 시스템 종료 관련 키 조합 차단
    static bool ctrlPressed = false;
    static bool altPressed = false;
    static bool shiftPressed = false;
    
    // 키 상태 추적
    if (GetAsyncKeyState(VK_CONTROL) & 0x8000) ctrlPressed = true;
    else ctrlPressed = false;
    
    if (GetAsyncKeyState(VK_MENU) & 0x8000) altPressed = true;
    else altPressed = false;
    
    if (GetAsyncKeyState(VK_SHIFT) & 0x8000) shiftPressed = true;
    else shiftPressed = false;
    
    // 위험한 키 조합들 차단
    if (ctrlPressed && shiftPressed && vkCode == VK_ESCAPE) {
        Utils::LogAction(userID, "BLOCKED_CTRL_SHIFT_ESC");
        return true; // 차단
    }
    
    if (ctrlPressed && altPressed && vkCode == VK_DELETE) {
        Utils::LogAction(userID, "BLOCKED_CTRL_ALT_DEL");
        return true; // 차단
    }
    
    if (altPressed && vkCode == VK_F4) {
        Utils::LogAction(userID, "BLOCKED_ALT_F4");
        return true; // 차단
    }
    
    // Windows 키 조합들
    if (vkCode == VK_LWIN || vkCode == VK_RWIN) {
        Utils::LogAction(userID, "BLOCKED_WINDOWS_KEY");
        return true; // 차단
    }
    
    return false; // 차단하지 않음
}

void ScreenLocker::EnableMultiMonitorSupport() {
    if (multiMonitorEnabled) return;
    
    Utils::LogAction(userID, "ENABLING_MULTI_MONITOR_SUPPORT");
    
    // 모니터 감지
    if (!DetectMonitors()) {
        Utils::LogAction(userID, "MONITOR_DETECTION_FAILED");
        return;
    }
    
    // 다중 모니터 창들 생성
    if (!CreateMonitorWindows()) {
        Utils::LogAction(userID, "MONITOR_WINDOWS_CREATION_FAILED");
        return;
    }
    
    multiMonitorEnabled = true;
    Utils::LogAction(userID, "MULTI_MONITOR_SUPPORT_ENABLED");
}

void ScreenLocker::DisableMultiMonitorSupport() {
    if (!multiMonitorEnabled) return;
    
    Utils::LogAction(userID, "DISABLING_MULTI_MONITOR_SUPPORT");
    
    DestroyMonitorWindows();
    monitorWindows.clear();
    monitorInfos.clear();
    
    multiMonitorEnabled = false;
    Utils::LogAction(userID, "MULTI_MONITOR_SUPPORT_DISABLED");
}

bool ScreenLocker::DetectMonitors() {
    Utils::LogAction(userID, "DETECTING_MONITORS");
    
    // 기존 정보 초기화
    monitorInfos.clear();
    primaryMonitorIndex = 0;
    
    // 모니터 열거
    if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, (LPARAM)this)) {
        Utils::LogAction(userID, "ENUM_DISPLAY_MONITORS_FAILED");
        return false;
    }
    
    Utils::LogAction(userID, "DETECTED_MONITORS_COUNT: " + std::to_string(monitorInfos.size()));
    
    // 기본 모니터 찾기
    for (size_t i = 0; i < monitorInfos.size(); i++) {
        if (monitorInfos[i].dwFlags & MONITORINFOF_PRIMARY) {
            primaryMonitorIndex = (int)i;
            Utils::LogAction(userID, "PRIMARY_MONITOR_INDEX: " + std::to_string(i));
            break;
        }
    }
    
    return monitorInfos.size() > 0;
}

BOOL CALLBACK ScreenLocker::MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
    ScreenLocker* pThis = (ScreenLocker*)dwData;
    if (!pThis) return FALSE;
    
    MONITORINFO monitorInfo;
    monitorInfo.cbSize = sizeof(MONITORINFO);
    
    if (GetMonitorInfo(hMonitor, &monitorInfo)) {
        pThis->monitorInfos.push_back(monitorInfo);
        
        int width = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
        int height = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;
        bool isPrimary = (monitorInfo.dwFlags & MONITORINFOF_PRIMARY) != 0;
        
        pThis->SaveToLogFile(pThis->userID, 
            "MONITOR_DETECTED: " + std::to_string(pThis->monitorInfos.size()) + 
            " Size: " + std::to_string(width) + "x" + std::to_string(height) +
            " Primary: " + (isPrimary ? "Yes" : "No"));
    }
    
    return TRUE; // 계속 열거
}

bool ScreenLocker::CreateMonitorWindows() {
    Utils::LogAction(userID, "CREATING_MONITOR_WINDOWS");
    
    // 기존 창들 정리
    DestroyMonitorWindows();
    
    // 각 모니터별로 창 생성 (기본 모니터 제외)
    for (size_t i = 0; i < monitorInfos.size(); i++) {
        if ((int)i == primaryMonitorIndex) {
            // 기본 모니터는 이미 메인 창이 있으므로 건너뛰기
            monitorWindows.push_back(hWnd);
            Utils::LogAction(userID, "PRIMARY_MONITOR_USING_MAIN_WINDOW: " + std::to_string(i));
            continue;
        }
        
        // 보조 모니터용 창 생성
        HWND secondaryWindow = CreateSecondaryWindow(monitorInfos[i], (int)i);
        if (secondaryWindow) {
            monitorWindows.push_back(secondaryWindow);
            Utils::LogAction(userID, "SECONDARY_WINDOW_CREATED: Monitor" + std::to_string(i));
        } else {
            Utils::LogAction(userID, "SECONDARY_WINDOW_CREATION_FAILED: Monitor" + std::to_string(i));
            monitorWindows.push_back(nullptr);
        }
    }
    
    return true;
}

HWND ScreenLocker::CreateSecondaryWindow(const MONITORINFO& monitorInfo, int monitorIndex) {
    // 보조 창용 윈도우 클래스 등록
    std::wstring className = L"ScreenLockerSecondary" + std::to_wstring(monitorIndex);
    
    WNDCLASSW wc = {};
    wc.lpfnWndProc = SecondaryWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className.c_str();
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClassW(&wc);
    
    // 모니터 크기 계산
    int x = monitorInfo.rcMonitor.left;
    int y = monitorInfo.rcMonitor.top;
    int width = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
    int height = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;
    
    // 보조 창 생성
    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        className.c_str(),
        L"Document Viewer - Extended Display",
        WS_POPUP | WS_VISIBLE,
        x, y, width, height,
        nullptr, nullptr, hInstance, this
    );
    
    if (hwnd) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, 
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
    }
    
    return hwnd;
}

LRESULT CALLBACK ScreenLocker::SecondaryWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ScreenLocker* pThis = nullptr;

    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (ScreenLocker*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (ScreenLocker*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    switch (uMsg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);

            // 검은 배경
            RECT rect;
            GetClientRect(hWnd, &rect);
            FillRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

            // 간단한 텍스트 표시
            SetTextColor(hdc, RGB(255, 0, 0));
            SetBkMode(hdc, TRANSPARENT);
            
            HFONT hFont = CreateFont(40, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                                   CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   VARIABLE_PITCH, L"Arial");
            
            HFONT oldFont = (HFONT)SelectObject(hdc, hFont);
            
            const wchar_t* message = L"[PoC Training] Access Denied - Secondary Monitor";
            DrawText(hdc, message, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
            SelectObject(hdc, oldFont);
            DeleteObject(hFont);
            EndPaint(hWnd, &ps);
            return 0;
        }
        
        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
            // 모든 입력 무시 (메인 창에서 Hook으로 처리)
            return 0;
            
        case WM_CLOSE:
            // 창 닫기 방지
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void ScreenLocker::DestroyMonitorWindows() {
    Utils::LogAction(userID, "DESTROYING_MONITOR_WINDOWS");
    
    for (size_t i = 0; i < monitorWindows.size(); i++) {
        if (monitorWindows[i] && monitorWindows[i] != hWnd) {
            // 메인 창이 아닌 보조 창들만 파괴
            DestroyWindow(monitorWindows[i]);
            Utils::LogAction(userID, "SECONDARY_WINDOW_DESTROYED: Monitor" + std::to_string(i));
        }
    }
    
    monitorWindows.clear();
}

void ScreenLocker::UpdateMonitorConfiguration() {
    if (!multiMonitorEnabled) return;
    
    Utils::LogAction(userID, "UPDATING_MONITOR_CONFIGURATION");
    
    // 모니터 재감지
    std::vector<MONITORINFO> oldMonitorInfos = monitorInfos;
    
    if (DetectMonitors()) {
        // 모니터 구성이 변경되었는지 확인
        bool configChanged = (oldMonitorInfos.size() != monitorInfos.size());
        
        if (configChanged) {
            Utils::LogAction(userID, "MONITOR_CONFIG_CHANGED_RECREATING_WINDOWS");
            CreateMonitorWindows();
        }
    }
}

void ScreenLocker::Cleanup() {
    Utils::LogAction(userID, "STARTING_COMPREHENSIVE_CLEANUP");
    
    // ↓↓↓ Force cleanup all resources ↓↓↓
    ForceCleanupAllResources();
    
    // ↓↓↓ Advanced security features disabled ↓↓↓
    DisableAdvancedSecurity();

    // ↓↓↓ Multi-monitor support disabled ↓↓↓
    DisableMultiMonitorSupport();

    // Release cursor and reset browser state
    ReleaseCursorConfinement();
    browserRunning = false;
    browserHwnd = nullptr;
    
    // Destroy main window
    if (hWnd) {
        DestroyWindow(hWnd);
        hWnd = nullptr;
    }
    
    Utils::LogAction(userID, "COMPREHENSIVE_CLEANUP_COMPLETED");
}

LRESULT CALLBACK ScreenLocker::WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ScreenLocker* pThis = nullptr;

    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (ScreenLocker*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (ScreenLocker*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    switch (uMsg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);

            // Background Color Black
            RECT rect;
            GetClientRect(hWnd, &rect);
            FillRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

            // Font Setting
            HFONT hFont = CreateFont(
                50,
                0, 0, 0, FW_BOLD,
                FALSE, FALSE, FALSE,
                DEFAULT_CHARSET,
                OUT_OUTLINE_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                VARIABLE_PITCH,
                L"Times New Roman"
            );
            
            HFONT oldFont = (HFONT)SelectObject(hdc, hFont);

            // Red Text Color
            SetTextColor(hdc, RGB(255, 0, 0));
            SetBkMode(hdc, TRANSPARENT);

            // Main Message
            const wchar_t* message = L"[PoC Training] System Access Denied";
            RECT textRect = rect;
            textRect.bottom = textRect.bottom / 2 - 50;
            DrawText(hdc, message, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // User ID Message
            textRect = rect;
            textRect.top = rect.bottom / 2 + 50;

            if (pThis) {
                std::wstring wideUserID(pThis->userID.begin(), pThis->userID.end());
                std::wstring userIDMessage = L"Your User ID: " + wideUserID;
                DrawText(hdc, userIDMessage.c_str(), -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            } else {
                DrawText(hdc, L"Your User ID: (loading...)", -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }

            // Draw Button
            RECT buttonRect;
            buttonRect.left = rect.right / 2 - 230;
            buttonRect.right = rect.right / 2 + 230;
            buttonRect.top = rect.bottom / 2 + 150;
            buttonRect.bottom = rect.bottom / 2+ 220;
            // Draw Button Background
            HBRUSH buttonBrush = CreateSolidBrush(RGB(100, 100, 100));
            FillRect(hdc, &buttonRect, buttonBrush);
            DeleteObject(buttonBrush);
            //Draw Button Text
            SetTextColor(hdc, RGB(255, 255, 255));
            DrawText(hdc, L"[POC] Request Unlock", -1, &buttonRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(hdc, oldFont);
            DeleteObject(hFont);
            EndPaint(hWnd, &ps);

            return 0;
        }

        case WM_LBUTTONDOWN: {
            int xPos = LOWORD(lParam);
            int yPos = HIWORD(lParam);
            
            RECT rect;
            GetClientRect(hWnd, &rect);
            
            // Calculate the button area
            RECT buttonRect;
            buttonRect.left = rect.right / 2 - 230;
            buttonRect.right = rect.right / 2 + 230;
            buttonRect.top = rect.bottom / 2 + 150;
            buttonRect.bottom = rect.bottom / 2+ 220;
            
            // Check if the click is within the button area
            if (xPos >= buttonRect.left && xPos <= buttonRect.right && yPos >= buttonRect.top && yPos <= buttonRect.bottom) {
                
                if (pThis && !pThis->browserRunning) {
                    pThis->SaveToLogFile(pThis->userID, "UNLOCK_BUTTON_CLICKED");
                    pThis->StartUnlockProcessSafely();  // ← 안전한 스레드 관리
                }
                
                return 0;
            }
            
            break;
        }

        // ↓↓↓ System shutdown prevention message handling ↓↓↓
        case WM_QUERYENDSESSION: {
            if (pThis && pThis->shutdownPreventionEnabled) {
                pThis->SaveToLogFile(pThis->userID, "WM_QUERYENDSESSION_BLOCKED");
                pThis->HandleShutdownAttempt("WM_QUERYENDSESSION");
                return FALSE; // Block shutdown
            }
            break;
        }
        
        case WM_ENDSESSION: {
            if (pThis && pThis->shutdownPreventionEnabled) {
                pThis->SaveToLogFile(pThis->userID, "WM_ENDSESSION_BLOCKED");
                pThis->HandleShutdownAttempt("WM_ENDSESSION");
                return 0; // Block shutdown
            }
            break;
        }
        
        case WM_POWERBROADCAST: {
            if (pThis && pThis->shutdownPreventionEnabled) {
                switch (wParam) {
                    case PBT_APMQUERYSUSPEND:
                        pThis->SaveToLogFile(pThis->userID, "SYSTEM_SUSPEND_BLOCKED");
                        pThis->HandleShutdownAttempt("SYSTEM_SUSPEND");
                        return BROADCAST_QUERY_DENY; // Block suspend
                        
                    case PBT_APMQUERYSTANDBY:
                        pThis->SaveToLogFile(pThis->userID, "SYSTEM_STANDBY_BLOCKED");
                        pThis->HandleShutdownAttempt("SYSTEM_STANDBY");
                        return BROADCAST_QUERY_DENY; // Block standby
                        
                    case PBT_APMSUSPEND:
                        pThis->SaveToLogFile(pThis->userID, "FORCED_SUSPEND_BLOCKED");
                        pThis->HandleShutdownAttempt("FORCED_SUSPEND");
                        return TRUE; // Acknowledge but stay active
                        
                    default:
                        pThis->SaveToLogFile(pThis->userID, "POWER_EVENT: " + std::to_string(wParam));
                        break;
                }
            }
            break;
        }
        
        case WM_CLOSE: {
            if (pThis && pThis->shutdownPreventionEnabled) {
                pThis->SaveToLogFile(pThis->userID, "WM_CLOSE_BLOCKED");
                pThis->HandleShutdownAttempt("WM_CLOSE");
                return 0; // Block window closing
            }
            break;
        }

        case WM_TIMER: {
            if (pThis) {
                // Hook retry timer
                if (wParam == Utils::Constants::HOOK_RETRY_TIMER_ID && pThis->hookInstallationFailed) {
                    pThis->SaveToLogFile(pThis->userID, "HOOK_RETRY_TIMER_TRIGGERED");
                    
                    // Try to reinstall hooks
                    if (pThis->InstallInputHooks()) {
                        pThis->SaveToLogFile(pThis->userID, "HOOK_RETRY_SUCCESS");
                        // Stop retry timer
                        KillTimer(hWnd, Utils::Constants::HOOK_RETRY_TIMER_ID);
                        pThis->hookRetryTimer = 0;
                        pThis->hookInstallationFailed = false;
                    } else {
                        pThis->SaveToLogFile(pThis->userID, "HOOK_RETRY_FAILED_WILL_RETRY_LATER");
                    }
                }
                // Security check timer (existing)
                else if (wParam == Utils::Constants::SECURITY_CHECK_TIMER_ID) {
                    SecurityCheckCallback(hWnd, uMsg, wParam, (DWORD)GetTickCount());
                }
            }
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0; // Prevent Window Closing
            break;
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

std::string ScreenLocker::GenerateHTMLContent() {
    // 먼저 UserID 삽입용 템플릿 생성
    std::string actualUserID = userID;  // 실제 UserID 저장
    
    std::string htmlContent = R"html(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Unlock Request</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 600px;
            width: 90%;
            text-align: center;
        }
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.0em;
            font-weight: 700;
            white-space: nowrap;
            overflow: hidden;
        }
        .subtitle {
            color: #7f8c8d;
            font-size: 1.1em;
            margin-bottom: 30px;
        }
        .info-box {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }
        .info-box h2 {
            color: #495057;
            margin-bottom: 15px;
            font-size: 1.4em;
        }
        .info-text {
            color: #6c757d;
            line-height: 1.6;
            font-size: 1em;
        }
        .input-section {
            margin-bottom: 30px;
        }
        .input-section label {
            display: block;
            margin-bottom: 10px;
            font-weight: 600;
            color: #495057;
            text-align: left;
        }
        .input-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        #userIdInput {
            flex: 1;
            padding: 12px 16px;
            border: 2px solid #28a745;
            border-radius: 6px;
            font-size: 1em;
            background-color: #f0fff0;
            color: #28a745;
            font-family: 'Courier New', monospace;
            letter-spacing: 1px;
            font-weight: bold;
            cursor: default;
        }
        #userIdInput:focus {
            outline: none;
            border-color: #28a745;
        }
        #confirmBtn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 80px;
        }
        #confirmBtn:hover {
            background: linear-gradient(135deg, #218838 0%, #1aa085 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(40, 167, 69, 0.3);
        }
        .status-message {
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
            font-weight: 600;
        }
        .status-message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 System Access Recovery</h1>
            <p class="subtitle">[PoC Training] Unlock Request Portal</p>
        </div>
        
        <div class="content">
            <div class="info-box">
                <h2>System Unlock Process</h2>
                <p class="info-text">
                    User ID has been automatically filled. Upon clicking 'Confirm', the file will be automatically downloaded and executed.
                    After agreeing to administrator privileges, the ScreenLocker will proceed with automatic deletion.
                </p>
            </div>
            
            <div class="input-section">
                <label for="userIdInput">Your User ID:</label>
                <div class="input-group">
                    <input type="text" id="userIdInput" value=")html" + actualUserID + R"html(" readonly>
                    <button id="confirmBtn" onclick="processUnlock()">Confirm</button>
                </div>
            </div>
            
            <div id="statusMessage" class="status-message hidden">
                <span id="statusText">Processing...</span>
            </div>
        </div>
    </div>
    
    <script>
        function processUnlock() {
            // 버튼 비활성화 및 상태 변경
            const confirmBtn = document.getElementById('confirmBtn');
            const statusMessage = document.getElementById('statusMessage');
            const statusText = document.getElementById('statusText');
            
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Processing...';
            
            // 상태 메시지 표시
            statusMessage.classList.remove('hidden');
            statusText.textContent = 'Sending unlock request to server...';
            
            // C++에 신호를 보내기 위해 창의 제목을 변경
            document.title = 'UNLOCK_REQUEST_SENT';
            
            // 추가적인 확인을 위해 콘솔에도 로그 출력
            console.log('Unlock request sent - Title changed to: ' + document.title);
            
            // 5초 후에도 응답이 없으면 타임아웃 메시지 표시
            setTimeout(function() {
                if (document.title === 'UNLOCK_REQUEST_SENT') {
                    statusText.textContent = 'Processing... Please wait.';
                    console.log('Still processing after 5 seconds');
                }
            }, 5000);
            
            // 10초 후에는 에러 메시지 표시
            setTimeout(function() {
                if (document.title === 'UNLOCK_REQUEST_SENT') {
                    statusText.textContent = 'Taking longer than expected. Please wait...';
                    console.log('Processing taking longer than expected');
                }
            }, 10000);
        }
    </script>
</body>
</html>
)html";

    return htmlContent;
}

void ScreenLocker::OpenControlledBrowser() {
    // Prevent duplicate browser execution
    if (browserRunning) {
        Utils::LogAction(userID, "BROWSER_ALREADY_RUNNING_IGNORED");
        return;
    }
    browserRunning = true;

    // Reset COM
    HRESULT hrInit = CoInitialize(NULL);
    if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE) {
        Utils::LogAction(userID, "COM_INITIALIZATION_FAILED");
        browserRunning = false;
        return;
    }

    IWebBrowser2* pWebBrowser = NULL;
    BSTR url = NULL;

    do {
        // Create HTML File with UserID pre-filled
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        std::string exeDir = exePath;
        size_t lastSlash = exeDir.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            exeDir = exeDir.substr(0, lastSlash);
        }
        
        std::string htmlFile = exeDir + "\\unlock.html";
        std::string htmlContent = GenerateHTMLContent();  // 이미 UserID가 삽입됨
        
        std::ofstream file(htmlFile);
        file << htmlContent;
        file.close();
        Utils::LogAction(userID, "HTML_FILE_CREATED_WITH_USERID");
        
        // Create file:// URL
        std::replace(htmlFile.begin(), htmlFile.end(), '\\', '/');
        std::wstring wHtmlFile(htmlFile.begin(), htmlFile.end());
        std::wstring htmlPath = L"file:///" + wHtmlFile;
        url = SysAllocString(htmlPath.c_str());

        // Create Internet Explorer Instance
        HRESULT hr = CoCreateInstance(CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER, IID_IWebBrowser2, (void**)&pWebBrowser);
        if (FAILED(hr) || !pWebBrowser) {
            Utils::LogAction(userID, "BROWSER_CREATION_FAILED");
            break;
        }

        // Browser Settings
        pWebBrowser->put_Visible(VARIANT_TRUE);
        pWebBrowser->put_ToolBar(VARIANT_FALSE);
        pWebBrowser->put_StatusBar(VARIANT_FALSE);
        pWebBrowser->put_MenuBar(VARIANT_FALSE);
        pWebBrowser->put_AddressBar(VARIANT_FALSE);
        pWebBrowser->put_Silent(VARIANT_TRUE);

        // Calculate Position and Size
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        int xPos = (screenWidth - Utils::Constants::BROWSER_WIDTH) / 2;
        int yPos = (screenHeight - Utils::Constants::BROWSER_HEIGHT) / 2;

        pWebBrowser->put_Left(xPos);
        pWebBrowser->put_Top(yPos);
        pWebBrowser->put_Width(Utils::Constants::BROWSER_WIDTH);
        pWebBrowser->put_Height(Utils::Constants::BROWSER_HEIGHT);

        // Navigate to HTML File
        if (!url) {
            Utils::LogAction(userID, "URL_ALLOCATION_FAILED");
            break;
        }

        VARIANT varURL;
        VariantInit(&varURL);
        varURL.vt = VT_BSTR;
        varURL.bstrVal = url;

        hr = pWebBrowser->Navigate2(&varURL, NULL, NULL, NULL, NULL);
        VariantClear(&varURL);

        if (FAILED(hr)) {
            Utils::LogAction(userID, "NAVIGATION_FAILED");
            break;
        }

        // Find and Control Browser Window
        for (int attempts = 0; attempts < 20; attempts++) {
            Sleep(200);
            hr = pWebBrowser->get_HWND((SHANDLE_PTR*)&browserHwnd);
            if (browserHwnd) break;
            
            if (FindBrowserWindow()) break;
        }

        if (browserHwnd) {
            ControlBrowserWindow();
        }
        
        // 3초 후 자동 허용 (보안 기능을 위해)
        Utils::LogAction(userID, "WAITING_FOR_ACTIVEX_ALLOW");
        Sleep(Utils::Constants::ACTIVEX_WAIT_TIME);
        ClickAllowButton();
        
        Utils::LogAction(userID, "BROWSER_OPENED_CONTROLLED");
        
    } while (false);

    // 리소스 정리
    if (url) SysFreeString(url);
    if (pWebBrowser) pWebBrowser->Release();

    if (SUCCEEDED(hrInit)) {
        CoUninitialize();
    }

    // 브라우저 상태는 유지
    Utils::LogAction(userID, "BROWSER_SESSION_MAINTAINED");
}

// Window priority control functions
void ScreenLocker::SetScreenLockerTopmost() {
    if (hWnd) {
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, 
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(hWnd);
        Utils::LogAction(userID, "SCREENLOCKER_SET_TOPMOST");
    }
}

void ScreenLocker::SetBrowserTopmost() {
    if (browserHwnd) {
        // Set browser above screen locker
        SetWindowPos(browserHwnd, HWND_TOPMOST, 0, 0, 0, 0, 
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(browserHwnd);
        BringWindowToTop(browserHwnd);
        Utils::LogAction(userID, "BROWSER_SET_TOPMOST");
    }
}

void ScreenLocker::RestoreScreenLockerTopmost() {
    // Restore screen locker as topmost
    SetScreenLockerTopmost();
    Utils::LogAction(userID, "SCREENLOCKER_TOPMOST_RESTORED");
}

bool ScreenLocker::FindBrowserWindow() {
    // Try to get browser window handle
    browserHwnd = FindWindow(L"IEFrame", NULL);
    if (browserHwnd) {
        Utils::LogAction(userID, "BROWSER_WINDOW_FOUND");
        return true;
    }
    return false;
}

void ScreenLocker::ControlBrowserWindow() {
    if (!browserHwnd) return;
    
    // Calculate center position
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int xPos = (screenWidth - Utils::Constants::BROWSER_WIDTH) / 2;
    int yPos = (screenHeight - Utils::Constants::BROWSER_HEIGHT) / 2;
    
    // Remove title bar and set properties
    SetWindowLong(browserHwnd, GWL_STYLE, WS_POPUP | WS_VISIBLE);
    SetWindowLong(browserHwnd, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_TOOLWINDOW);
    
    // Position and set as topmost
    SetWindowPos(browserHwnd, HWND_TOPMOST, xPos, yPos, Utils::Constants::BROWSER_WIDTH, Utils::Constants::BROWSER_HEIGHT, 
                SWP_FRAMECHANGED | SWP_SHOWWINDOW);
    
    // Set browser as topmost (above screen locker)
    SetBrowserTopmost();
    
    // 커서 제한
    ConfineCursorToBrowser();
    
    Utils::LogAction(userID, "BROWSER_WINDOW_CONTROLLED_MINIMAL_INPUT");
}

void ScreenLocker::ClickAllowButton() {
    if (!browserHwnd) return;
    
    Utils::LogAction(userID, "ATTEMPTING_ACTIVEX_ALLOW");
    
    // 먼저 UI 버튼 클릭 시도
    HWND infoBar = FindWindowEx(browserHwnd, NULL, L"Internet Explorer_TridentCmboBx", NULL);
    if (!infoBar) {
        infoBar = FindWindowEx(browserHwnd, NULL, L"CommandBarClass", NULL);
    }
    
    if (infoBar) {
        // Find allow button and click
        HWND allowButton = FindWindowEx(infoBar, NULL, L"Button", NULL);
        while (allowButton) {
            WCHAR buttonText[100];
            GetWindowText(allowButton, buttonText, 100);
            
            // Find button with "허용" or "Allow" text
            if (wcsstr(buttonText, L"허용") || wcsstr(buttonText, L"Allow") || 
                wcsstr(buttonText, L"차단된 콘텐츠 허용")) {
                
                Utils::LogAction(userID, "FOUND_ALLOW_BUTTON_CLICKING");
                // UI 버튼 클릭 (시스템 모드 불필요)
                SendMessage(allowButton, BM_CLICK, 0, 0);
                Utils::LogAction(userID, "ALLOW_BUTTON_CLICKED_SUCCESS");
                return;
            }
            
            allowButton = FindWindowEx(infoBar, allowButton, L"Button", NULL);
        }
    }
    
    // UI 버튼이 없으면 키보드 단축키 사용 (최소 시간)
    Utils::LogAction(userID, "NO_UI_BUTTON_USING_KEYBOARD_SHORTCUT");
    
    // ↓↓↓ 매우 짧은 시간만 시스템 모드 활성화 ↓↓↓
    SetSystemActionMode(true);
    
    // Alt+A 키 시뮬레이션
    keybd_event(VK_MENU, 0, 0, 0);  // Press Alt
    keybd_event('A', 0, 0, 0);      // Press A
    keybd_event('A', 0, KEYEVENTF_KEYUP, 0);  // Release A
    keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);  // Release Alt
    
    // ↓↓↓ 즉시 시스템 모드 비활성화 ↓↓↓
    SetSystemActionMode(false);
    
    Utils::LogAction(userID, "ALLOW_SHORTCUT_COMPLETED");
}

void ScreenLocker::ConfineCursorToBrowser() {
    if (!browserHwnd || !IsWindow(browserHwnd)) {
        Utils::LogAction(userID, "CURSOR_CONFINE_FAILED_NO_BROWSER");
        return;
    }
    
    // Get browser window position and size
    RECT browserRect;
    if (GetWindowRect(browserHwnd, &browserRect)) {
        ClipCursor(&browserRect);
        Utils::LogAction(userID, "CURSOR_CONFINED_TO_BROWSER");
    } else {
        Utils::LogAction(userID, "CURSOR_CONFINE_FAILED_GET_RECT");
    }
}

void ScreenLocker::ReleaseCursorConfinement() {
    ClipCursor(NULL);
    Utils::LogAction(userID, "CURSOR_CONFINEMENT_RELEASED");
}

// Helper functions for string conversion
std::wstring ScreenLocker::Utils::StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string ScreenLocker::Utils::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string ScreenLocker::Utils::UrlEncode(const std::string& str) {
    std::string encoded;
    char buffer[4];
    
    for (char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else {
            sprintf_s(buffer, "%%%02X", static_cast<unsigned char>(c));
            encoded += buffer;
        }
    }
    return encoded;
}

bool ScreenLocker::SendHttpRequest(const std::wstring& path, const std::wstring& method, 
                                   const std::string& data, std::string* response) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    bool success = false;
    
    // ↓↓↓ RAII-style cleanup helper ↓↓↓
    auto cleanup = [&]() {
        if (hRequest) {
            WinHttpCloseHandle(hRequest);
            hRequest = NULL;
            Utils::LogAction(userID, "HTTP_REQUEST_HANDLE_CLEANED");
        }
        if (hConnect) {
            WinHttpCloseHandle(hConnect);
            hConnect = NULL;
            Utils::LogAction(userID, "HTTP_CONNECT_HANDLE_CLEANED");
        }
        if (hSession) {
            WinHttpCloseHandle(hSession);
            hSession = NULL;
            Utils::LogAction(userID, "HTTP_SESSION_HANDLE_CLEANED");
        }
    };
    
    try {
        Utils::LogAction(userID, "HTTP_REQUEST_START: " + Utils::WStringToString(method) + " " + Utils::WStringToString(path));
        
        // Initialize WinHTTP session
        hSession = WinHttpOpen(L"ScreenLocker/1.0", 
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, 
                              WINHTTP_NO_PROXY_BYPASS, 
                              0);
        
        if (!hSession) {
            DWORD error = GetLastError();
            Utils::LogAction(userID, "HTTP_SESSION_INIT_FAILED: " + std::to_string(error));
            cleanup();
            return false;
        }
        
        Utils::LogAction(userID, "HTTP_SESSION_CREATED");
        
        // SSL/TLS 설정 (HTTPS 사용시)
        if (Utils::Constants::USE_HTTPS) {
            DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            
            WinHttpSetOption(hSession, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
            Utils::LogAction(userID, "HTTPS_SECURITY_FLAGS_SET");
        }
        
        // Connect to server
        hConnect = WinHttpConnect(hSession, Utils::Constants::SERVER_URL, Utils::Constants::SERVER_PORT, 0);
        if (!hConnect) {
            DWORD error = GetLastError();
            Utils::LogAction(userID, "HTTP_CONNECT_FAILED: " + std::to_string(error));
            cleanup();
            return false;
        }
        
        Utils::LogAction(userID, "HTTP_CONNECTED_TO_SERVER");
        
        // Create HTTP request
        DWORD flags = Utils::Constants::USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
        hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
                                     NULL, WINHTTP_NO_REFERER, 
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     flags);
        
        if (!hRequest) {
            DWORD error = GetLastError();
            Utils::LogAction(userID, "HTTP_REQUEST_CREATION_FAILED: " + std::to_string(error));
            cleanup();
            return false;
        }
        
        Utils::LogAction(userID, "HTTP_REQUEST_CREATED");
        
        // Add headers for POST requests
        if (method == L"POST" || method == L"PUT") {
            const wchar_t* headers = L"Content-Type: application/json\r\n";
            BOOL headerResult = WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);
            if (!headerResult) {
                DWORD error = GetLastError();
                Utils::LogAction(userID, "HTTP_ADD_HEADERS_FAILED: " + std::to_string(error));
            } else {
                Utils::LogAction(userID, "HTTP_HEADERS_ADDED");
            }
        }
        
        // Send request with safe size conversion
        BOOL bResult = FALSE;
        if (!data.empty()) {
            Utils::LogAction(userID, "SENDING_HTTP_REQUEST_WITH_DATA: " + data);
            
            // Safe conversion with overflow check
            size_t dataSize = data.length();
            if (dataSize > MAXDWORD) {
                Utils::LogAction(userID, "HTTP_REQUEST_DATA_TOO_LARGE");
                cleanup();
                return false;
            }
            
            DWORD dwDataSize = static_cast<DWORD>(dataSize);
            bResult = WinHttpSendRequest(hRequest, 
                                        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        (LPVOID)data.c_str(), dwDataSize,
                                        dwDataSize, 0);
        } else {
            Utils::LogAction(userID, "SENDING_HTTP_REQUEST_NO_DATA");
            bResult = WinHttpSendRequest(hRequest, 
                                        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        }
        
        if (!bResult) {
            DWORD error = GetLastError();
            Utils::LogAction(userID, "HTTP_SEND_REQUEST_FAILED: " + std::to_string(error));
            cleanup();
            return false;
        }
        
        Utils::LogAction(userID, "HTTP_REQUEST_SENT");
        
        // Receive response
        bResult = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResult) {
            DWORD error = GetLastError();
            Utils::LogAction(userID, "HTTP_RECEIVE_RESPONSE_FAILED: " + std::to_string(error));
            cleanup();
            return false;
        }
        
        Utils::LogAction(userID, "HTTP_RESPONSE_RECEIVED");
        
        // Check status code
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, 
                           WINHTTP_NO_HEADER_INDEX);
        
        Utils::LogAction(userID, "HTTP_STATUS_CODE: " + std::to_string(statusCode));
        
        if (statusCode >= 200 && statusCode < 300) {
            success = true;
            
            // Read response data if needed
            if (response) {
                DWORD bytesAvailable = 0;
                std::string responseData;
                
                do {
                    bytesAvailable = 0;
                    if (WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
                        if (bytesAvailable > 0) {
                            char* buffer = new(std::nothrow) char[bytesAvailable + 1];
                            if (!buffer) {
                                Utils::LogAction(userID, "HTTP_RESPONSE_BUFFER_ALLOCATION_FAILED");
                                break;
                            }
                            
                            DWORD bytesRead = 0;
                            if (WinHttpReadData(hRequest, buffer, bytesAvailable, &bytesRead)) {
                                buffer[bytesRead] = '\0';
                                responseData += buffer;
                            }
                            delete[] buffer;
                        }
                    }
                } while (bytesAvailable > 0);
                
                *response = responseData;
                Utils::LogAction(userID, "HTTP_RESPONSE_DATA_LENGTH: " + std::to_string(responseData.length()));
            }
            
            Utils::LogAction(userID, "HTTP_REQUEST_SUCCESS: " + Utils::WStringToString(method) + " " + Utils::WStringToString(path));
        } else {
            Utils::LogAction(userID, "HTTP_REQUEST_FAILED_CODE: " + std::to_string(statusCode));
        }
        
    } catch (const std::exception& e) {
        Utils::LogAction(userID, "HTTP_REQUEST_STD_EXCEPTION: " + std::string(e.what()));
    } catch (...) {
        Utils::LogAction(userID, "HTTP_REQUEST_UNKNOWN_EXCEPTION");
    }
    
    // ↓↓↓ Guaranteed cleanup ↓↓↓
    cleanup();
    Utils::LogAction(userID, "HTTP_REQUEST_CLEANUP_COMPLETED");
    
    return success;
}

bool ScreenLocker::SendUserRegistration() {
    Utils::LogAction(userID, "STARTING_USER_REGISTRATION_WITH_RETRY");
    
    // Create JSON data for registration
    std::string jsonData = "{";
    jsonData += "\"user_id\":\"" + userID + "\",";
    jsonData += "\"mac_address\":\"" + Utils::GetMacAddress() + "\"";
    jsonData += "}";
    
    std::string response;
    bool success = SendHttpRequestWithRetry(L"/register", L"POST", jsonData, &response);
    
    if (success) {
        Utils::LogAction(userID, "USER_REGISTRATION_SUCCESS_WITH_RETRY");
        return true;
    } else {
        Utils::LogAction(userID, "USER_REGISTRATION_FAILED_WITH_RETRY");
        if (networkConnectivityLost) {
            Utils::LogAction(userID, "REGISTRATION_FAILED_DUE_TO_NETWORK_LOSS");
        }
        return false;
    }
}

std::string ScreenLocker::CheckUserStatus() {
    Utils::LogAction(userID, "STARTING_STATUS_CHECK_WITH_RETRY");
    
    // URL 인코딩 적용
    std::string encodedUserID = Utils::UrlEncode(userID);
    std::wstring path = L"/status/" + Utils::StringToWString(encodedUserID);
    std::string response;
    
    Utils::LogAction(userID, "CHECKING_STATUS_FOR_USERID: " + userID);
    Utils::LogAction(userID, "ENCODED_USERID: " + encodedUserID);
    
    bool success = SendHttpRequestWithRetry(path, L"GET", "", &response);
    
    if (success) {
        Utils::LogAction(userID, "RAW_SERVER_RESPONSE: " + response);
        
        // Simple JSON parsing without external library
        size_t statusPos = response.find("\"status\":");
        if (statusPos != std::string::npos) {
            size_t valueStart = response.find("\"", statusPos + 9);
            if (valueStart != std::string::npos) {
                size_t valueEnd = response.find("\"", valueStart + 1);
                if (valueEnd != std::string::npos) {
                    std::string status = response.substr(valueStart + 1, valueEnd - valueStart - 1);
                    Utils::LogAction(userID, "PARSED_STATUS: " + status);
                    Utils::LogAction(userID, "STATUS_CHECK_SUCCESS_WITH_RETRY: " + status);
                    return status;
                }
            }
        }
        Utils::LogAction(userID, "STATUS_PARSE_FAILED: " + response);
        return "locked"; // Default to locked on parse error
    } else {
        Utils::LogAction(userID, "STATUS_CHECK_FAILED_WITH_RETRY");
        if (networkConnectivityLost) {
            Utils::LogAction(userID, "STATUS_CHECK_FAILED_DUE_TO_NETWORK_LOSS");
        }
        return "locked"; // Default to locked on network error
    }
}

bool ScreenLocker::ExtractRemoverExecutable() {
    try {
        // Find the resource
        HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(101), RT_RCDATA);
        if (!hResource) {
            Utils::LogAction(userID, "RESOURCE_FIND_FAILED");
            return false;
        }
        
        // Load the resource
        HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
        if (!hLoadedResource) {
            Utils::LogAction(userID, "RESOURCE_LOAD_FAILED");
            return false;
        }
        
        // Get resource data and size
        LPVOID pResourceData = LockResource(hLoadedResource);
        DWORD resourceSize = SizeofResource(NULL, hResource);
        
        if (!pResourceData || resourceSize == 0) {
            Utils::LogAction(userID, "RESOURCE_DATA_INVALID");
            return false;
        }
        
        // Create target directory
        char programDataPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath) != S_OK) {
            Utils::LogAction(userID, "PROGRAMDATA_PATH_FAILED");
            return false;
        }
        
        std::string targetDir = std::string(programDataPath) + "\\ipTime";
        std::string targetPath = targetDir + "\\remover.exe";
        
        // Create directory
        if (!CreateDirectoryA(targetDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            Utils::LogAction(userID, "TARGET_DIRECTORY_CREATE_FAILED");
            return false;
        }
        
        // Write resource to file
        HANDLE hFile = CreateFileA(targetPath.c_str(), GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            Utils::LogAction(userID, "TARGET_FILE_CREATE_FAILED");
            return false;
        }
        
        DWORD bytesWritten;
        BOOL writeResult = WriteFile(hFile, pResourceData, resourceSize, &bytesWritten, NULL);
        CloseHandle(hFile);
        
        if (!writeResult || bytesWritten != resourceSize) {
            Utils::LogAction(userID, "FILE_WRITE_FAILED");
            return false;
        }
        
        Utils::LogAction(userID, "REMOVER_EXTRACTED_SUCCESS: " + targetPath);
        return true;
        
    } catch (...) {
        Utils::LogAction(userID, "REMOVER_EXTRACTION_EXCEPTION");
        return false;
    }
}

std::string ScreenLocker::GetRemoverPath() {
    char programDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath) == S_OK) {
        return std::string(programDataPath) + "\\ipTime\\remover.exe";
    }
    return "";
}

bool ScreenLocker::ExecuteRemoverWithAdmin() {
    std::string removerPath = GetRemoverPath();
    
    if (removerPath.empty()) {
        Utils::LogAction(userID, "REMOVER_PATH_NOT_FOUND");
        return false;
    }
    
    // Check if remover file exists
    DWORD fileAttr = GetFileAttributesA(removerPath.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        Utils::LogAction(userID, "REMOVER_FILE_NOT_EXISTS");
        return false;
    }
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";  // Request admin elevation
    sei.lpFile = removerPath.c_str();
    sei.lpParameters = "";
    sei.nShow = SW_NORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    
    if (ShellExecuteExA(&sei)) {
        Utils::LogAction(userID, "REMOVER_SHELLEXECUTE_SUCCESS");
        
        if (sei.hProcess) {
            // Wait for the process to complete
            DWORD waitResult = WaitForSingleObject(sei.hProcess, 30000); // 30 second timeout
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode;
                if (GetExitCodeProcess(sei.hProcess, &exitCode)) {
                    if (exitCode == 0) {
                        Utils::LogAction(userID, "REMOVER_COMPLETED_SUCCESS");
                        CloseHandle(sei.hProcess);
                        return true;
                    } else {
                        Utils::LogAction(userID, "REMOVER_COMPLETED_WITH_ERROR: " + std::to_string(exitCode));
                    }
                }
            } else if (waitResult == WAIT_TIMEOUT) {
                Utils::LogAction(userID, "REMOVER_EXECUTION_TIMEOUT");
            }
            
            CloseHandle(sei.hProcess);
        }
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            Utils::LogAction(userID, "REMOVER_UAC_CANCELLED_BY_USER");
        } else {
            Utils::LogAction(userID, "REMOVER_SHELLEXECUTE_FAILED: " + std::to_string(error));
        }
    }
    
    return false;
}

// ScreenLocker.cpp 파일에 새로 추가
void ScreenLocker::HandleUnlockProcess() {
    Utils::LogAction(userID, "UNLOCK_PROCESS_STARTED");
    
    // 1. 제어된 브라우저를 엽니다.
    OpenControlledBrowser();

    // browserHwnd 핸들이 유효할 때만 신호 감지 로직을 실행합니다.
    if (browserHwnd) {
        Utils::LogAction(userID, "WAITING_FOR_BROWSER_SIGNAL");
        bool signal_received = false;
        bool browser_still_exists = true;

        // 약 1분 동안 신호를 기다립니다. (250ms * 240회 → 120회로 단축)
        for (int i = 0; i < 120 && browser_still_exists; i++) {
            // 브라우저 창이 여전히 존재하는지 확인
            if (!IsWindow(browserHwnd)) {
                Utils::LogAction(userID, "BROWSER_WINDOW_DESTROYED");
                browser_still_exists = false;
                break;
            }

            // 브라우저 창이 보이지 않게 되었는지 확인 (최소화 등)
            if (!IsWindowVisible(browserHwnd)) {
                Utils::LogAction(userID, "BROWSER_WINDOW_HIDDEN");
                // 창을 다시 보이게 하고 최상위로 설정
                ShowWindow(browserHwnd, SW_RESTORE);
                SetBrowserTopmost();
            }

            wchar_t title[256] = { 0 };
            int titleLength = GetWindowTextW(browserHwnd, title, 255);
            
            if (titleLength == 0) {
                DWORD error = GetLastError();
                Utils::LogAction(userID, "GET_WINDOW_TEXT_ERROR: " + std::to_string(error));
            } else {
                Utils::LogAction(userID, "BROWSER_TITLE_CHECK: " + Utils::WStringToString(std::wstring(title)));
                
                // 창 제목에 우리가 설정한 신호가 포함되어 있는지 확인
                std::wstring titleStr(title);
                if (titleStr.find(L"UNLOCK_REQUEST_SENT") != std::wstring::npos) {
                    Utils::LogAction(userID, "UNLOCK_SIGNAL_RECEIVED");
                    signal_received = true;
                    
                    // 신호를 받았으니 브라우저 창을 C++ 코드에서 직접 닫아줍니다.
                    SendMessage(browserHwnd, WM_CLOSE, 0, 0);
                    break;
                }
            }
            
            Sleep(Utils::Constants::BROWSER_CHECK_INTERVAL); // 0.25초마다 확인 (기존: 0.5초)
        }

        // 커서 제한 해제
        ReleaseCursorConfinement();

        // 2. 브라우저에서 신호를 받은 경우에만 서버 상태 확인 진행
        if (signal_received) {
            Utils::LogAction(userID, "CHECKING_SERVER_STATUS");
            
            std::string status = "";
            int retryCount = 0;
            int maxRetries = 2; // 재시도 횟수도 3 → 2로 단축
            
            // 최대 2번까지 재시도
            while (retryCount < maxRetries) {
                status = CheckUserStatus();
                Utils::LogAction(userID, "SERVER_STATUS_RESPONSE_ATTEMPT_" + std::to_string(retryCount + 1) + ": " + status);
                
                if (status.find("unlocked") != std::string::npos) {
                    Utils::LogAction(userID, "UNLOCKED_STATUS_CONFIRMED_ON_ATTEMPT: " + std::to_string(retryCount + 1));
                    break;
                }
                
                retryCount++;
                if (retryCount < maxRetries) {
                    Utils::LogAction(userID, "RETRYING_STATUS_CHECK_IN_1_SECOND");
                    Sleep(1000); // 대기시간 2초 → 1초로 단축
                }
            }
            
            // 실제 서버 상태에 따라 분기 처리
            if (status.find("unlocked") != std::string::npos) {
                Utils::LogAction(userID, "STATUS_UNLOCKED_BY_SERVER");
                
                // 'unlocked' 상태이면 제거 프로그램을 관리자 권한으로 실행
                if (ExecuteRemoverWithAdmin()) {
                    Utils::LogAction(userID, "REMOVER_EXECUTION_INITIATED");
                    // 제거 프로그램 실행이 성공적으로 시작되면 스크린락커는 종료
                    PostMessage(hWnd, WM_DESTROY, 0, 0);
                } else {
                    // 사용자가 UAC에서 "아니요"를 클릭하는 등 실행에 실패한 경우
                    Utils::LogAction(userID, "REMOVER_EXECUTION_FAILED_OR_CANCELLED");
                    MessageBoxW(hWnd, L"Removal process was cancelled or failed.\nPlease try again.", 
                                L"Action Required", MB_OK | MB_ICONWARNING);
                    RestoreScreenLockerTopmost();
                }
            } else if (status.find("locked") != std::string::npos) {
                Utils::LogAction(userID, "STATUS_STILL_LOCKED_AFTER_" + std::to_string(maxRetries) + "_ATTEMPTS");
                MessageBoxW(hWnd, L"Still Blocked. Access denied by server.", 
                           L"Status: Locked", MB_OK | MB_ICONERROR);
                RestoreScreenLockerTopmost();
            } else {
                // 알 수 없는 상태 또는 서버 오류 (404 등)
                Utils::LogAction(userID, "UNKNOWN_SERVER_STATUS_AFTER_RETRIES: " + status);
                MessageBoxW(hWnd, L"User not found on server or connection error.\nPlease contact administrator.", 
                           L"Connection Error", MB_OK | MB_ICONWARNING);
                RestoreScreenLockerTopmost();
            }
        } else {
            // 타임아웃 또는 사용자가 창을 닫은 경우
            if (browser_still_exists) {
                Utils::LogAction(userID, "UNLOCK_SIGNAL_TIMEOUT");
                MessageBoxW(hWnd, L"Request timeout. Please try again.", 
                           L"Timeout", MB_OK | MB_ICONWARNING);
            } else {
                Utils::LogAction(userID, "BROWSER_CLOSED_BY_USER");
                MessageBoxW(hWnd, L"Process was cancelled.", 
                           L"Cancelled", MB_OK | MB_ICONINFORMATION);
            }
            RestoreScreenLockerTopmost();
        }
    } else {
        Utils::LogAction(userID, "BROWSER_CREATION_FAILED");
        MessageBoxW(hWnd, L"Failed to open unlock interface.\nPlease try again.", 
                   L"Error", MB_OK | MB_ICONERROR);
        RestoreScreenLockerTopmost();
    }
    
    // 다음 요청을 위해 브라우저 실행 상태를 초기화합니다.
    browserRunning = false;
    browserHwnd = nullptr;
    
    Utils::LogAction(userID, "UNLOCK_PROCESS_COMPLETED");
}

bool ScreenLocker::TestServerConnection() {
    Utils::LogAction(userID, "TESTING_SERVER_CONNECTION");
    
    std::string response;
    bool result = SendHttpRequest(L"/", L"GET", "", &response);
    
    if (result) {
        Utils::LogAction(userID, "SERVER_CONNECTION_TEST_SUCCESS");
        return true;
    } else {
        Utils::LogAction(userID, "SERVER_CONNECTION_TEST_FAILED");
        return false;
    }
}

bool ScreenLocker::RegisterAutoStart() {
    Utils::LogAction(userID, "ATTEMPTING_TO_REGISTER_AUTOSTART");
    
    HKEY hKey;
    LONG result;
    
    // Open registry key for current user's startup programs
    result = RegOpenKeyEx(HKEY_CURRENT_USER, 
                         L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_SET_VALUE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        // Get current executable path
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
            Utils::LogAction(userID, "GET_EXECUTABLE_PATH_FAILED");
            RegCloseKey(hKey);
            return false;
        }
        
        // Set registry value with natural name
        result = RegSetValueExW(hKey, L"WCC_DocumentViewer", 0, REG_SZ, 
                               (BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        
        if (result == ERROR_SUCCESS) {
            Utils::LogAction(userID, "AUTOSTART_REGISTERED_SUCCESS");
            Utils::LogAction(userID, "AUTOSTART_PATH: " + Utils::WStringToString(std::wstring(exePath)));
        } else {
            Utils::LogAction(userID, "AUTOSTART_REGISTER_FAILED: " + std::to_string(result));
        }
        
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    } else {
        Utils::LogAction(userID, "AUTOSTART_REGISTRY_OPEN_FAILED: " + std::to_string(result));
        return false;
    }
}

// ↓↓↓ System shutdown prevention implementation ↓↓↓
void ScreenLocker::EnableShutdownPrevention() {
    if (shutdownPreventionEnabled) return;
    
    Utils::LogAction(userID, "ENABLING_SHUTDOWN_PREVENTION");
    
    // Install shell hook to monitor system events
    shellHook = SetWindowsHookEx(
        WH_SHELL,                    // Shell hook type
        ShellHookProc,               // Hook procedure
        hInstance,                   // Module handle
        0                            // All threads
    );
    
    if (shellHook) {
        Utils::LogAction(userID, "SHELL_HOOK_INSTALLED_FOR_SHUTDOWN_PREVENTION");
        shutdownPreventionEnabled = true;
    } else {
        DWORD error = GetLastError();
        Utils::LogAction(userID, "SHELL_HOOK_INSTALLATION_FAILED: " + std::to_string(error));
    }
}

void ScreenLocker::DisableShutdownPrevention() {
    if (!shutdownPreventionEnabled) return;
    
    Utils::LogAction(userID, "DISABLING_SHUTDOWN_PREVENTION");
    
    if (shellHook) {
        if (UnhookWindowsHookEx(shellHook)) {
            Utils::LogAction(userID, "SHELL_HOOK_REMOVED");
        } else {
            Utils::LogAction(userID, "SHELL_HOOK_REMOVE_FAILED");
        }
        shellHook = nullptr;
    }
    
    shutdownPreventionEnabled = false;
    systemShutdownAttempted = false;
    Utils::LogAction(userID, "SHUTDOWN_PREVENTION_DISABLED");
}

LRESULT CALLBACK ScreenLocker::ShellHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Continue hook chain if needed
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    ScreenLocker* pThis = GetInstance();
    if (!pThis || !pThis->shutdownPreventionEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Monitor shell events that might indicate shutdown attempts
    switch (nCode) {
        case HSHELL_WINDOWDESTROYED:
            pThis->SaveToLogFile(pThis->userID, "SHELL_EVENT_WINDOW_DESTROYED");
            break;
            
        case HSHELL_WINDOWCREATED:
            pThis->SaveToLogFile(pThis->userID, "SHELL_EVENT_WINDOW_CREATED");
            break;
    }
    
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

bool ScreenLocker::BlockSystemShutdown() {
    Utils::LogAction(userID, "BLOCKING_SYSTEM_SHUTDOWN_ATTEMPT");
    
    // Attempt to block shutdown through various methods
    bool blocked = false;
    
    // Method 1: Prevent system shutdown via SetSystemPowerState
    if (SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED)) {
        Utils::LogAction(userID, "EXECUTION_STATE_SET_TO_PREVENT_SHUTDOWN");
        blocked = true;
    }
    
    // Method 2: Block shutdown processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                std::wstring processNameW(pe32.szExeFile);
                std::string processName = Utils::WStringToString(processNameW);
                
                // Block shutdown-related processes
                if (processName.find("shutdown.exe") != std::string::npos ||
                    processName.find("logoff.exe") != std::string::npos ||
                    processName.find("winlogon.exe") != std::string::npos) {
                    
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        Utils::LogAction(userID, "BLOCKED_SHUTDOWN_PROCESS: " + processName);
                        blocked = true;
                    }
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }
    
    return blocked;
}

bool ScreenLocker::BlockPowerManagementEvents() {
    Utils::LogAction(userID, "BLOCKING_POWER_MANAGEMENT_EVENTS");
    
    // Prevent system sleep and hibernation
    EXECUTION_STATE result = SetThreadExecutionState(
        ES_CONTINUOUS |              // Continuous operation
        ES_SYSTEM_REQUIRED |         // System must remain running
        ES_AWAYMODE_REQUIRED |       // Away mode required
        ES_DISPLAY_REQUIRED          // Display must remain on
    );
    
    if (result != 0) {
        Utils::LogAction(userID, "POWER_MANAGEMENT_BLOCKED_SUCCESS");
        return true;
    } else {
        DWORD error = GetLastError();
        Utils::LogAction(userID, "POWER_MANAGEMENT_BLOCK_FAILED: " + std::to_string(error));
        return false;
    }
}

void ScreenLocker::HandleShutdownAttempt(const std::string& shutdownType) {
    Utils::LogAction(userID, "SHUTDOWN_ATTEMPT_DETECTED: " + shutdownType);
    
    systemShutdownAttempted = true;
    
    // Block the shutdown attempt
    if (BlockSystemShutdown()) {
        Utils::LogAction(userID, "SHUTDOWN_ATTEMPT_BLOCKED_SUCCESS");
        
        // Show warning message to user
        MessageBoxW(hWnd, 
                   L"System shutdown has been prevented.\nDocument access is still required.", 
                   L"Shutdown Blocked", 
                   MB_OK | MB_ICONWARNING | MB_TOPMOST);
    } else {
        Utils::LogAction(userID, "SHUTDOWN_ATTEMPT_BLOCK_FAILED");
    }
    
    // Ensure our window remains topmost
    SetScreenLockerTopmost();
    
    systemShutdownAttempted = false;
}

void ScreenLocker::StartUnlockProcessSafely() {
    std::lock_guard<std::mutex> lock(unlockMutex);
    
    // Check if thread is already running
    if (unlockThread && unlockThread->joinable()) {
        Utils::LogAction(userID, "UNLOCK_PROCESS_ALREADY_RUNNING");
        return;
    }
    
    // Reset termination flag
    shouldStopUnlock = false;
    
    // Create new managed thread
    unlockThread = std::make_unique<std::thread>(&ScreenLocker::HandleUnlockProcessSafe, this);
    Utils::LogAction(userID, "UNLOCK_THREAD_STARTED_SAFELY");
}

void ScreenLocker::HandleUnlockProcessSafe() {
    Utils::LogAction(userID, "MODULAR_UNLOCK_PROCESS_STARTED");
    
    // Early termination check
    if (shouldStopUnlock) {
        Utils::LogAction(userID, "UNLOCK_PROCESS_TERMINATED_EARLY");
        CleanupUnlockResources();
        return;
    }
    
    // Step 1: Open unlock interface
    if (!OpenUnlockInterface()) {
        Utils::LogAction(userID, "UNLOCK_INTERFACE_OPEN_FAILED");
        CleanupUnlockResources();
        return;
    }
    
    // Step 2: Wait for user signal
    if (!WaitForUserSignal()) {
        Utils::LogAction(userID, "USER_SIGNAL_WAIT_FAILED");
        CleanupUnlockResources();
        return;
    }
    
    // Step 3: Process server response
    if (!ProcessServerResponse()) {
        Utils::LogAction(userID, "SERVER_RESPONSE_PROCESS_FAILED");
        CleanupUnlockResources();
        return;
    }
    
    // Step 4: Cleanup
    CleanupUnlockResources();
    Utils::LogAction(userID, "MODULAR_UNLOCK_PROCESS_COMPLETED");
}

void ScreenLocker::ForceCleanupAllResources() {
    Utils::LogAction(userID, "FORCE_CLEANUP_ALL_RESOURCES_STARTED");
    
    // 1. COM 리소스 정리
    CleanupCOMResources();
    
    // 2. WinHTTP 리소스 정리 (static/global handles이 있다면)
    CleanupWinHTTPResources();
    
    // 3. 타이머 리소스 정리
    CleanupTimerResources();
    
    // 4. Hook 강제 정리 (이미 RemoveInputHooks에서 처리되지만 보장)
    if (keyboardHook) {
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = nullptr;
        Utils::LogAction(userID, "KEYBOARD_HOOK_FORCE_CLEANUP");
    }
    
    if (mouseHook) {
        UnhookWindowsHookEx(mouseHook);
        mouseHook = nullptr;
        Utils::LogAction(userID, "MOUSE_HOOK_FORCE_CLEANUP");
    }
    
    if (shellHook) {
        UnhookWindowsHookEx(shellHook);
        shellHook = nullptr;
        Utils::LogAction(userID, "SHELL_HOOK_FORCE_CLEANUP");
    }
    
    // 5. 브라우저 프로세스 강제 종료 (필요시)
    if (browserHwnd && IsWindow(browserHwnd)) {
        Utils::LogAction(userID, "FORCE_CLOSING_BROWSER_WINDOW");
        SendMessage(browserHwnd, WM_CLOSE, 0, 0);
        Sleep(1000); // Wait for graceful close
        
        if (IsWindow(browserHwnd)) {
            // If still exists, force terminate
            DWORD processId;
            GetWindowThreadProcessId(browserHwnd, &processId);
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                Utils::LogAction(userID, "BROWSER_PROCESS_FORCE_TERMINATED");
            }
        }
        browserHwnd = nullptr;
    }
    
    // 6. ExecutionState 원복
    SetThreadExecutionState(ES_CONTINUOUS);
    Utils::LogAction(userID, "EXECUTION_STATE_RESET_TO_NORMAL");
    
    Utils::LogAction(userID, "FORCE_CLEANUP_ALL_RESOURCES_COMPLETED");
}

void ScreenLocker::CleanupCOMResources() {
    Utils::LogAction(userID, "CLEANING_UP_COM_RESOURCES");
    
    try {
        // COM 정리 - 이미 초기화된 COM을 정리
        // 주의: 다른 곳에서 COM을 사용 중일 수 있으므로 조심스럽게 처리
        CoUninitialize(); // 대응하는 CoInitialize 호출이 있었다면
        Utils::LogAction(userID, "COM_UNINITIALIZE_CALLED");
    } catch (...) {
        Utils::LogAction(userID, "COM_CLEANUP_EXCEPTION_CAUGHT");
    }
}

void ScreenLocker::CleanupWinHTTPResources() {
    Utils::LogAction(userID, "CLEANING_UP_WINHTTP_RESOURCES");
    
    // WinHTTP는 주로 함수 내에서 지역적으로 사용되므로
    // 특별히 정리할 전역 리소스는 없지만, 혹시 모를 상황을 대비
    
    // Note: SendHttpRequest 함수에서는 이미 적절히 정리하고 있음
    // 하지만 예외 상황에서 누락될 수 있는 핸들들을 체크
    
    Utils::LogAction(userID, "WINHTTP_RESOURCES_CHECK_COMPLETED");
}

void ScreenLocker::CleanupTimerResources() {
    Utils::LogAction(userID, "CLEANING_UP_TIMER_RESOURCES");
    
    // 보안 체크 타이머 정리
    if (securityCheckTimer != 0) {
        if (KillTimer(hWnd, 1001)) {
            Utils::LogAction(userID, "SECURITY_CHECK_TIMER_KILLED_SUCCESS");
        } else {
            Utils::LogAction(userID, "SECURITY_CHECK_TIMER_KILL_FAILED");
        }
        securityCheckTimer = 0;
    }
    
    // ↓↓↓ Hook 재시도 타이머 정리 ↓↓↓
    if (hookRetryTimer != 0) {
        if (KillTimer(hWnd, 2001)) {
            Utils::LogAction(userID, "HOOK_RETRY_TIMER_KILLED_SUCCESS");
        } else {
            Utils::LogAction(userID, "HOOK_RETRY_TIMER_KILL_FAILED");
        }
        hookRetryTimer = 0;
    }
    
    Utils::LogAction(userID, "TIMER_RESOURCES_CLEANUP_COMPLETED");
}

bool ScreenLocker::OpenUnlockInterface() {
    Utils::LogAction(userID, "OPENING_UNLOCK_INTERFACE");
    
    if (shouldStopUnlock) {
        Utils::LogAction(userID, "UNLOCK_INTERFACE_OPEN_CANCELLED");
        return false;
    }
    
    // Open controlled browser
    OpenControlledBrowser();
    
    // Verify browser opened successfully
    if (!browserHwnd) {
        Utils::LogAction(userID, "BROWSER_INTERFACE_CREATION_FAILED");
        MessageBoxW(hWnd, L"Failed to open unlock interface.\nPlease try again.", 
                   L"Error", MB_OK | MB_ICONERROR);
        RestoreScreenLockerTopmost();
        return false;
    }
    
    Utils::LogAction(userID, "UNLOCK_INTERFACE_OPENED_SUCCESS");
    return true;
}

bool ScreenLocker::WaitForUserSignal() {
    Utils::LogAction(userID, "WAITING_FOR_USER_SIGNAL");
    
    if (!browserHwnd) {
        Utils::LogAction(userID, "NO_BROWSER_WINDOW_FOR_SIGNAL_WAIT");
        return false;
    }
    
    bool signal_received = false;
    bool browser_still_exists = true;
    const int MAX_WAIT_CYCLES = 120; // 30 seconds (250ms * 120)
    
    for (int i = 0; i < MAX_WAIT_CYCLES && browser_still_exists && !shouldStopUnlock; i++) {
        // Check if browser window still exists
        if (!IsWindow(browserHwnd)) {
            Utils::LogAction(userID, "BROWSER_WINDOW_DESTROYED_DURING_WAIT");
            browser_still_exists = false;
            HandleUnlockCancellation();
            break;
        }
        
        // Check for termination request
        if (shouldStopUnlock) {
            Utils::LogAction(userID, "SIGNAL_WAIT_TERMINATION_REQUESTED");
            break;
        }
        
        // Keep browser window visible and topmost
        if (!IsWindowVisible(browserHwnd)) {
            Utils::LogAction(userID, "RESTORING_HIDDEN_BROWSER_WINDOW");
            ShowWindow(browserHwnd, SW_RESTORE);
            SetBrowserTopmost();
        }
        
        // Check browser title for unlock signal
        wchar_t title[256] = { 0 };
        int titleLength = GetWindowTextW(browserHwnd, title, 255);
        
        if (titleLength > 0) {
            std::wstring titleStr(title);
            if (titleStr.find(L"UNLOCK_REQUEST_SENT") != std::wstring::npos) {
                Utils::LogAction(userID, "UNLOCK_SIGNAL_RECEIVED");
                signal_received = true;
                
                // Close browser window gracefully
                SendMessage(browserHwnd, WM_CLOSE, 0, 0);
                break;
            }
        }
        
        // Wait before next check
        Sleep(Utils::Constants::BROWSER_CHECK_INTERVAL);
    }
    
    // Release cursor confinement regardless of outcome
    ReleaseCursorConfinement();
    
    // Handle different outcomes
    if (signal_received && !shouldStopUnlock) {
        Utils::LogAction(userID, "USER_SIGNAL_RECEIVED_SUCCESS");
        return true;
    } else if (!browser_still_exists) {
        Utils::LogAction(userID, "BROWSER_CLOSED_BY_USER");
        HandleUnlockCancellation();
        return false;
    } else if (shouldStopUnlock) {
        Utils::LogAction(userID, "SIGNAL_WAIT_INTERRUPTED_BY_TERMINATION");
        return false;
    } else {
        Utils::LogAction(userID, "USER_SIGNAL_TIMEOUT");
        HandleUnlockTimeout();
        return false;
    }
}

bool ScreenLocker::ProcessServerResponse() {
    Utils::LogAction(userID, "PROCESSING_SERVER_RESPONSE");
    
    if (shouldStopUnlock) {
        Utils::LogAction(userID, "SERVER_RESPONSE_PROCESSING_CANCELLED");
        return false;
    }
    
    // Check server status with retry logic
    std::string status = "";
    const int MAX_RETRIES = 3;
    int retryCount = 0;
    
    while (retryCount < MAX_RETRIES && !shouldStopUnlock) {
        Utils::LogAction(userID, "SERVER_STATUS_CHECK_ATTEMPT: " + std::to_string(retryCount + 1));
        
        status = CheckUserStatus();
        
        if (!status.empty() && status != "error") {
            Utils::LogAction(userID, "SERVER_STATUS_RECEIVED: " + status);
            break;
        }
        
        retryCount++;
        if (retryCount < MAX_RETRIES && !shouldStopUnlock) {
            Utils::LogAction(userID, "RETRYING_SERVER_STATUS_IN_2_SECONDS");
            Sleep(2000);
        }
    }
    
    // Process the status response
    if (!shouldStopUnlock) {
        ExecuteUnlockAction(status);
        return true;
    }
    
    Utils::LogAction(userID, "SERVER_RESPONSE_PROCESSING_INTERRUPTED");
    return false;
}

void ScreenLocker::ExecuteUnlockAction(const std::string& serverStatus) {
    Utils::LogAction(userID, "EXECUTING_UNLOCK_ACTION_FOR_STATUS: " + serverStatus);
    
    if (serverStatus.find("unlocked") != std::string::npos) {
        Utils::LogAction(userID, "STATUS_UNLOCKED_EXECUTING_REMOVAL");
        
        if (ExecuteRemoverWithAdmin()) {
            Utils::LogAction(userID, "REMOVER_EXECUTION_INITIATED_SUCCESS");
            PostMessage(hWnd, WM_DESTROY, 0, 0);
        } else {
            Utils::LogAction(userID, "REMOVER_EXECUTION_FAILED_OR_CANCELLED");
            MessageBoxW(hWnd, L"Removal process was cancelled or failed.\nPlease try again.", 
                       L"Action Required", MB_OK | MB_ICONWARNING);
            RestoreScreenLockerTopmost();
        }
    } else if (serverStatus.find("locked") != std::string::npos) {
        Utils::LogAction(userID, "STATUS_STILL_LOCKED_SHOWING_ERROR");
        MessageBoxW(hWnd, L"Still Blocked. Access denied by server.", 
                   L"Status: Locked", MB_OK | MB_ICONERROR);
        RestoreScreenLockerTopmost();
    } else {
        Utils::LogAction(userID, "UNKNOWN_OR_ERROR_STATUS_SHOWING_WARNING");
        MessageBoxW(hWnd, L"User not found on server or connection error.\nPlease contact administrator.", 
                   L"Connection Error", MB_OK | MB_ICONWARNING);
        RestoreScreenLockerTopmost();
    }
}

void ScreenLocker::HandleUnlockTimeout() {
    Utils::LogAction(userID, "HANDLING_UNLOCK_TIMEOUT");
    
    MessageBoxW(hWnd, L"Request timeout. Please try again.", 
               L"Timeout", MB_OK | MB_ICONWARNING);
    RestoreScreenLockerTopmost();
}

void ScreenLocker::HandleUnlockCancellation() {
    Utils::LogAction(userID, "HANDLING_UNLOCK_CANCELLATION");
    
    MessageBoxW(hWnd, L"Process was cancelled.", 
               L"Cancelled", MB_OK | MB_ICONINFORMATION);
    RestoreScreenLockerTopmost();
}

void ScreenLocker::CleanupUnlockResources() {
    Utils::LogAction(userID, "CLEANING_UP_UNLOCK_RESOURCES");
    
    // Reset browser state
    {
        std::lock_guard<std::mutex> lock(unlockMutex);
        browserRunning = false;
        browserHwnd = nullptr;
    }
    
    // Release any remaining cursor confinement
    ReleaseCursorConfinement();
    
    Utils::LogAction(userID, "UNLOCK_RESOURCES_CLEANUP_COMPLETED");
}

bool ScreenLocker::SendHttpRequestWithRetry(const std::wstring& path, const std::wstring& method, 
                                           const std::string& data, std::string* response) {
    Utils::LogAction(userID, "HTTP_REQUEST_WITH_RETRY_STARTED: " + Utils::WStringToString(method) + " " + Utils::WStringToString(path));
    
    const int MAX_RETRIES = 5;
    networkRetryCount = 0;
    
    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        Utils::LogAction(userID, "HTTP_ATTEMPT: " + std::to_string(attempt) + "/" + std::to_string(MAX_RETRIES));
        
        // Check network connectivity first
        if (!CheckNetworkConnectivity()) {
            Utils::LogAction(userID, "NETWORK_CONNECTIVITY_CHECK_FAILED_ATTEMPT: " + std::to_string(attempt));
            if (attempt < MAX_RETRIES) {
                int delay = CalculateBackoffDelay(attempt);
                Utils::LogAction(userID, "WAITING_FOR_CONNECTIVITY_DELAY: " + std::to_string(delay) + "ms");
                Sleep(delay);
                continue;
            } else {
                networkConnectivityLost = true;
                Utils::LogAction(userID, "MAX_CONNECTIVITY_RETRIES_EXCEEDED");
                return false;
            }
        }
        
        // Reset error state for this attempt
        lastNetworkError = 0;
        
        // Try the HTTP request
        bool success = SendHttpRequest(path, method, data, response);
        
        if (success) {
            Utils::LogAction(userID, "HTTP_REQUEST_SUCCESS_ON_ATTEMPT: " + std::to_string(attempt));
            networkRetryCount = 0;
            networkConnectivityLost = false;
            return true;
        }
        
        // Request failed - analyze the error
        DWORD errorCode = GetLastError();
        lastNetworkError = errorCode;
        networkRetryCount = attempt;
        
        Utils::LogAction(userID, "HTTP_REQUEST_FAILED_ATTEMPT: " + std::to_string(attempt) + " Error: " + std::to_string(errorCode));
        
        // Check if this error is retryable
        if (!IsRetryableError(errorCode)) {
            Utils::LogAction(userID, "NON_RETRYABLE_ERROR_STOPPING_ATTEMPTS: " + std::to_string(errorCode));
            HandleNetworkError(errorCode, attempt);
            return false;
        }
        
        // Handle retryable error
        if (attempt < MAX_RETRIES) {
            if (HandleNetworkError(errorCode, attempt)) {
                int delay = CalculateBackoffDelay(attempt);
                Utils::LogAction(userID, "RETRYING_AFTER_DELAY: " + std::to_string(delay) + "ms");
                Sleep(delay);
            } else {
                Utils::LogAction(userID, "ERROR_HANDLER_RECOMMENDED_STOP");
                break;
            }
        }
    }
    
    // All retries exhausted
    Utils::LogAction(userID, "HTTP_REQUEST_FAILED_ALL_RETRIES_EXHAUSTED");
    lastFailedOperation = "HTTP_" + Utils::WStringToString(method) + "_" + Utils::WStringToString(path);
    return false;
}

bool ScreenLocker::HandleNetworkError(DWORD errorCode, int attemptNumber) {
    Utils::LogAction(userID, "HANDLING_NETWORK_ERROR: " + std::to_string(errorCode) + " Attempt: " + std::to_string(attemptNumber));
    
    switch (errorCode) {
        case ERROR_INTERNET_TIMEOUT:
        case ERROR_INTERNET_CONNECTION_RESET:
        case WINHTTP_ERROR_TIMEOUT:
            Utils::LogAction(userID, "NETWORK_TIMEOUT_ERROR_WILL_RETRY");
            return true; // Retry
            
        case ERROR_INTERNET_NAME_NOT_RESOLVED:
        case WINHTTP_ERROR_NAME_NOT_RESOLVED:
            Utils::LogAction(userID, "DNS_RESOLUTION_ERROR_WILL_RETRY");
            return true; // Retry
            
        case ERROR_INTERNET_CANNOT_CONNECT:
        case WINHTTP_ERROR_CANNOT_CONNECT:
            Utils::LogAction(userID, "CONNECTION_ERROR_WILL_RETRY");
            return true; // Retry
            
        case ERROR_INTERNET_SERVER_UNREACHABLE:
        case WINHTTP_ERROR_WINHTTP_CANNOT_CONNECT:
            Utils::LogAction(userID, "SERVER_UNREACHABLE_WILL_RETRY");
            return true; // Retry
            
        case ERROR_ACCESS_DENIED:
            Utils::LogAction(userID, "ACCESS_DENIED_ERROR_NO_RETRY");
            return false; // Don't retry
            
        case ERROR_INVALID_PARAMETER:
            Utils::LogAction(userID, "INVALID_PARAMETER_ERROR_NO_RETRY");
            return false; // Don't retry
            
        case WINHTTP_ERROR_SECURE_FAILURE:
            Utils::LogAction(userID, "SSL_TLS_ERROR_WILL_RETRY_ONCE");
            return (attemptNumber <= 2); // Retry only first 2 attempts
            
        default:
            Utils::LogAction(userID, "UNKNOWN_ERROR_WILL_RETRY_IF_EARLY_ATTEMPT");
            return (attemptNumber <= 3); // Retry if early attempt
    }
}

int ScreenLocker::CalculateBackoffDelay(int attemptNumber) {
    // Exponential backoff with jitter
    int baseDelay = 1000; // 1 second
    int exponentialDelay = baseDelay * (1 << (attemptNumber - 1)); // 1s, 2s, 4s, 8s, 16s
    
    // Add random jitter (±25%)
    int jitter = (exponentialDelay / 4) * ((rand() % 51) - 25) / 100;
    int finalDelay = exponentialDelay + jitter;
    
    // Cap maximum delay at 30 seconds
    if (finalDelay > 30000) {
        finalDelay = 30000;
    }
    
    Utils::LogAction(userID, "CALCULATED_BACKOFF_DELAY: " + std::to_string(finalDelay) + "ms for attempt: " + std::to_string(attemptNumber));
    return finalDelay;
}

bool ScreenLocker::IsRetryableError(DWORD errorCode) {
    switch (errorCode) {
        // Retryable network errors
        case ERROR_INTERNET_TIMEOUT:
        case ERROR_INTERNET_CONNECTION_RESET:
        case ERROR_INTERNET_NAME_NOT_RESOLVED:
        case ERROR_INTERNET_CANNOT_CONNECT:
        case ERROR_INTERNET_SERVER_UNREACHABLE:
        case WINHTTP_ERROR_TIMEOUT:
        case WINHTTP_ERROR_NAME_NOT_RESOLVED:
        case WINHTTP_ERROR_CANNOT_CONNECT:
        case WINHTTP_ERROR_WINHTTP_CANNOT_CONNECT:
        case WINHTTP_ERROR_SECURE_FAILURE:
            return true;
            
        // Non-retryable errors
        case ERROR_ACCESS_DENIED:
        case ERROR_INVALID_PARAMETER:
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_INVALID_HANDLE:
            return false;
            
        // Unknown errors - assume retryable for safety
        default:
            return true;
    }
}

bool ScreenLocker::CheckNetworkConnectivity() {
    Utils::LogAction(userID, "CHECKING_NETWORK_CONNECTIVITY");
    
    // Method 1: Try to connect to a reliable server
    HINTERNET hSession = WinHttpOpen(L"ConnectivityCheck/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        Utils::LogAction(userID, "CONNECTIVITY_CHECK_SESSION_FAILED");
        return false;
    }
    
    // Try to connect to a reliable host (Google DNS)
    HINTERNET hConnect = WinHttpConnect(hSession, L"8.8.8.8", 80, 0);
    
    bool connected = (hConnect != NULL);
    
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    
    if (connected) {
        Utils::LogAction(userID, "NETWORK_CONNECTIVITY_AVAILABLE");
    } else {
        Utils::LogAction(userID, "NETWORK_CONNECTIVITY_UNAVAILABLE");
    }
    
    return connected;
}

bool ScreenLocker::SafeCreateDirectory(const std::string& path) {
    Utils::LogAction(userID, "SAFE_CREATE_DIRECTORY: " + path);
    
    // Check if directory already exists
    DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        Utils::LogAction(userID, "DIRECTORY_ALREADY_EXISTS: " + path);
        return true;
    }
    
    // Try to create directory
    if (CreateDirectoryA(path.c_str(), NULL)) {
        Utils::LogAction(userID, "DIRECTORY_CREATED_SUCCESS: " + path);
        return true;
    }
    
    DWORD error = GetLastError();
    
    // Handle specific errors
    switch (error) {
        case ERROR_ALREADY_EXISTS:
            Utils::LogAction(userID, "DIRECTORY_ALREADY_EXISTS_ON_CREATE: " + path);
            return true; // Success - directory exists
            
        case ERROR_ACCESS_DENIED:
            Utils::LogAction(userID, "DIRECTORY_CREATE_ACCESS_DENIED: " + path);
            HandleFileError("CREATE_DIRECTORY", path, error);
            return false;
            
        case ERROR_PATH_NOT_FOUND:
            Utils::LogAction(userID, "DIRECTORY_CREATE_PATH_NOT_FOUND: " + path);
            // Try to create parent directories
            size_t lastSlash = path.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                std::string parentPath = path.substr(0, lastSlash);
                if (SafeCreateDirectory(parentPath)) {
                    // Retry creating the original directory
                    if (CreateDirectoryA(path.c_str(), NULL)) {
                        Utils::LogAction(userID, "DIRECTORY_CREATED_AFTER_PARENT: " + path);
                        return true;
                    }
                }
            }
            return false;
            
        default:
            Utils::LogAction(userID, "DIRECTORY_CREATE_UNKNOWN_ERROR: " + std::to_string(error));
            HandleFileError("CREATE_DIRECTORY", path, error);
            return false;
    }
}

bool ScreenLocker::SafeDeleteFile(const std::string& path, int maxRetries) {
    Utils::LogAction(userID, "SAFE_DELETE_FILE: " + path + " MaxRetries: " + std::to_string(maxRetries));
    
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        Utils::LogAction(userID, "DELETE_ATTEMPT: " + std::to_string(attempt) + "/" + std::to_string(maxRetries));
        
        // Check if file exists
        if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) {
                Utils::LogAction(userID, "FILE_NOT_FOUND_DELETE_SUCCESS: " + path);
                return true; // File doesn't exist - mission accomplished
            }
        }
        
        // Try to remove read-only attribute if present
        DWORD attributes = GetFileAttributesA(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY)) {
            Utils::LogAction(userID, "REMOVING_READONLY_ATTRIBUTE: " + path);
            SetFileAttributesA(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
        }
        
        // Try to delete the file
        if (DeleteFileA(path.c_str())) {
            Utils::LogAction(userID, "FILE_DELETED_SUCCESS: " + path);
            return true;
        }
        
        DWORD error = GetLastError();
        Utils::LogAction(userID, "DELETE_ATTEMPT_FAILED: " + std::to_string(attempt) + " Error: " + std::to_string(error));
        
        // Handle specific errors
        switch (error) {
            case ERROR_ACCESS_DENIED:
                Utils::LogAction(userID, "DELETE_ACCESS_DENIED_RETRYING");
                if (attempt < maxRetries) {
                    Sleep(Utils::Constants::SECURITY_CHECK_INTERVAL); // Wait before retry
                }
                break;
                
            case ERROR_SHARING_VIOLATION:
                Utils::LogAction(userID, "DELETE_SHARING_VIOLATION_RETRYING");
                if (attempt < maxRetries) {
                    Sleep(2000); // Wait 2 seconds for file release
                }
                break;
                
            case ERROR_FILE_NOT_FOUND:
                Utils::LogAction(userID, "FILE_NOT_FOUND_DURING_DELETE: " + path);
                return true; // File was deleted by someone else
                
            default:
                HandleFileError("DELETE_FILE", path, error);
                if (attempt < maxRetries) {
                    Sleep(500);
                }
                break;
        }
    }
    
    Utils::LogAction(userID, "FILE_DELETE_FAILED_ALL_RETRIES: " + path);
    return false;
}

bool ScreenLocker::SafeWriteFile(const std::string& path, const std::string& content) {
    Utils::LogAction(userID, "SAFE_WRITE_FILE: " + path + " Size: " + std::to_string(content.length()));
    
    // Ensure directory exists
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        std::string directory = path.substr(0, lastSlash);
        if (!SafeCreateDirectory(directory)) {
            Utils::LogAction(userID, "FAILED_TO_CREATE_DIRECTORY_FOR_FILE: " + directory);
            return false;
        }
    }
    
    // Try to write file
    HANDLE hFile = CreateFileA(path.c_str(),
                              GENERIC_WRITE,
                              0, // No sharing
                              NULL,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Utils::LogAction(userID, "FILE_CREATE_FAILED: " + std::to_string(error));
        HandleFileError("CREATE_FILE", path, error);
        return false;
    }
    
    DWORD bytesWritten;
    BOOL writeResult = WriteFile(hFile, content.c_str(), 
                                static_cast<DWORD>(content.length()), 
                                &bytesWritten, NULL);
    
    CloseHandle(hFile);
    
    if (!writeResult || bytesWritten != content.length()) {
        DWORD error = GetLastError();
        Utils::LogAction(userID, "FILE_WRITE_FAILED: " + std::to_string(error) + 
                             " Written: " + std::to_string(bytesWritten) + 
                             " Expected: " + std::to_string(content.length()));
        HandleFileError("WRITE_FILE", path, error);
        return false;
    }
    
    Utils::LogAction(userID, "FILE_WRITE_SUCCESS: " + path);
    return true;
}

bool ScreenLocker::HandleFileError(const std::string& operation, const std::string& path, DWORD errorCode) {
    Utils::LogAction(userID, "HANDLING_FILE_ERROR: " + operation + " Path: " + path + " Error: " + std::to_string(errorCode));
    
    std::string errorMessage = "Unknown file error";
    bool shouldRetry = false;
    
    switch (errorCode) {
        case ERROR_ACCESS_DENIED:
            errorMessage = "Access denied - check permissions";
            shouldRetry = true;
            break;
            
        case ERROR_SHARING_VIOLATION:
            errorMessage = "File is in use by another process";
            shouldRetry = true;
            break;
            
        case ERROR_DISK_FULL:
            errorMessage = "Disk is full";
            shouldRetry = false;
            break;
            
        case ERROR_PATH_NOT_FOUND:
            errorMessage = "Path not found";
            shouldRetry = false;
            break;
            
        case ERROR_FILE_NOT_FOUND:
            errorMessage = "File not found";
            shouldRetry = false;
            break;
            
        case ERROR_INVALID_NAME:
            errorMessage = "Invalid file name";
            shouldRetry = false;
            break;
            
        default:
            errorMessage = "System error code: " + std::to_string(errorCode);
            shouldRetry = true;
            break;
    }
    
    Utils::LogAction(userID, "FILE_ERROR_ANALYSIS: " + errorMessage + " ShouldRetry: " + (shouldRetry ? "Yes" : "No"));
    
    return shouldRetry;
}