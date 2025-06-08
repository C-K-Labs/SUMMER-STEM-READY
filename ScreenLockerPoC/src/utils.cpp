#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <cctype>
#include <algorithm>
#include <iphlpapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>

namespace Utils {

// ↓↓↓ String conversion utilities implementation ↓↓↓
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string UrlEncode(const std::string& str) {
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

// ↓↓↓ Logging utilities implementation ↓↓↓
void LogAction(const std::string& userID, const std::string& action) {
    LogAction(userID, action, "");
}

void LogAction(const std::string& userID, const std::string& action, const std::string& details) {
    std::string appDataPath = GetAppDataPath();
    if (appDataPath.empty()) return;
    
    std::string logDir = appDataPath + Constants::LOG_FOLDER_APPDATA;
    std::string logPath = logDir + "\\" + Constants::MAIN_LOG_FILE;
    
    // Create directory if it doesn't exist
    SafeCreateDirectory(logDir);
    
    std::ofstream logFile(logPath, std::ios::app);
    if (!logFile.is_open()) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    logFile << "[" << st.wYear << "-" << std::setfill('0') << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay 
            << " " << std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2) << st.wSecond 
            << "] " << action;
    
    if (!details.empty()) {
        logFile << " | " << details;
    }
    
    logFile << " | User ID: " << userID << " | MAC: " << GetMacAddress() << std::endl;
    logFile.close();
}

// ↓↓↓ System utilities implementation ↓↓↓
std::string GetMacAddress() {
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

// ↓↓↓ Process utilities implementation ↓↓↓
bool FindProcessByName(const std::string& processName, std::vector<DWORD>& processIds) {
    processIds.clear();
    
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    bool found = false;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            std::wstring processNameW(pe32.szExeFile);
            std::string currentProcessName = WStringToString(processNameW);
            
            // Case-insensitive comparison
            std::string lowerProcessName = processName;
            std::string lowerCurrentName = currentProcessName;
            std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);
            std::transform(lowerCurrentName.begin(), lowerCurrentName.end(), lowerCurrentName.begin(), ::tolower);
            
            if (lowerCurrentName.find(lowerProcessName) != std::string::npos) {
                processIds.push_back(pe32.th32ProcessID);
                found = true;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    
    CloseHandle(hProcessSnap);
    return found;
}

bool TerminateProcessSafely(DWORD processId, const std::string& processName) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) return false;
    
    // Try graceful termination first (if it's a windowed application)
    HWND hWnd = NULL;
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        DWORD windowProcessId;
        GetWindowThreadProcessId(hwnd, &windowProcessId);
        if (windowProcessId == (DWORD)lParam) {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        return TRUE;
    }, (LPARAM)processId);
    
    // Wait a bit for graceful shutdown
    DWORD waitResult = WaitForSingleObject(hProcess, 3000);
    if (waitResult == WAIT_OBJECT_0) {
        CloseHandle(hProcess);
        return true; // Process terminated gracefully
    }
    
    // Force termination if graceful failed
    BOOL result = TerminateProcess(hProcess, 0);
    if (result) {
        WaitForSingleObject(hProcess, 5000); // Wait up to 5 seconds
    }
    
    CloseHandle(hProcess);
    return result == TRUE;
}

std::string GetProcessExecutablePath(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) return "";
    
    wchar_t executablePath[MAX_PATH];
    DWORD pathLength = MAX_PATH;
    
    if (QueryFullProcessImageNameW(hProcess, 0, executablePath, &pathLength)) {
        CloseHandle(hProcess);
        return WStringToString(std::wstring(executablePath));
    }
    
    CloseHandle(hProcess);
    return "";
}

// ↓↓↓ File system utilities implementation ↓↓↓
bool SafeCreateDirectory(const std::string& path) {
    // Check if directory already exists
    DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;
    }
    
    // Try to create directory
    if (CreateDirectoryA(path.c_str(), NULL)) {
        return true;
    }
    
    DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS) {
        return true; // Success - directory exists
    }
    
    if (error == ERROR_PATH_NOT_FOUND) {
        // Try to create parent directories
        size_t lastSlash = path.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            std::string parentPath = path.substr(0, lastSlash);
            if (SafeCreateDirectory(parentPath)) {
                return CreateDirectoryA(path.c_str(), NULL) != FALSE;
            }
        }
    }
    
    return false;
}

bool SafeDeleteFile(const std::string& path, int maxRetries) {
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        // Check if file exists
        if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) {
                return true; // File doesn't exist - mission accomplished
            }
        }
        
        // Try to remove read-only attribute
        DWORD attributes = GetFileAttributesA(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY)) {
            SetFileAttributesA(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
        }
        
        // Try to delete the file
        if (DeleteFileA(path.c_str())) {
            return true;
        }
        
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            return true; // File was deleted by someone else
        }
        
        if (attempt < maxRetries) {
            Sleep(1000); // Wait before retry
        }
    }
    
    return false;
}

bool SafeWriteFile(const std::string& path, const std::string& content) {
    // Ensure directory exists
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        std::string directory = path.substr(0, lastSlash);
        if (!SafeCreateDirectory(directory)) {
            return false;
        }
    }
    
    // Try to write file
    HANDLE hFile = CreateFileA(path.c_str(),
                              GENERIC_WRITE,
                              0,
                              NULL,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD bytesWritten;
    BOOL writeResult = WriteFile(hFile, content.c_str(), 
                                static_cast<DWORD>(content.length()), 
                                &bytesWritten, NULL);
    
    CloseHandle(hFile);
    
    return (writeResult && bytesWritten == content.length());
}

bool DeleteFolderRecursively(const std::string& folderPath) {
    std::string searchPath = folderPath + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return true; // Folder doesn't exist
        }
        return false;
    }
    
    do {
        std::string fileName = findData.cFileName;
        
        if (fileName == "." || fileName == "..") {
            continue;
        }
        
        std::string fullPath = folderPath + "\\" + fileName;
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteFolderRecursively(fullPath);
            RemoveDirectoryA(fullPath.c_str());
        } else {
            SafeDeleteFile(fullPath);
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    
    return RemoveDirectoryA(folderPath.c_str()) != FALSE;
}

std::string GetExecutableDirectory() {
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        return "";
    }
    
    std::wstring wExeDir = exePath;
    size_t lastSlash = wExeDir.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        wExeDir = wExeDir.substr(0, lastSlash);
    }
    
    return WStringToString(wExeDir);
}

std::string GetAppDataPath() {
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) == S_OK) {
        return std::string(appDataPath);
    }
    return "";
}

std::string GetProgramDataPath() {
    char programDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath) == S_OK) {
        return std::string(programDataPath);
    }
    return "";
}

// ↓↓↓ Registry utilities implementation ↓↓↓
bool SetRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName, const std::string& value) {
    HKEY hSubKey;
    LONG result = RegOpenKeyExA(hKey, subKey.c_str(), 0, KEY_SET_VALUE, &hSubKey);
    
    if (result == ERROR_SUCCESS) {
        std::wstring wValueName = StringToWString(valueName);
        std::wstring wValue = StringToWString(value);
        
        result = RegSetValueExW(hSubKey, wValueName.c_str(), 0, REG_SZ, 
                               (BYTE*)wValue.c_str(), (wValue.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hSubKey);
    }
    
    return result == ERROR_SUCCESS;
}

bool DeleteRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName) {
    HKEY hSubKey;
    LONG result = RegOpenKeyExA(hKey, subKey.c_str(), 0, KEY_SET_VALUE, &hSubKey);
    
    if (result == ERROR_SUCCESS) {
        std::wstring wValueName = StringToWString(valueName);
        result = RegDeleteValueW(hSubKey, wValueName.c_str());
        RegCloseKey(hSubKey);
    }
    
    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
}

// ↓↓↓ System state utilities implementation ↓↓↓
bool RestorePowerManagementSettings() {
    EXECUTION_STATE result = SetThreadExecutionState(ES_CONTINUOUS);
    if (result != 0) {
        SetThreadExecutionState(ES_CONTINUOUS); // Additional reset
        return true;
    }
    return false;
}

bool RestoreSystemExecutionState() {
    try {
        SetThreadExecutionState(ES_CONTINUOUS);
        return true;
    } catch (...) {
        return false;
    }
}

// ↓↓↓ Error handling utilities implementation ↓↓↓
std::string GetErrorMessage(DWORD errorCode) {
    switch (errorCode) {
        case ERROR_ACCESS_DENIED: return "Access denied";
        case ERROR_FILE_NOT_FOUND: return "File not found";
        case ERROR_PATH_NOT_FOUND: return "Path not found";
        case ERROR_SHARING_VIOLATION: return "File is in use by another process";
        case ERROR_DISK_FULL: return "Disk is full";
        case ERROR_INVALID_PARAMETER: return "Invalid parameter";
        case ERROR_NOT_ENOUGH_MEMORY: return "Not enough memory";
        case ERROR_INTERNET_TIMEOUT: return "Network timeout";
        case ERROR_INTERNET_CONNECTION_RESET: return "Connection reset";
        case ERROR_INTERNET_CANNOT_CONNECT: return "Cannot connect to server";
        default: return "Unknown error (code: " + std::to_string(errorCode) + ")";
    }
}

void LogError(const std::string& userID, const std::string& operation, DWORD errorCode) {
    std::string errorMessage = GetErrorMessage(errorCode);
    LogAction(userID, "ERROR_" + operation, errorMessage + " (Code: " + std::to_string(errorCode) + ")");
}

bool IsRetryableError(DWORD errorCode) {
    switch (errorCode) {
        // Retryable errors
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
        case ERROR_INTERNET_TIMEOUT:
        case ERROR_INTERNET_CONNECTION_RESET:
        case ERROR_INTERNET_CANNOT_CONNECT:
        case ERROR_INTERNET_NAME_NOT_RESOLVED:
            return true;
            
        // Non-retryable errors
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_DISK_FULL:
        case ERROR_INVALID_PARAMETER:
        case ERROR_NOT_ENOUGH_MEMORY:
            return false;
            
        default:
            return true; // Assume retryable for unknown errors
    }
}

} // namespace Utils