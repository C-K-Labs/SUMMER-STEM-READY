#include "remover.h"
#include "StringUtils.h" // [REFACTOR] Include the new utility header.
#include "Constants.h" // [REFACTOR] Include the new constants header.
#include <iostream>
#include <fstream>
#include <shlobj.h>
#include <sstream> // [REFACTOR] Add stringstream header

// ... (anonymous namespace with helper functions remains unchanged) ...
namespace {

void AppendBatchHeader(std::stringstream& ss, const std::string& logPath) {
    ss << "@echo off\n";
    ss << "chcp 65001 >nul\n";
    ss << "echo [%date% %time%] Batch started >> \"" << logPath << "\"\n";
}

void AppendProcessKill(std::stringstream& ss, DWORD pid, const std::string& logPath) {
    ss << "echo [%date% %time%] Waiting for main process to exit... >> \"" << logPath << "\"\n";
    ss << "ping 127.0.0.1 -n 3 >nul\n";
    ss << "echo [%date% %time%] Force killing remover process (PID: " << pid << ") >> \"" << logPath << "\"\n";
    ss << "taskkill /f /pid " << pid << " >nul 2>&1\n";
    ss << "ping 127.0.0.1 -n 2 >nul\n";
}

void AppendRemoverDeletion(std::stringstream& ss, const std::string& removerPath, const std::string& logPath) {
    ss << "echo [%date% %time%] Attempting to delete remover executable... >> \"" << logPath << "\"\n";
    ss << ":DELETE_REMOVER\n";
    ss << "del \"" << removerPath << "\" >nul 2>&1\n";
    ss << "if exist \"" << removerPath << "\" (\n";
    ss << "    ping 127.0.0.1 -n 2 >nul\n";
    ss << "    del \"" << removerPath << "\" >nul 2>&1\n";
    ss << "    if exist \"" << removerPath << "\" (\n";
    ss << "        echo [%date% %time%] remover.exe deletion failed after multiple attempts >> \"" << logPath << "\"\n";
    ss << "    ) else (\n";
    ss << "        echo [%date% %time%] remover.exe deleted on 2nd attempt >> \"" << logPath << "\"\n";
    ss << "    )\n";
    ss << ") else (\n";
    ss << "    echo [%date% %time%] remover.exe deleted on 1st attempt >> \"" << logPath << "\"\n";
    ss << ")\n";
}

void AppendFolderCleanup(std::stringstream& ss, const std::string& ipTimeDir, const std::string& logPath) {
    ss << "echo [%date% %time%] Deleting log files and ipTime folder... >> \"" << logPath << "\"\n";
    ss << "del /f /q \"" << ipTimeDir << "\\*.*\" >nul 2>&1\n";
    ss << "rmdir /s /q \"" << ipTimeDir << "\" >nul 2>&1\n";
    ss << "if exist \"" << ipTimeDir << "\" (\n";
    ss << "    echo [%date% %time%] ipTime folder deletion failed >> \"" << logPath << "\"\n";
    ss << ") else (\n";
    ss << "    echo [%date% %time%] ipTime folder deleted successfully >> \"" << logPath << "\"\n";
    ss << ")\n";
}

void AppendCompletionMessage(std::stringstream& ss, const std::string& logPath) {
    ss << "echo [%date% %time%] Showing completion message... >> \"" << logPath << "\"\n";
    ss << "powershell -Command \"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Removal Completed Successfully. You may now close any remaining windows.', 'Complete', 'OK', 'Information')\" >nul 2>&1\n";
    ss << "if errorlevel 1 (\n";
    ss << "    mshta \"javascript:alert('Removal Completed Successfully.');close()\" >nul 2>&1\n";
    ss << ")\n";
}

void AppendSelfDelete(std::stringstream& ss, const std::string& logPath) {
    ss << "echo [%date% %time%] Cleaning up batch file... >> \"" << logPath << "\"\n";
    ss << "del \"%~f0\" >nul 2>&1\n";
    ss << "exit\n";
}

} // end anonymous namespace

// [FIX] Constructor now initializes the isUsbRemover flag.
Remover::Remover(bool usbMode) : isUsbRemover(usbMode) {
    // Constructor
}

Remover::~Remover() {
    // Destructor
}

bool Remover::Initialize() {
    LogAction("REMOVER_INITIALIZED");
    
    // Check if running as administrator
    if (!IsRunningAsAdmin()) {
        LogAction("REMOVER_NOT_ADMIN");
        MessageBoxA(NULL, "Administrator privileges required to proceed", "Admin Required", MB_OK | MB_ICONWARNING);
        return false;
    }
    
    LogAction("REMOVER_ADMIN_CONFIRMED");
    return true;
}

bool Remover::IsRunningAsAdmin() {
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

int Remover::Run() {
    LogAction("REMOVER_EXECUTION_STARTED");
    
    // Execute removal process
    if (ExecuteRemoval()) {
        // Self-deletion first
        LogAction("PREPARING_FOR_IMMEDIATE_EXIT");
        
        // Program immediate exit (ExitProcess usage)
        ExitProcess(0);  // Force exit
        
        return 0;
    } else {
        LogAction("REMOVER_EXECUTION_FAILED");
        MessageBoxA(NULL, "Removal process failed", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }
}

bool Remover::ExecuteRemoval() {
    LogAction("REMOVER_PROCESS_STARTED");

    // 1st step: Process detection and termination (first to be executed)
    LogAction("STEP_1_TERMINATING_SCREENLOCKER_PROCESS");
    if (!FindAndTerminateProcess()) {
        LogAction("PROCESS_TERMINATION_FAILED - MAY NOT BE RUNNING");
        // Continue even if the process is not found
    }
    
    // Wait for the process to completely exit and file locks to be released
    Sleep(1500); 

    // 2nd step: Restore system settings
    LogAction("STEP_2_RESTORING_SYSTEM_SETTINGS");
    RestorePowerManagementSettings();
    RestoreSystemExecutionState();
    CleanupSystemHooks();

    // 3rd step: Remove auto-start registry
    LogAction("STEP_3_REMOVING_AUTOSTART_ENTRY");
    if (!RemoveAutoStartEntry()) {
        LogAction("AUTOSTART_REMOVE_FAILED_CONTINUING");
    }
    
    // 4th step: Delete files
    LogAction("STEP_4_DELETING_FILES");
    bool success = RemoveScreenLockerFiles();
    
    if (success) {
        LogAction("FILE_DELETION_SUCCESSFUL");
        
        // 5th step: Execute self-deletion
        LogAction("STEP_5_INITIATING_SELF_DELETE");
        if (SelfDelete()) {
            LogAction("SELF_DELETE_INITIATED_SUCCESSFULLY");
            return true;
        } else {
            LogAction("SELF_DELETE_INITIATION_FAILED");
            return false;
        }
    } else {
        LogAction("FILE_DELETION_FAILED");
        return false;
    }
}

bool Remover::RemoveScreenLockerFiles() {
    LogAction("REMOVER_FILE_SCAN_STARTED");
    
    bool overallSuccess = true;
    
    // 1. Delete main executable
    LogAction("STEP_1_DELETING_MAIN_EXECUTABLE");
    if (!DeleteMainExecutable()) {
        LogAction("MAIN_EXECUTABLE_DELETE_STEP_FAILED");
        overallSuccess = false;
    } else {
        LogAction("MAIN_EXECUTABLE_DELETE_STEP_SUCCESS");
    }
    
    // 2. Delete log folders (temporarily disabled)
    LogAction("STEP_2_DELETING_LOG_FOLDERS");
    if (!DeleteLogFolders()) {
        LogAction("LOG_FOLDERS_DELETE_STEP_FAILED");
        overallSuccess = false;
    } else {
        LogAction("LOG_FOLDERS_DELETE_STEP_SUCCESS");
    }
    
    if (overallSuccess) {
        LogAction("ALL_FILES_DELETED_SUCCESS");
    } else {
        LogAction("SOME_FILES_DELETE_FAILED");
    }
    
    LogAction("REMOVER_FILE_SCAN_COMPLETED");
    return overallSuccess;
}

bool Remover::FindAndTerminateProcess() {
    LogAction("SEARCHING_FOR_SCREENLOCKER_PROCESS");
    
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    targetExecutablePath = "";  // Initialize
    bool processFound = false;
    int processCount = 0;
    
    // Create process snapshot
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        LogAction("PROCESS_SNAPSHOT_FAILED");
        return false;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // Get first process information
    if (!Process32First(hProcessSnap, &pe32)) {
        LogAction("PROCESS32_FIRST_FAILED");
        CloseHandle(hProcessSnap);
        return false;
    }
    
    LogAction("STARTING_PROCESS_ENUMERATION");
    
    // Enumerate all processes to find ScreenLockerPoC.exe
    do {
        processCount++;
        std::wstring processNameW(pe32.szExeFile);
        std::string processName = StringUtils::WStringToString(processNameW);
        
        // Debug: Log all process names (first 10 only)
        if (processCount <= 10) {
            LogAction("PROCESS_" + std::to_string(processCount) + ": " + processName);
        }
        
        // Case-insensitive comparison - new file names included
        if (processName.find("ScreenLockerPoC") != std::string::npos || 
            processName.find("screenlockerpoc") != std::string::npos ||
            processName.find("Application_Form.pdf") != std::string::npos ||
            processName.find("application_form.pdf") != std::string::npos ||
            processName.find("Form_DocumentViewer") != std::string::npos ||
            processName.find("form_documentviewer") != std::string::npos) {
            
            LogAction("TARGET_PROCESS_FOUND: " + processName + " (PID: " + std::to_string(pe32.th32ProcessID) + ")");
            
            // Get the executable path and store it in the member variable
            targetExecutablePath = GetProcessExecutablePath(pe32.th32ProcessID);

            if (!targetExecutablePath.empty()) {
                LogAction("EXECUTABLE_PATH_FOUND: " + targetExecutablePath);
            } else {
                LogAction("EXECUTABLE_PATH_NOT_FOUND");
            }
            
            // Terminate the process
            if (TerminateProcessSafely(pe32.th32ProcessID)) {
                LogAction("PROCESS_TERMINATED_SUCCESS");
                processFound = true;
            } else {
                LogAction("PROCESS_TERMINATE_FAILED");
            }
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    
    CloseHandle(hProcessSnap);
    
    LogAction("TOTAL_PROCESSES_SCANNED: " + std::to_string(processCount));
    
    if (!processFound) {
        LogAction("SCREENLOCKER_PROCESS_NOT_FOUND");
        // Even if the process is not found, delete the files
        return true;
    }
    
    return processFound;
}

std::string Remover::GetProcessExecutablePath(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        LogAction("OPEN_PROCESS_FAILED_FOR_PATH");
        return "";
    }
    
    wchar_t executablePath[MAX_PATH];  // Change char to wchar_t
    DWORD pathLength = MAX_PATH;
    
    if (QueryFullProcessImageNameW(hProcess, 0, executablePath, &pathLength)) {  // Change A to W
        CloseHandle(hProcess);
        return StringUtils::WStringToString(std::wstring(executablePath)); // Add conversion
    }
    
    CloseHandle(hProcess);
    LogAction("QUERY_PROCESS_PATH_FAILED");
    return "";
}

bool Remover::TerminateProcessSafely(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        LogAction("OPEN_PROCESS_FAILED_FOR_TERMINATE");
        return false;
    }
    
    if (TerminateProcess(hProcess, 0)) {
        // Wait for the process to actually exit
        WaitForSingleObject(hProcess, 5000); // 5 seconds wait
        CloseHandle(hProcess);
        return true;
    }
    
    CloseHandle(hProcess);
    return false;
}

std::string Remover::GetExecutableDirectory() {
    LogAction("GETTING_EXECUTABLE_DIRECTORY");
    
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        DWORD error = GetLastError();
        LogAction("GET_MODULE_FILENAME_FAILED: " + std::to_string(error));
        return "";
    }
    
    std::wstring wExeDir = exePath;
    // [BUILD FIX] Change this last remaining call to use the StringUtils namespace.
    LogAction("RAW_EXECUTABLE_PATH: " + StringUtils::WStringToString(wExeDir));
    
    size_t lastSlash = wExeDir.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        wExeDir = wExeDir.substr(0, lastSlash);
    }
    
    std::string exeDir = StringUtils::WStringToString(wExeDir);
    LogAction("EXECUTABLE_DIRECTORY: " + exeDir);
    return exeDir;
}

// [FIX] This function now uses a runtime check instead of a preprocessor directive.
std::string Remover::CreateSelfDeleteBatch() {
    LogAction("CREATING_SELF_DELETE_BATCH");

    // 1. Get necessary paths and the current process ID.
    wchar_t currentPathW[MAX_PATH];
    if (GetModuleFileNameW(NULL, currentPathW, MAX_PATH) == 0) {
        LogAction("GET_CURRENT_EXECUTABLE_PATH_FAILED");
        return "";
    }
    std::string currentExePath = StringUtils::WStringToString(std::wstring(currentPathW));
    DWORD currentPID = GetCurrentProcessId();

    char programDataPath[MAX_PATH];
    std::string ipTimeDir = "";
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath) == S_OK) {
        ipTimeDir = std::string(programDataPath) + "\\ipTime";
    }

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        LogAction("GET_TEMP_PATH_FAILED");
        return "";
    }
    std::string batchPath = std::string(tempPath) + "remover_cleanup.bat";
    std::string debugLogPath = std::string(tempPath) + "remover_cleanup_log.txt";

    // 2. Build the batch script content using a stringstream and helper functions.
    std::stringstream batchContentStream;
    AppendBatchHeader(batchContentStream, debugLogPath);
    AppendProcessKill(batchContentStream, currentPID, debugLogPath);

    // [FIX] Only add the self-deletion step if this is NOT the USB version.
    if (!isUsbRemover) {
        AppendRemoverDeletion(batchContentStream, currentExePath, debugLogPath);
    }

    if (!ipTimeDir.empty()) {
        AppendFolderCleanup(batchContentStream, ipTimeDir, debugLogPath);
    }
    AppendCompletionMessage(batchContentStream, debugLogPath);
    AppendSelfDelete(batchContentStream, debugLogPath);

    // 3. Write the generated content to the batch file.
    std::ofstream batchFile(batchPath);
    if (!batchFile.is_open()) {
        LogAction("BATCH_FILE_CREATE_FAILED: " + batchPath);
        return "";
    }
    batchFile << batchContentStream.str();
    batchFile.close();

    LogAction("SELF_DELETE_BATCH_CREATED: " + batchPath);
    return batchPath;
}

bool Remover::SelfDelete() {
    LogAction("SELF_DELETE_PROCESS_STARTED");
    
    // Create batch file
    std::string batchPath = CreateSelfDeleteBatch();
    if (batchPath.empty()) {
        LogAction("SELF_DELETE_BATCH_CREATION_FAILED");
        return false;
    }
    
    // Execute batch file
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hidden mode execution
    
    std::string commandLine = "cmd.exe /c \"" + batchPath + "\"";
    LogAction("EXECUTING_BATCH_COMMAND: " + commandLine);
    
    if (CreateProcessA(NULL, 
                      const_cast<char*>(commandLine.c_str()),
                      NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW | DETACHED_PROCESS,
                      NULL, NULL, &si, &pi)) {
        
        LogAction("SELF_DELETE_BATCH_STARTED");
        
        // Clean up handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    } else {
        DWORD error = GetLastError();
        LogAction("SELF_DELETE_BATCH_EXECUTION_FAILED: " + std::to_string(error));
        
        // Clean up batch file
        DeleteFileA(batchPath.c_str());
        return false;
    }
}

bool Remover::DeleteMainExecutable() {
    LogAction("ATTEMPTING_TO_DELETE_MAIN_EXECUTABLE");
    
    std::string mainExePath;
    
    if (!targetExecutablePath.empty()) {
        // Use the actual path obtained from the process
        mainExePath = targetExecutablePath;
        LogAction("USING_PROCESS_PATH: " + mainExePath);
    } else {
        // Backup: Find based on the current directory
        std::string exeDir = GetExecutableDirectory();
        if (exeDir.empty()) {
            LogAction("EXECUTABLE_DIRECTORY_NOT_FOUND");
            return false;
        }
        
        // Check all possible file names
        std::string latestPath = exeDir + "\\" + Constants::ExeName1;
        std::string middlePath = exeDir + "\\" + Constants::ExeName2;
        std::string oldPath = exeDir + "\\" + Constants::ExeName3;
        
        // Use the latest file if it exists
        if (GetFileAttributesA(latestPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            mainExePath = latestPath;
            LogAction("USING_LATEST_PATH: " + mainExePath);
        } else if (GetFileAttributesA(middlePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            mainExePath = middlePath;
            LogAction("USING_MIDDLE_PATH: " + mainExePath);
        } else {
            mainExePath = oldPath;
            LogAction("USING_FALLBACK_PATH: " + mainExePath);
        }

        LogAction("USING_FALLBACK_PATH: " + mainExePath);
    }
    
    if (DeleteFileA(mainExePath.c_str())) {
        LogAction("MAIN_EXECUTABLE_DELETED: " + mainExePath);
        return true;
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            LogAction("MAIN_EXECUTABLE_NOT_FOUND: " + mainExePath);
            return true; // Treat as success even if the file is not found
        } else {
            LogAction("MAIN_EXECUTABLE_DELETE_FAILED: " + std::to_string(error));
            return false;
        }
    }
}

bool Remover::DeleteFolderRecursively(const std::string& folderPath) {
    LogAction("DELETING_FOLDER_RECURSIVELY: " + folderPath);
    
    std::string searchPath = folderPath + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            LogAction("FOLDER_NOT_FOUND: " + folderPath);
            return true; // Treat as success even if the folder is not found
        }
        LogAction("FIND_FIRST_FILE_FAILED: " + std::to_string(error));
        return false;
    }
    
    do {
        std::string fileName = findData.cFileName;
        
        // Skip . and ..
        if (fileName == "." || fileName == "..") {
            continue;
        }
        
        std::string fullPath = folderPath + "\\" + fileName;
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursively delete subfolders
            if (!DeleteFolderRecursively(fullPath)) {
                LogAction("SUBFOLDER_DELETE_FAILED: " + fullPath);
            }
            
            // Delete the folder
            if (RemoveDirectoryA(fullPath.c_str())) {
                LogAction("SUBFOLDER_DELETED: " + fullPath);
            } else {
                LogAction("SUBFOLDER_REMOVE_FAILED: " + fullPath);
            }
        } else {
            // Delete the file
            if (DeleteFileA(fullPath.c_str())) {
                LogAction("FILE_DELETED: " + fullPath);
            } else {
                LogAction("FILE_DELETE_FAILED: " + fullPath);
            }
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    
    // Finally delete the folder itself
    if (RemoveDirectoryA(folderPath.c_str())) {
        LogAction("FOLDER_DELETED_SUCCESS: " + folderPath);
        return true;
    } else {
        DWORD error = GetLastError();
        LogAction("FOLDER_DELETE_FAILED: " + folderPath + " (Error: " + std::to_string(error) + ")");
        return false;
    }
}

bool Remover::DeleteLogFolders() {
    LogAction("DELETING_LOG_FOLDERS");
    bool success = true;
    
    // Delete %APPDATA%\Windows folder
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) == S_OK) {
        std::string windowsLogDir = std::string(appDataPath) + Constants::AppDataLogDir;
        LogAction("ATTEMPTING_TO_DELETE_APPDATA_WINDOWS: " + windowsLogDir);
        if (!DeleteFolderRecursively(windowsLogDir)) {
            LogAction("APPDATA_WINDOWS_DELETE_FAILED");
            success = false;
        } else {
            LogAction("APPDATA_WINDOWS_DELETE_SUCCESS");
        }
    } else {
        LogAction("APPDATA_PATH_GET_FAILED");
        success = false;
    }
    
    // %PROGRAMDATA%\ipTime folder is handled by self-deletion, so it is excluded here
    // The current running remover.exe cannot be deleted because it is running
    LogAction("PROGRAMDATA_IPTIME_SKIPPED_FOR_SELF_DELETE");
    
    return success;
}

void Remover::LogAction(const std::string& action) {
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, appDataPath) == S_OK) {
        std::string logDir = std::string(appDataPath) + Constants::ProgramDataDir;
        std::string logPath = logDir + "\\" + Constants::RemoverLogFile;
        
        // Create directory if it doesn't exist
        CreateDirectoryA(logDir.c_str(), NULL);
        
        std::ofstream logFile(logPath, std::ios::app);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        logFile << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay 
                << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond 
                << "] " << action << std::endl;
        
        logFile.close();
    }
}

bool Remover::RemoveAutoStartEntry() {
    LogAction("REMOVING_AUTOSTART_REGISTRY_ENTRY");
    
    HKEY hKey;
    LONG result;
    
    // Open registry key for current user's startup programs
    result = RegOpenKeyEx(HKEY_CURRENT_USER, 
                         L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                         0, KEY_SET_VALUE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        // Delete the registry value
        result = RegDeleteValueW(hKey, Constants::RegistryKeyName);
        
        if (result == ERROR_SUCCESS) {
            LogAction("AUTOSTART_ENTRY_REMOVED_SUCCESS");
        } else if (result == ERROR_FILE_NOT_FOUND) {
            LogAction("AUTOSTART_ENTRY_NOT_FOUND");
            result = ERROR_SUCCESS; // Not an error if it doesn't exist
        } else {
            LogAction("AUTOSTART_ENTRY_REMOVE_FAILED: " + std::to_string(result));
        }
        
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    } else {
        LogAction("AUTOSTART_REGISTRY_OPEN_FAILED_FOR_REMOVE: " + std::to_string(result));
        return false;
    }
}

bool Remover::RestorePowerManagementSettings() {
    LogAction("RESTORING_POWER_MANAGEMENT_SETTINGS");
    
    // Reset execution state to allow normal power management
    EXECUTION_STATE result = SetThreadExecutionState(ES_CONTINUOUS);
    
    if (result != 0) {
        LogAction("POWER_MANAGEMENT_RESTORED_SUCCESS");
        
        // Additional reset to ensure clean state
        SetThreadExecutionState(ES_CONTINUOUS);
        LogAction("EXECUTION_STATE_RESET_COMPLETED");
        return true;
    } else {
        DWORD error = GetLastError();
        LogAction("POWER_MANAGEMENT_RESTORE_FAILED: " + std::to_string(error));
        return false;
    }
}

bool Remover::RestoreSystemExecutionState() {
    LogAction("RESTORING_SYSTEM_EXECUTION_STATE");
    
    try {
        // Force reset all execution state flags
        EXECUTION_STATE currentState = SetThreadExecutionState(
            ES_CONTINUOUS |
            (~(ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_AWAYMODE_REQUIRED))
        );
        
        // Then set to normal state
        SetThreadExecutionState(ES_CONTINUOUS);
        
        LogAction("SYSTEM_EXECUTION_STATE_RESTORED");
        return true;
        
    } catch (...) {
        LogAction("SYSTEM_EXECUTION_STATE_RESTORE_EXCEPTION");
        return false;
    }
}

bool Remover::CleanupSystemHooks() {
    LogAction("CLEANING_UP_SYSTEM_HOOKS");
    
    // Note: We cannot directly remove hooks from another process,
    // but we can ensure the process is terminated cleanly
    // The hook cleanup will happen automatically when the process terminates
    
    bool success = true;
    
    // Check if any hook-related processes are still running
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                std::wstring processNameW(pe32.szExeFile);
                std::string processName = StringUtils::WStringToString(processNameW);
                
                // Check for any remaining ScreenLocker processes
                if (processName.find("Form_DocumentViewer") != std::string::npos ||
                    processName.find("ScreenLocker") != std::string::npos) {
                    
                    LogAction("FOUND_REMAINING_PROCESS: " + processName);
                    
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        if (TerminateProcess(hProcess, 0)) {
                            WaitForSingleObject(hProcess, 3000); // Wait up to 3 seconds
                            LogAction("REMAINING_PROCESS_TERMINATED: " + processName);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }
    
    // Small delay to ensure hooks are properly released
    Sleep(1000);
    
    LogAction("SYSTEM_HOOKS_CLEANUP_COMPLETED");
    return success;
}