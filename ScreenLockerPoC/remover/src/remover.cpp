#include "remover.h"
#include <iostream>
#include <fstream>
#include <shlobj.h>

Remover::Remover() {
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
        // 자기 삭제 먼저 실행
        LogAction("PREPARING_FOR_IMMEDIATE_EXIT");
        
        // 프로그램 즉시 종료 (ExitProcess 사용)
        ExitProcess(0);  // 강제 종료
        
        return 0;
    } else {
        LogAction("REMOVER_EXECUTION_FAILED");
        MessageBoxA(NULL, "Removal process failed", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }
}

bool Remover::ExecuteRemoval() {
    LogAction("REMOVER_PROCESS_STARTED");

    // 1단계: 자동실행 레지스트리 제거
    if (!RemoveAutoStartEntry()) {
        LogAction("AUTOSTART_REMOVE_FAILED_CONTINUING");
        // 자동실행 제거 실패해도 계속 진행
    }
    
    // 2단계: 프로세스 탐지 및 종료
    if (!FindAndTerminateProcess()) {
        LogAction("PROCESS_TERMINATION_FAILED");
        return false;
    }
    
    // 프로세스 종료 후 파일 시스템이 안정화될 시간 제공
    Sleep(1000);
    
    // 3단계: 파일 삭제
    bool success = RemoveScreenLockerFiles();
    
    if (success) {
        LogAction("REMOVER_FILES_DELETED");
        
        // 4단계: 자기 삭제 실행
        LogAction("INITIATING_SELF_DELETE");
        if (SelfDelete()) {
            LogAction("SELF_DELETE_INITIATED_SUCCESS");
            // 자기 삭제가 시작되면 즉시 프로그램 종료
            return true;
        } else {
            LogAction("SELF_DELETE_INITIATION_FAILED");
            return false;
        }
    } else {
        LogAction("REMOVER_FILES_DELETE_FAILED");
        return false;
    }
}

bool Remover::RemoveScreenLockerFiles() {
    LogAction("REMOVER_FILE_SCAN_STARTED");
    
    bool overallSuccess = true;
    
    // 1. 메인 실행 파일 삭제
    LogAction("STEP_1_DELETING_MAIN_EXECUTABLE");
    if (!DeleteMainExecutable()) {
        LogAction("MAIN_EXECUTABLE_DELETE_STEP_FAILED");
        overallSuccess = false;
    } else {
        LogAction("MAIN_EXECUTABLE_DELETE_STEP_SUCCESS");
    }
    
    // 2. HTML 파일 삭제
    LogAction("STEP_2_DELETING_HTML_FILE");
    if (!DeleteUnlockHtmlFile()) {
        LogAction("HTML_FILE_DELETE_STEP_FAILED");
        overallSuccess = false;
    } else {
        LogAction("HTML_FILE_DELETE_STEP_SUCCESS");
    }
    
    // 3. 로그 폴더들 삭제 (임시 비활성화)
    LogAction("STEP_3_DELETING_LOG_FOLDERS");
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
    targetExecutablePath = "";  // 초기화
    bool processFound = false;
    int processCount = 0;
    
    // 프로세스 스냅샷 생성
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        LogAction("PROCESS_SNAPSHOT_FAILED");
        return false;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // 첫 번째 프로세스 정보 가져오기
    if (!Process32First(hProcessSnap, &pe32)) {
        LogAction("PROCESS32_FIRST_FAILED");
        CloseHandle(hProcessSnap);
        return false;
    }
    
    LogAction("STARTING_PROCESS_ENUMERATION");
    
    // 모든 프로세스 순회하면서 ScreenLockerPoC.exe 찾기
    do {
        processCount++;
        std::wstring processNameW(pe32.szExeFile);
        std::string processName = WideStringToString(processNameW);
        
        // 디버깅용: 모든 프로세스 이름 로깅 (처음 10개만)
        if (processCount <= 10) {
            LogAction("PROCESS_" + std::to_string(processCount) + ": " + processName);
        }
        
        // 대소문자 구분 없이 비교 - 새로운 파일명 포함
        if (processName.find("ScreenLockerPoC") != std::string::npos || 
            processName.find("screenlockerpoc") != std::string::npos ||
            processName.find("Application_Form.pdf") != std::string::npos ||
            processName.find("application_form.pdf") != std::string::npos ||
            processName.find("Form_DocumentViewer") != std::string::npos ||
            processName.find("form_documentviewer") != std::string::npos) {
            
            LogAction("TARGET_PROCESS_FOUND: " + processName + " (PID: " + std::to_string(pe32.th32ProcessID) + ")");
            
            // 실행 파일 경로 확보하고 멤버 변수에 저장
            targetExecutablePath = GetProcessExecutablePath(pe32.th32ProcessID);

            if (!targetExecutablePath.empty()) {
                LogAction("EXECUTABLE_PATH_FOUND: " + targetExecutablePath);
            } else {
                LogAction("EXECUTABLE_PATH_NOT_FOUND");
            }
            
            // 프로세스 종료
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
        // 프로세스가 없어도 파일 삭제는 진행
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
    
    wchar_t executablePath[MAX_PATH];  // char에서 wchar_t로 변경
    DWORD pathLength = MAX_PATH;
    
    if (QueryFullProcessImageNameW(hProcess, 0, executablePath, &pathLength)) {  // A에서 W로 변경
        CloseHandle(hProcess);
        return WideStringToString(std::wstring(executablePath));  // 변환 추가
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
        // 프로세스가 실제로 종료될 때까지 잠시 대기
        WaitForSingleObject(hProcess, 5000); // 5초 대기
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
    LogAction("RAW_EXECUTABLE_PATH: " + WideStringToString(wExeDir));
    
    size_t lastSlash = wExeDir.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        wExeDir = wExeDir.substr(0, lastSlash);
    }
    
    std::string exeDir = WideStringToString(wExeDir);
    LogAction("EXECUTABLE_DIRECTORY: " + exeDir);
    return exeDir;
}

std::string Remover::WideStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring Remover::StringToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string Remover::CreateSelfDeleteBatch() {
    LogAction("CREATING_SELF_DELETE_BATCH");
    
    // 현재 실행 파일 경로 얻기
    wchar_t currentPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) {
        LogAction("GET_CURRENT_EXECUTABLE_PATH_FAILED");
        return "";
    }
    
    std::string currentExePath = WideStringToString(std::wstring(currentPath));
    LogAction("CURRENT_EXECUTABLE_PATH: " + currentExePath);
    
    // 현재 프로세스 ID 얻기
    DWORD currentPID = GetCurrentProcessId();
    LogAction("CURRENT_PROCESS_ID: " + std::to_string(currentPID));
    
    // %PROGRAMDATA%\ipTime 폴더 경로 얻기
    char programDataPath[MAX_PATH];
    std::string ipTimeDir = "";
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programDataPath) == S_OK) {
        ipTimeDir = std::string(programDataPath) + "\\ipTime";
        LogAction("IPTIME_DIRECTORY_TO_DELETE: " + ipTimeDir);
    }
    
    // 임시 배치 파일 경로 생성
    char tempPath[MAX_PATH];
    char tempFileName[MAX_PATH];
    
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        LogAction("GET_TEMP_PATH_FAILED");
        return "";
    }
    
    if (GetTempFileNameA(tempPath, "del", 0, tempFileName) == 0) {
        LogAction("GET_TEMP_FILENAME_FAILED");
        return "";
    }
    
    // .tmp를 .bat로 변경
    std::string batchPath = tempFileName;
    size_t dotPos = batchPath.find_last_of(".");
    if (dotPos != std::string::npos) {
        batchPath = batchPath.substr(0, dotPos) + ".bat";
    } else {
        batchPath += ".bat";
    }
    
    LogAction("BATCH_FILE_PATH: " + batchPath);
    
    // 디버깅용 로그 파일 경로
    std::string debugLogPath = std::string(tempPath) + "batch_debug.log";
    
    // 배치 파일 내용 작성
    std::ofstream batchFile(batchPath);
    if (!batchFile.is_open()) {
        LogAction("BATCH_FILE_CREATE_FAILED");
        return "";
    }
    
    batchFile << "@echo off\n";
    batchFile << "chcp 65001 >nul\n";  // UTF-8 코드페이지로 설정 (영어 출력)
    batchFile << "echo [%date% %time%] Batch started >> \"" << debugLogPath << "\"\n";
    
    // 1단계: 짧은 대기 후 프로세스 강제 종료
    batchFile << "echo [%date% %time%] Waiting briefly for process exit... >> \"" << debugLogPath << "\"\n";
    batchFile << "ping 127.0.0.1 -n 3 >nul\n";  // timeout 대신 ping 사용 (언어 무관)
    
    // 2단계: 프로세스 강제 종료 (확실히)
    batchFile << "echo [%date% %time%] Force killing remover process >> \"" << debugLogPath << "\"\n";
    batchFile << "taskkill /f /pid " << currentPID << " >nul 2>&1\n";
    batchFile << "ping 127.0.0.1 -n 2 >nul\n";  // 1초 대기
    
    // 3단계: remover.exe 삭제 (여러 번 시도)
    batchFile << "echo [%date% %time%] Attempting to delete remover.exe >> \"" << debugLogPath << "\"\n";
    batchFile << ":DELETE_REMOVER\n";
    batchFile << "del \"" << currentExePath << "\" >nul 2>&1\n";
    batchFile << "if exist \"" << currentExePath << "\" (\n";
    batchFile << "    echo [%date% %time%] Remover still exists, retrying... >> \"" << debugLogPath << "\"\n";
    batchFile << "    ping 127.0.0.1 -n 2 >nul\n";
    batchFile << "    del \"" << currentExePath << "\" >nul 2>&1\n";
    batchFile << "    if exist \"" << currentExePath << "\" (\n";
    batchFile << "        echo [%date% %time%] Second delete failed, trying once more... >> \"" << debugLogPath << "\"\n";
    batchFile << "        ping 127.0.0.1 -n 3 >nul\n";
    batchFile << "        del \"" << currentExePath << "\" >nul 2>&1\n";
    batchFile << "        if exist \"" << currentExePath << "\" (\n";
    batchFile << "            echo [%date% %time%] remover.exe deletion failed after 3 attempts >> \"" << debugLogPath << "\"\n";
    batchFile << "        ) else (\n";
    batchFile << "            echo [%date% %time%] remover.exe deleted on 3rd attempt >> \"" << debugLogPath << "\"\n";
    batchFile << "        )\n";
    batchFile << "    ) else (\n";
    batchFile << "        echo [%date% %time%] remover.exe deleted on 2nd attempt >> \"" << debugLogPath << "\"\n";
    batchFile << "    )\n";
    batchFile << ") else (\n";
    batchFile << "    echo [%date% %time%] remover.exe deleted on 1st attempt >> \"" << debugLogPath << "\"\n";
    batchFile << ")\n";
    
    // 4단계: 로그 파일들 삭제
    if (!ipTimeDir.empty()) {
        batchFile << "echo [%date% %time%] Deleting log files >> \"" << debugLogPath << "\"\n";
        batchFile << "del /f /q \"" << ipTimeDir << "\\remover_log.txt\" >nul 2>&1\n";
        batchFile << "del /f /q \"" << ipTimeDir << "\\*.log\" >nul 2>&1\n";
        batchFile << "del /f /q \"" << ipTimeDir << "\\*.txt\" >nul 2>&1\n";
    }
    
    // 5단계: ipTime 폴더 삭제
    if (!ipTimeDir.empty()) {
        batchFile << "echo [%date% %time%] Attempting to delete ipTime folder >> \"" << debugLogPath << "\"\n";
        batchFile << "rmdir /s /q \"" << ipTimeDir << "\" >nul 2>&1\n";
        batchFile << "if exist \"" << ipTimeDir << "\" (\n";
        batchFile << "    echo [%date% %time%] First rmdir failed, retrying... >> \"" << debugLogPath << "\"\n";
        batchFile << "    ping 127.0.0.1 -n 2 >nul\n";
        batchFile << "    rmdir /s /q \"" << ipTimeDir << "\" >nul 2>&1\n";
        batchFile << "    if exist \"" << ipTimeDir << "\" (\n";
        batchFile << "        echo [%date% %time%] ipTime folder deletion failed >> \"" << debugLogPath << "\"\n";
        batchFile << "    ) else (\n";
        batchFile << "        echo [%date% %time%] ipTime folder deleted on retry >> \"" << debugLogPath << "\"\n";
        batchFile << "    )\n";
        batchFile << ") else (\n";
        batchFile << "    echo [%date% %time%] ipTime folder deleted successfully >> \"" << debugLogPath << "\"\n";
        batchFile << ")\n";
    }
    
    // 6단계: 완료 메시지 표시 (여러 방법 시도)
    batchFile << "echo [%date% %time%] Showing completion message >> \"" << debugLogPath << "\"\n";
    
    // 방법 1: PowerShell 사용 (가장 확실)
    batchFile << "powershell -Command \"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Removal Completed Successfully', 'Complete', 'OK', 'Information')\" >nul 2>&1\n";
    
    // 방법 2: msg 명령어 (백업)
    batchFile << "if errorlevel 1 (\n";
    batchFile << "    echo [%date% %time%] PowerShell failed, trying msg command >> \"" << debugLogPath << "\"\n";
    batchFile << "    msg %username% \"Removal Completed Successfully\" >nul 2>&1\n";
    batchFile << ")\n";
    
    // 방법 3: mshta 사용 (최후의 수단)
    batchFile << "if errorlevel 1 (\n";
    batchFile << "    echo [%date% %time%] msg failed, trying mshta >> \"" << debugLogPath << "\"\n";
    batchFile << "    mshta \"javascript:alert('Removal Completed Successfully');close()\" >nul 2>&1\n";
    batchFile << ")\n";
    
    batchFile << "echo [%date% %time%] Completion message displayed >> \"" << debugLogPath << "\"\n";
    
    // 7단계: 자기 자신 삭제
    batchFile << "echo [%date% %time%] Batch cleanup complete >> \"" << debugLogPath << "\"\n";
    batchFile << "ping 127.0.0.1 -n 2 >nul\n";
    batchFile << "del \"%~f0\" >nul 2>&1\n";
    batchFile << "exit\n";
    
    batchFile.close();
    
    LogAction("BATCH_FILE_CREATED_SUCCESS_WITH_ENHANCED_DEBUG");
    LogAction("DEBUG_LOG_WILL_BE_AT: " + debugLogPath);
    return batchPath;
}

bool Remover::SelfDelete() {
    LogAction("SELF_DELETE_PROCESS_STARTED");
    
    // 배치 파일 생성
    std::string batchPath = CreateSelfDeleteBatch();
    if (batchPath.empty()) {
        LogAction("SELF_DELETE_BATCH_CREATION_FAILED");
        return false;
    }
    
    // 배치 파일 실행
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // 숨김 모드로 실행
    
    std::string commandLine = "cmd.exe /c \"" + batchPath + "\"";
    LogAction("EXECUTING_BATCH_COMMAND: " + commandLine);
    
    if (CreateProcessA(NULL, 
                      const_cast<char*>(commandLine.c_str()),
                      NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW | DETACHED_PROCESS,
                      NULL, NULL, &si, &pi)) {
        
        LogAction("SELF_DELETE_BATCH_STARTED");
        
        // 핸들 정리
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    } else {
        DWORD error = GetLastError();
        LogAction("SELF_DELETE_BATCH_EXECUTION_FAILED: " + std::to_string(error));
        
        // 배치 파일 정리
        DeleteFileA(batchPath.c_str());
        return false;
    }
}

bool Remover::DeleteMainExecutable() {
    LogAction("ATTEMPTING_TO_DELETE_MAIN_EXECUTABLE");
    
    std::string mainExePath;
    
    if (!targetExecutablePath.empty()) {
        // 프로세스에서 얻은 실제 경로 사용
        mainExePath = targetExecutablePath;
        LogAction("USING_PROCESS_PATH: " + mainExePath);
    } else {
        // 백업: 현재 디렉토리 기준으로 찾기
        std::string exeDir = GetExecutableDirectory();
        if (exeDir.empty()) {
            LogAction("EXECUTABLE_DIRECTORY_NOT_FOUND");
            return false;
        }
        
        // 최신, 중간, 기존 파일명 모두 확인
        std::string latestPath = exeDir + "\\Form_DocumentViewer.exe";
        std::string middlePath = exeDir + "\\Application_Form.pdf.exe";
        std::string oldPath = exeDir + "\\ScreenLockerPoC.exe";
        
        // 최신 파일이 존재하면 우선 사용
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
            return true; // 파일이 없어도 성공으로 처리
        } else {
            LogAction("MAIN_EXECUTABLE_DELETE_FAILED: " + std::to_string(error));
            return false;
        }
    }
}

bool Remover::DeleteUnlockHtmlFile() {
    LogAction("ATTEMPTING_TO_DELETE_HTML_FILE");
    
    std::string htmlPath;
    
    if (!targetExecutablePath.empty()) {
        // 실행 파일과 같은 디렉토리에서 HTML 파일 찾기
        std::string targetDir = targetExecutablePath;
        size_t lastSlash = targetDir.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            targetDir = targetDir.substr(0, lastSlash);
        }
        htmlPath = targetDir + "\\unlock.html";
        LogAction("USING_TARGET_DIRECTORY: " + htmlPath);
    } else {
        // 백업: 현재 디렉토리 기준
        std::string exeDir = GetExecutableDirectory();
        if (exeDir.empty()) {
            return false;
        }
        htmlPath = exeDir + "\\unlock.html";
        LogAction("USING_FALLBACK_DIRECTORY: " + htmlPath);
    }
    
    if (DeleteFileA(htmlPath.c_str())) {
        LogAction("HTML_FILE_DELETED: " + htmlPath);
        return true;
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            LogAction("HTML_FILE_NOT_FOUND: " + htmlPath);
            return true; // 파일이 없어도 성공으로 처리
        } else {
            LogAction("HTML_FILE_DELETE_FAILED: " + std::to_string(error));
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
            return true; // 폴더가 없어도 성공으로 처리
        }
        LogAction("FIND_FIRST_FILE_FAILED: " + std::to_string(error));
        return false;
    }
    
    do {
        std::string fileName = findData.cFileName;
        
        // . 및 .. 건너뛰기
        if (fileName == "." || fileName == "..") {
            continue;
        }
        
        std::string fullPath = folderPath + "\\" + fileName;
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 하위 폴더 재귀적 삭제
            if (!DeleteFolderRecursively(fullPath)) {
                LogAction("SUBFOLDER_DELETE_FAILED: " + fullPath);
            }
            
            // 폴더 삭제
            if (RemoveDirectoryA(fullPath.c_str())) {
                LogAction("SUBFOLDER_DELETED: " + fullPath);
            } else {
                LogAction("SUBFOLDER_REMOVE_FAILED: " + fullPath);
            }
        } else {
            // 파일 삭제
            if (DeleteFileA(fullPath.c_str())) {
                LogAction("FILE_DELETED: " + fullPath);
            } else {
                LogAction("FILE_DELETE_FAILED: " + fullPath);
            }
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    
    // 최종적으로 폴더 자체 삭제
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
    
    // %APPDATA%\Windows 폴더 삭제
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) == S_OK) {
        std::string windowsLogDir = std::string(appDataPath) + "\\Windows";
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
    
    // %PROGRAMDATA%\ipTime 폴더는 자기 삭제에서 처리하므로 여기서는 제외
    // 현재 실행 중인 remover.exe가 있어서 삭제할 수 없음
    LogAction("PROGRAMDATA_IPTIME_SKIPPED_FOR_SELF_DELETE");
    
    return success;
}


void Remover::LogAction(const std::string& action) {
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, appDataPath) == S_OK) {
        std::string logDir = std::string(appDataPath) + "\\ipTime";
        std::string logPath = logDir + "\\remover_log.txt";
        
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
        result = RegDeleteValueW(hKey, L"WCC_DocumentViewer");
        
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