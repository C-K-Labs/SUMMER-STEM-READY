#pragma once

#include <windows.h>

namespace Constants {
    // --- Registry ---
    constexpr wchar_t RegistryKeyName[] = L"WCC_DocumentViewer";

    // --- File & Folder Names ---
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

    // --- USB Emergency Remover ---
    constexpr char UsbRemoverExeName[] = "usb_remover.exe";
    constexpr char UsbUnlockKeyFile[] = "_unlock.key";
    
    // Native Dialog Control IDs
    constexpr int DIALOG_TITLE_ID = 1001;
    constexpr int DIALOG_SUBTITLE_ID = 1002;
    constexpr int DIALOG_INFO_ID = 1003;
    constexpr int DIALOG_USERID_LABEL_ID = 1004;
    constexpr int DIALOG_USERID_INPUT_ID = 1005;
    constexpr int DIALOG_CONFIRM_BTN_ID = 1006;
}