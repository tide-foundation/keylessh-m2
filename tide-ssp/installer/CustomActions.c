/*
 * WiX Custom Actions for TideSSP installer.
 *
 * Handles appending/removing "TideSSP" from the REG_MULTI_SZ
 * SecurityPackages value under HKLM\SYSTEM\CurrentControlSet\Control\Lsa,
 * and cleaning up UF_MNS_LOGON_ACCOUNT flags on uninstall.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <lm.h>
#include <strsafe.h>

#pragma comment(lib, "msi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

#define LSA_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define MSV1_0_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"
#define PACKAGE_NAME L"TideSSP"
#define SUBAUTH_NAME L"TideSubAuth"

/* ---------- helpers ---------- */

/* Return total byte size of a REG_MULTI_SZ buffer (including double-null). */
static DWORD MultiSzSize(const WCHAR *msz)
{
    const WCHAR *p = msz;
    while (*p)
        p += wcslen(p) + 1;
    return (DWORD)((p - msz + 1) * sizeof(WCHAR));
}

/* Check if a string exists in a REG_MULTI_SZ. */
static BOOL MultiSzContains(const WCHAR *msz, const WCHAR *target)
{
    const WCHAR *p = msz;
    while (*p) {
        if (_wcsicmp(p, target) == 0)
            return TRUE;
        p += wcslen(p) + 1;
    }
    return FALSE;
}

/* ---------- install actions ---------- */

UINT __stdcall RegisterSecurityPackage(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;
    DWORD cbData = 0;
    WCHAR *msz = NULL;
    UINT ret = ERROR_SUCCESS;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
                      KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    /* Read current SecurityPackages */
    DWORD type = 0;
    RegQueryValueExW(hKey, L"SecurityPackages", NULL, &type, NULL, &cbData);
    if (cbData == 0)
        cbData = 2; /* empty multi-sz: just double-null */

    /* Allocate enough for existing + new entry */
    DWORD extraBytes = (DWORD)((wcslen(PACKAGE_NAME) + 1) * sizeof(WCHAR));
    msz = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData + extraBytes);
    if (!msz) { ret = ERROR_INSTALL_FAILURE; goto done; }

    RegQueryValueExW(hKey, L"SecurityPackages", NULL, NULL, (BYTE *)msz, &cbData);

    if (!MultiSzContains(msz, PACKAGE_NAME)) {
        /* Append: find the double-null terminator and insert before it */
        WCHAR *end = msz;
        while (*end)
            end += wcslen(end) + 1;
        /* end now points to the final '\0' of the double-null */
        StringCchCopyW(end, wcslen(PACKAGE_NAME) + 1, PACKAGE_NAME);
        DWORD newSize = MultiSzSize(msz);
        RegSetValueExW(hKey, L"SecurityPackages", 0, REG_MULTI_SZ,
                       (BYTE *)msz, newSize);
    }

done:
    if (msz) HeapFree(GetProcessHeap(), 0, msz);
    if (hKey) RegCloseKey(hKey);
    return ret;
}

UINT __stdcall RegisterSubAuth(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;
    DWORD disp = 0;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MSV1_0_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                        &hKey, &disp) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    RegSetValueExW(hKey, L"Auth0", 0, REG_SZ,
                   (BYTE *)SUBAUTH_NAME, (DWORD)((wcslen(SUBAUTH_NAME) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);
    return ERROR_SUCCESS;
}

/* ---------- uninstall actions ---------- */

UINT __stdcall UnregisterSecurityPackage(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;
    DWORD cbData = 0;
    WCHAR *msz = NULL, *out = NULL;
    UINT ret = ERROR_SUCCESS;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
                      KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return ERROR_SUCCESS; /* nothing to undo */

    DWORD type = 0;
    RegQueryValueExW(hKey, L"SecurityPackages", NULL, &type, NULL, &cbData);
    if (cbData == 0) goto done;

    msz = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData);
    out = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData);
    if (!msz || !out) goto done;

    RegQueryValueExW(hKey, L"SecurityPackages", NULL, NULL, (BYTE *)msz, &cbData);

    /* Rebuild without TideSSP */
    WCHAR *src = msz;
    WCHAR *dst = out;
    while (*src) {
        DWORD len = (DWORD)wcslen(src);
        if (_wcsicmp(src, PACKAGE_NAME) != 0) {
            StringCchCopyW(dst, len + 1, src);
            dst += len + 1;
        }
        src += len + 1;
    }
    *dst = L'\0'; /* double-null terminate */

    DWORD newSize = MultiSzSize(out);
    RegSetValueExW(hKey, L"SecurityPackages", 0, REG_MULTI_SZ,
                   (BYTE *)out, newSize);

done:
    if (msz) HeapFree(GetProcessHeap(), 0, msz);
    if (out) HeapFree(GetProcessHeap(), 0, out);
    if (hKey) RegCloseKey(hKey);
    return ret;
}

UINT __stdcall UnregisterSubAuth(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MSV1_0_KEY, 0,
                      KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Auth0");
        RegCloseKey(hKey);
    }
    return ERROR_SUCCESS;
}

UINT __stdcall ClearMnsFlags(MSIHANDLE hInstall)
{
    (void)hInstall;
    /* Clear UF_MNS_LOGON_ACCOUNT (0x20000) from all local users */
    LPUSER_INFO_1 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;

    if (NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT,
                    (LPBYTE *)&pBuf, MAX_PREFERRED_LENGTH,
                    &entriesRead, &totalEntries, NULL) == NERR_Success && pBuf) {
        for (DWORD i = 0; i < entriesRead; i++) {
            if (pBuf[i].usri1_flags & UF_MNS_LOGON_ACCOUNT) {
                USER_INFO_1008 flagInfo;
                flagInfo.usri1008_flags = pBuf[i].usri1_flags & ~UF_MNS_LOGON_ACCOUNT;
                NetUserSetInfo(NULL, pBuf[i].usri1_name, 1008,
                              (LPBYTE)&flagInfo, NULL);
            }
        }
        NetApiBufferFree(pBuf);
    }
    return ERROR_SUCCESS;
}
