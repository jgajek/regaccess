#include <iostream>
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

void printErrorMessage(DWORD errorCode) {
    LPWSTR errorMsg = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&errorMsg,
        0,
        nullptr
    );
    if (errorMsg) {
        std::wcerr << L"Error: " << errorMsg << std::endl;
        LocalFree(errorMsg);
    } else {
        std::wcerr << L"Unknown error code: " << errorCode << std::endl;
    }
}

void printSecurityDescriptor(HKEY hKey) {
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD dwSDSize = 0;

    // Get the size of the security descriptor
    LONG result = RegGetKeySecurity(hKey, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, pSD, &dwSDSize);

    if (result == ERROR_INSUFFICIENT_BUFFER) {
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSDSize);
        if (pSD == nullptr) {
            std::cerr << "Failed to allocate memory for security descriptor." << std::endl;
            return;
        }

        // Get the security descriptor
        result = RegGetKeySecurity(hKey, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, pSD, &dwSDSize);

        if (result == ERROR_SUCCESS) {
            // Print Owner SID
            PSID pOwnerSID = nullptr;
            BOOL bOwnerDefaulted = FALSE;
            if (GetSecurityDescriptorOwner(pSD, &pOwnerSID, &bOwnerDefaulted)) {
                LPWSTR pOwnerSIDStr = nullptr;
                if (ConvertSidToStringSidW(pOwnerSID, &pOwnerSIDStr)) {
                    std::wcout << L"Owner SID: " << pOwnerSIDStr << std::endl;
                    LocalFree(pOwnerSIDStr);
                }
            }

            // Print Primary Group SID
            PSID pGroupSID = nullptr;
            BOOL bGroupDefaulted = FALSE;
            if (GetSecurityDescriptorGroup(pSD, &pGroupSID, &bGroupDefaulted)) {
                LPWSTR pGroupSIDStr = nullptr;
                if (ConvertSidToStringSidW(pGroupSID, &pGroupSIDStr)) {
                    std::wcout << L"Primary Group SID: " << pGroupSIDStr << std::endl;
                    LocalFree(pGroupSIDStr);
                }
            }

            // Print DACL
            PACL pDACL = nullptr;
            BOOL bDaclPresent = FALSE;
            BOOL bDaclDefaulted = FALSE;
            if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDACL, &bDaclDefaulted)) {
                if (bDaclPresent && pDACL != nullptr) {
                    LPWSTR pDACLStr = nullptr;
                    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pDACLStr, nullptr)) {
                        std::wcout << L"DACL: " << pDACLStr << std::endl;
                        LocalFree(pDACLStr);
                    }
                }
            }

            // Print SACL
            PACL pSACL = nullptr;
            BOOL bSaclPresent = FALSE;
            BOOL bSaclDefaulted = FALSE;
            if (GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSACL, &bSaclDefaulted)) {
                if (bSaclPresent && pSACL != nullptr) {
                    LPWSTR pSACLStr = nullptr;
                    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, SACL_SECURITY_INFORMATION, &pSACLStr, nullptr)) {
                        std::wcout << L"SACL: " << pSACLStr << std::endl;
                        LocalFree(pSACLStr);
                    }
                }
            }

            // Print Security Descriptor Control Bits
            SECURITY_DESCRIPTOR_CONTROL sdc;
            DWORD dwRevision;
            if (GetSecurityDescriptorControl(pSD, &sdc, &dwRevision)) {
                std::wcout << L"Security Descriptor Control Bits: " << std::endl;
                if (sdc & SE_OWNER_DEFAULTED) std::wcout << L"  - SE_OWNER_DEFAULTED" << std::endl;
                if (sdc & SE_GROUP_DEFAULTED) std::wcout << L"  - SE_GROUP_DEFAULTED" << std::endl;
                if (sdc & SE_DACL_PRESENT) std::wcout << L"  - SE_DACL_PRESENT" << std::endl;
                if (sdc & SE_DACL_DEFAULTED) std::wcout << L"  - SE_DACL_DEFAULTED" << std::endl;
                if (sdc & SE_SACL_PRESENT) std::wcout << L"  - SE_SACL_PRESENT" << std::endl;
                if (sdc & SE_SACL_DEFAULTED) std::wcout << L"  - SE_SACL_DEFAULTED" << std::endl;
                if (sdc & 0x40) std::wcout << L"  - SE_DACL_UNTRUSTED" << std::endl;
                if (sdc & 0x80) std::wcout << L"  - SE_SERVER_SECURITY" << std::endl;
                if (sdc & SE_DACL_AUTO_INHERIT_REQ) std::wcout << L"  - SE_DACL_AUTO_INHERIT_REQ" << std::endl;
                if (sdc & SE_SACL_AUTO_INHERIT_REQ) std::wcout << L"  - SE_SACL_AUTO_INHERIT_REQ" << std::endl;
                if (sdc & SE_DACL_AUTO_INHERITED) std::wcout << L"  - SE_DACL_AUTO_INHERITED" << std::endl;
                if (sdc & SE_SACL_AUTO_INHERITED) std::wcout << L"  - SE_SACL_AUTO_INHERITED" << std::endl;
                if (sdc & SE_DACL_PROTECTED) std::wcout << L"  - SE_DACL_PROTECTED" << std::endl;
                if (sdc & SE_SACL_PROTECTED) std::wcout << L"  - SE_SACL_PROTECTED" << std::endl;
                if (sdc & SE_RM_CONTROL_VALID) std::wcout << L"  - SE_RM_CONTROL_VALID" << std::endl;
                if (sdc & SE_SELF_RELATIVE) std::wcout << L"  - SE_SELF_RELATIVE" << std::endl;
            }
        }
        else {
            std::cerr << "Failed to get security descriptor. ";
            printErrorMessage(result);
        }

        LocalFree(pSD);
    }
    else {
        std::cerr << "Failed to get security descriptor size. ";
        printErrorMessage(result);
    }
}

bool CopySecurityDescriptor(HKEY hSourceKey, HKEY hDestKey) {
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD dwSDSize = 0;

    // Get the size of the security descriptor
    LONG result = RegGetKeySecurity(hSourceKey, BACKUP_SECURITY_INFORMATION, pSD, &dwSDSize);

    if (result == ERROR_INSUFFICIENT_BUFFER) {
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSDSize);
        if (pSD == nullptr) {
            std::cerr << "Failed to allocate memory for security descriptor." << std::endl;
            return false;
        }

        // Get the security descriptor
        result = RegGetKeySecurity(hSourceKey, BACKUP_SECURITY_INFORMATION, pSD, &dwSDSize);

        if (result == ERROR_SUCCESS) {
            // Set the security descriptor to the destination key
            result = RegSetKeySecurity(hDestKey, BACKUP_SECURITY_INFORMATION, pSD);
            if (result != ERROR_SUCCESS) {
                std::cerr << "Failed to set security descriptor. ";
                printErrorMessage(result);
                LocalFree(pSD);
                return false;
            }
        }
        else {
            std::cerr << "Failed to get security descriptor. ";
            printErrorMessage(result);
            LocalFree(pSD);
            return false;
        }

        LocalFree(pSD);
    }
    else {
        std::cerr << "Failed to get security descriptor size. ";
        printErrorMessage(result);
        return false;
    }

    return true;
}

bool EnablePrivilege(LPCWSTR privilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken error: ";
        printErrorMessage(GetLastError());
        return false;
    }

    if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
        std::cerr << "LookupPrivilegeValue error: ";
        printErrorMessage(GetLastError());
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges error: ";
        printErrorMessage(GetLastError());
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

HKEY openRegistryKey(const std::wstring& keyPath, REGSAM samDesired) {
    HKEY hRootKey = nullptr;
    std::wstring subKey;

    if (keyPath.find(L"HKEY_LOCAL_MACHINE") == 0) {
        hRootKey = HKEY_LOCAL_MACHINE;
        subKey = keyPath.substr(19); // Length of "HKEY_LOCAL_MACHINE\"
    }
    else if (keyPath.find(L"HKEY_CURRENT_USER") == 0) {
        hRootKey = HKEY_CURRENT_USER;
        subKey = keyPath.substr(18); // Length of "HKEY_CURRENT_USER\"
    }
    else if (keyPath.find(L"HKEY_CLASSES_ROOT") == 0) {
        hRootKey = HKEY_CLASSES_ROOT;
        subKey = keyPath.substr(18);
    }
    else if (keyPath.find(L"HKEY_USERS") == 0) {
        hRootKey = HKEY_USERS;
        subKey = keyPath.substr(11);
    }
    else if (keyPath.find(L"HKEY_CURRENT_CONFIG") == 0) {
        hRootKey = HKEY_CURRENT_CONFIG;
        subKey = keyPath.substr(20);
    }
    else {
        std::wcerr << "Invalid registry key path: " << keyPath << std::endl;
        return nullptr;
    }

    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, samDesired, &hKey);
    if (result != ERROR_SUCCESS) {
        std::wcerr << "Failed to open registry key: " << keyPath << ". ";
        printErrorMessage(result);
        return nullptr;
    }

    return hKey;
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <source_registry_key_path> [<dest_registry_key_path>]" << std::endl;
        std::cerr << "Example: " << argv[0] << " HKEY_LOCAL_MACHINE\\SOFTWARE\\MyKey" << std::endl;
        std::cerr << "Example: " << argv[0] << " HKEY_LOCAL_MACHINE\\SOFTWARE\\SourceKey HKEY_LOCAL_MACHINE\\SOFTWARE\\DestKey" << std::endl;
        return 1;
    }

    if (!EnablePrivilege(SE_RESTORE_NAME)) {
        std::cerr << "Failed to enable SeBackupPrivilege." << std::endl;
        return 1;
    }

    if (!EnablePrivilege(SE_SECURITY_NAME)) {
        std::cerr << "Failed to enable SeSecurityPrivilege." << std::endl;
        return 1;
    }

    std::wstring sourceKeyPath = std::wstring(argv[1], argv[1] + strlen(argv[1]));
    HKEY hSourceKey = openRegistryKey(sourceKeyPath, KEY_READ | READ_CONTROL | ACCESS_SYSTEM_SECURITY);
    if (hSourceKey == nullptr) {
        return 1;
    }

    if (argc == 2) {
        // Print the security descriptor of the source key
        printSecurityDescriptor(hSourceKey);
        RegCloseKey(hSourceKey);
    }
    else if (argc == 3) {
        std::wstring destKeyPath = std::wstring(argv[2], argv[2] + strlen(argv[2]));
        HKEY hDestKey = openRegistryKey(destKeyPath, KEY_WRITE | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
        if (hDestKey == nullptr) {
            RegCloseKey(hSourceKey);
            return 1;
        }

        // Copy the security descriptor from the source key to the destination key
        if (!CopySecurityDescriptor(hSourceKey, hDestKey)) {
            std::cerr << "Failed to copy security descriptor." << std::endl;
            RegCloseKey(hSourceKey);
            RegCloseKey(hDestKey);
            return 1;
        }

        RegCloseKey(hSourceKey);
        RegCloseKey(hDestKey);
        std::wcout << L"Security descriptor copied successfully." << std::endl;
    }

    return 0;
}
