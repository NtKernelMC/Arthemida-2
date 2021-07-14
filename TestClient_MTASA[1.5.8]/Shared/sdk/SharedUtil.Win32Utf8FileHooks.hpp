/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        SharedUtil.Win32Utf8FileHooks.hpp
 *  PURPOSE:     Hooks for making Windows file functions use UTF8 strings
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include <shlobj.h>
#include "detours/include/detours.h"

/*
The hooks in this file modify the following functions to work correctly with utf8 strings:

    CreateFile
    LoadLibrary
    LoadLibraryEx
    SetDllDirectory
    SetCurrentDirectory
    AddFontResourceEx
    RemoveFontResourceEx
    RemoveDirectory
    GetDiskFreeSpaceEx
    GetFileAttributes
    SetFileAttributes
    ShellExecute
    CreateDirectory
    CopyFile
    MoveFile
    DeleteFile
    GetModuleHandle

Some more will also work correctly with utf8 strings as they eventually call the above hooked functions

BUT
    * Many other functions are not hooked and will need utf8 conversions when used, like these:
        FindFirstFile
        GetModuleFileName
        GetModuleFileNameEx
        GetCurrentDirectory
        GetDllDirectory
        getcwd
            and many more...
*/

namespace SharedUtil
{
    /////////////////////////////////////////////////////////////
    //
    // Hook variables
    //
    /////////////////////////////////////////////////////////////
    #define HOOKVAR(name) \
        using FUNC_##name = decltype(&name); \
        FUNC_##name pfn##name;

    HOOKVAR(CreateFileA)
    HOOKVAR(LoadLibraryA)
    HOOKVAR(LoadLibraryExA)
    HOOKVAR(SetDllDirectoryA)
    HOOKVAR(SetCurrentDirectoryA)
    HOOKVAR(AddFontResourceExA)
    HOOKVAR(RemoveFontResourceExA)
    HOOKVAR(RemoveDirectoryA)
    HOOKVAR(GetDiskFreeSpaceExA)
    HOOKVAR(GetFileAttributesA)
    HOOKVAR(SetFileAttributesA)
    HOOKVAR(ShellExecuteA)
    HOOKVAR(CreateDirectoryA)
    HOOKVAR(CopyFileA)
    HOOKVAR(MoveFileA)
    HOOKVAR(DeleteFileA)
    HOOKVAR(GetModuleHandleA)

#ifdef MTA_CLIENT
    /////////////////////////////////////////////////////////////
    //
    // Ensure codepage type characters have been utf8ified
    //
    /////////////////////////////////////////////////////////////
    SString MakeSurePathIsUTF8(const SString& strOriginal)
    {
        static SString strLaunchPathCP, strLaunchPathUTF8;
        if (strLaunchPathCP.empty())
        {
            char szLaunchPath[2048];
            GetModuleFileNameA(NULL, szLaunchPath, NUMELMS(szLaunchPath) - 1);
            strLaunchPathCP = ExtractPath(szLaunchPath);
            strLaunchPathUTF8 = GetLaunchPath();
        }
        if (strOriginal.BeginsWithI(strLaunchPathCP))
        {
            // Fix gta install path
            SString strPathTail = strOriginal.SubStr(strLaunchPathCP.length());
            SString strNewPathName = PathJoin(strLaunchPathUTF8, strPathTail);
            return strNewPathName;
        }

        static SString strProfilePathCP, strProfilePathUTF8;
        if (strProfilePathCP.empty())
        {
            char    szProfilePath[MAX_PATH] = "";
            wchar_t wszProfilePath[MAX_PATH] = L"";
            SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, szProfilePath);
            SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, wszProfilePath);
            strProfilePathCP = szProfilePath;
            strProfilePathUTF8 = ToUTF8(wszProfilePath);
        }
        if (strOriginal.BeginsWithI(strProfilePathCP))
        {
            // Fix username path
            SString strPathTail = strOriginal.SubStr(strProfilePathCP.length());
            SString strNewPathName = PathJoin(strProfilePathUTF8, strPathTail);
            return strNewPathName;
        }
        return strOriginal;
    }
#endif

    /////////////////////////////////////////////////////////////
    //
    // Hook implementations
    //
    /////////////////////////////////////////////////////////////
    HANDLE
    WINAPI
    MyCreateFileA(__in LPCSTR lpFileName, __in DWORD dwDesiredAccess, __in DWORD dwShareMode, __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                  __in DWORD dwCreationDisposition, __in DWORD dwFlagsAndAttributes, __in_opt HANDLE hTemplateFile)
    {
        SString strFileName = lpFileName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strFileName = MakeSurePathIsUTF8(strFileName);
#endif
        return CreateFileW(FromUTF8(strFileName), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                           hTemplateFile);
    }

    HMODULE
    WINAPI
    MyLoadLibraryA(__in LPCSTR lpLibFileName) { return LoadLibraryW(FromUTF8(lpLibFileName)); }

    HMODULE
    WINAPI
    MyLoadLibraryExA(__in LPCSTR lpLibFileName, __reserved HANDLE hFile, __in DWORD dwFlags) { return LoadLibraryExW(FromUTF8(lpLibFileName), hFile, dwFlags); }

    BOOL WINAPI MySetDllDirectoryA(__in_opt LPCSTR lpPathName) { return SetDllDirectoryW(FromUTF8(lpPathName)); }

    BOOL WINAPI MySetCurrentDirectoryA(__in LPCSTR lpPathName)
    {
        SString strPathName = lpPathName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strPathName = MakeSurePathIsUTF8(strPathName);
#endif
        return SetCurrentDirectoryW(FromUTF8(strPathName));
    }

    int WINAPI MyAddFontResourceExA(__in LPCSTR name, __in DWORD fl, __reserved PVOID res) { return AddFontResourceExW(FromUTF8(name), fl, res); }

    BOOL WINAPI MyRemoveFontResourceExA(__in LPCSTR name, __in DWORD fl, __reserved PVOID pdv) { return RemoveFontResourceExW(FromUTF8(name), fl, pdv); }

    BOOL WINAPI MyRemoveDirectoryA(__in LPCSTR lpPathName)
    {
        SString strPathName = lpPathName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strPathName = MakeSurePathIsUTF8(lpPathName);
#endif
        return RemoveDirectoryW(FromUTF8(strPathName));
    }

    BOOL WINAPI MyGetDiskFreeSpaceExA(__in_opt LPCSTR lpDirectoryName, __out_opt PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                                      __out_opt PULARGE_INTEGER lpTotalNumberOfBytes, __out_opt PULARGE_INTEGER lpTotalNumberOfFreeBytes)
    {
        return GetDiskFreeSpaceExW(FromUTF8(lpDirectoryName), lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
    }

    DWORD
    WINAPI
    MyGetFileAttributesA(__in LPCSTR lpFileName)
    {
        SString strFileName = lpFileName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strFileName = MakeSurePathIsUTF8(strFileName);
#endif
        return GetFileAttributesW(FromUTF8(strFileName));
    }

    BOOL WINAPI MySetFileAttributesA(__in LPCSTR lpFileName, __in DWORD dwFileAttributes)
    {
        SString strFileName = lpFileName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strFileName = MakeSurePathIsUTF8(strFileName);
#endif
        return SetFileAttributesW(FromUTF8(strFileName), dwFileAttributes);
    }

    HINSTANCE STDAPICALLTYPE MyShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)
    {
        return ShellExecuteW(hwnd, FromUTF8(lpOperation), FromUTF8(lpFile), FromUTF8(lpParameters), FromUTF8(lpDirectory), nShowCmd);
    }

    BOOL WINAPI MyCreateDirectoryA(__in LPCSTR lpPathName, __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes)
    {
        SString strPathName = lpPathName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strPathName = MakeSurePathIsUTF8(strPathName);
#endif
        return CreateDirectoryW(FromUTF8(strPathName), lpSecurityAttributes);
    }

    BOOL WINAPI MyCopyFileA(__in LPCSTR lpExistingFileName, __in LPCSTR lpNewFileName, __in BOOL bFailIfExists)
    {
        return CopyFileW(FromUTF8(lpExistingFileName), FromUTF8(lpNewFileName), bFailIfExists);
    }

    BOOL WINAPI MyMoveFileA(__in LPCSTR lpExistingFileName, __in LPCSTR lpNewFileName)
    {
        return MoveFileW(FromUTF8(lpExistingFileName), FromUTF8(lpNewFileName));
    }

    BOOL WINAPI MyDeleteFileA(__in LPCSTR lpFileName)
    {
        SString strFileName = lpFileName;
#ifdef MTA_CLIENT
        if (IsGTAProcess())
            strFileName = MakeSurePathIsUTF8(strFileName);
#endif
        return DeleteFileW(FromUTF8(strFileName));
    }

    HMODULE
    WINAPI
    MyGetModuleHandleA(__in_opt LPCSTR lpModuleName)
    {
        if (!lpModuleName)
            return GetModuleHandleW(NULL);
        return GetModuleHandleW(FromUTF8(lpModuleName));
    }

    /////////////////////////////////////////////////////////////
    //
    // Hook adding
    //
    /////////////////////////////////////////////////////////////
    void AddUtf8FileHooks()
    {
        #define ADDHOOK(module,name) \
                pfn##name = reinterpret_cast < FUNC_##name > ( DetourFunction ( DetourFindFunction ( module, #name ), reinterpret_cast < PBYTE > ( My##name ) ) ); \
                assert( pfn##name );

        ADDHOOK("Kernel32.dll", CreateFileA)
        ADDHOOK("Kernel32.dll", LoadLibraryA)
        ADDHOOK("Kernel32.dll", LoadLibraryExA)
        ADDHOOK("Kernel32.dll", SetDllDirectoryA)
        ADDHOOK("Kernel32.dll", SetCurrentDirectoryA)
        ADDHOOK("Gdi32.dll", AddFontResourceExA)
        ADDHOOK("Gdi32.dll", RemoveFontResourceExA)
        ADDHOOK("Kernel32.dll", RemoveDirectoryA)
        ADDHOOK("Kernel32.dll", GetDiskFreeSpaceExA)
        ADDHOOK("Kernel32.dll", GetFileAttributesA)
        ADDHOOK("Kernel32.dll", SetFileAttributesA)
        ADDHOOK("Shell32.dll", ShellExecuteA)
        ADDHOOK("Kernel32.dll", CreateDirectoryA)
        ADDHOOK("Kernel32.dll", CopyFileA)
        ADDHOOK("Kernel32.dll", MoveFileA)
        ADDHOOK("Kernel32.dll", DeleteFileA)
        ADDHOOK("Kernel32.dll", GetModuleHandleA)
    }

    /////////////////////////////////////////////////////////////
    //
    // Hook taking away
    //
    /////////////////////////////////////////////////////////////
    void RemoveUtf8FileHooks()
    {
        #define DELHOOK(name) \
            if ( pfn##name ) \
            { \
                DetourRemove ( reinterpret_cast < PBYTE > ( pfn##name ),  \
                               reinterpret_cast < PBYTE > ( My##name  ) ); \
                pfn##name = NULL; \
            }

        DELHOOK(CreateFileA)
        DELHOOK(LoadLibraryA)
        DELHOOK(LoadLibraryExA)
        DELHOOK(SetDllDirectoryA)
        DELHOOK(SetCurrentDirectoryA)
        DELHOOK(AddFontResourceExA)
        DELHOOK(RemoveFontResourceExA)
        DELHOOK(RemoveDirectoryA)
        DELHOOK(GetDiskFreeSpaceExA)
        DELHOOK(GetFileAttributesA)
        DELHOOK(SetFileAttributesA)
        DELHOOK(ShellExecuteA)
        DELHOOK(CreateDirectoryA)
        DELHOOK(CopyFileA)
        DELHOOK(MoveFileA)
        DELHOOK(DeleteFileA)
        DELHOOK(GetModuleHandleA)
    }
}            // namespace SharedUtil
