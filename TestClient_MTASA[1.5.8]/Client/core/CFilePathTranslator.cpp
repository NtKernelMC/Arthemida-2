/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        core/CFilePathTranslator.cpp
 *  PURPOSE:     Easy interface to file paths
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"

using std::string;

CFilePathTranslator::CFilePathTranslator()
{
}

CFilePathTranslator::~CFilePathTranslator()
{
}

bool CFilePathTranslator::GetFileFromModPath(const string& FileToGet, string& TranslatedFilePathOut)
{
    // Translate the path to this file.
    TranslatedFilePathOut = m_ModPath;
    TranslatedFilePathOut += '\\';
    TranslatedFilePathOut += FileToGet;

    return true;
}

bool CFilePathTranslator::GetFileFromWorkingDirectory(const string& FileToGet, string& TranslatedFilePathOut)
{
    // Translate the path to this file.
    TranslatedFilePathOut = m_WorkingDirectory;
    TranslatedFilePathOut += '\\';
    TranslatedFilePathOut += FileToGet;

    return true;
}

void CFilePathTranslator::GetModPath(string& ModPathOut)
{
    ModPathOut = m_ModPath;
}

void CFilePathTranslator::SetModPath(const string& PathBasedOffWorkingDirectory)
{
    m_ModPath = m_WorkingDirectory;
    m_ModPath += '\\';
    m_ModPath += PathBasedOffWorkingDirectory;
}

void CFilePathTranslator::SetCurrentWorkingDirectory(const string& PathBasedOffModuleRoot)
{
    string RootDirectory;

    // Get the root directory.
    GetMTASARootDirectory(RootDirectory);

    // Store it
    m_WorkingDirectory = RootDirectory;
    m_WorkingDirectory += '\\';
    m_WorkingDirectory += PathBasedOffModuleRoot;
}

void CFilePathTranslator::UnSetCurrentWorkingDirectory()
{
    m_WorkingDirectory = "";
}

void CFilePathTranslator::GetCurrentWorkingDirectory(string& WorkingDirectoryOut)
{
    WorkingDirectoryOut = m_WorkingDirectory;
}

void CFilePathTranslator::GetGTARootDirectory(string& ModuleRootDirOut)
{
    ModuleRootDirOut = GetLaunchPath();
}

void CFilePathTranslator::GetMTASARootDirectory(string& InstallRootDirOut)
{
    InstallRootDirOut = GetMTASABaseDir();
}
