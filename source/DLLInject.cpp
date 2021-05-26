#include "DLLInject.hpp"

#include "tlhelp32.h"

DLLInject::DLLInject(const std::string&& process_name, const std::string&& dll_name, const std::uint32_t poll_interval)
    : m_process_handle(nullptr)
    , m_process_pid(0)
    , m_process_name(process_name)
    , m_dll_name(dll_name)
    , m_dll_address(nullptr)
    , m_poll_interval(poll_interval)
{
}

void DLLInject::run()
{
    getPID();
    openProcess();
    allocate();
    startRemoteThread();
}

void DLLInject::getPID()
{
    while(m_process_pid == 0)
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if(hSnap == INVALID_HANDLE_VALUE)
            return;

        PROCESSENTRY32 procEntry{};
        procEntry.dwSize = sizeof(PROCESSENTRY32);

        if(Process32First(hSnap, &procEntry))
        {
            do
            {
                std::string process = procEntry.szExeFile;
                if(process == m_process_name)
                {
                    m_process_pid = procEntry.th32ProcessID;
                    break;
                }
            } while(Process32Next(hSnap, &procEntry));
        }

        CloseHandle(hSnap);
        Sleep(m_poll_interval);
    }
}

void DLLInject::openProcess()
{
    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_process_pid);
}

void DLLInject::allocate()
{
    m_dll_address = VirtualAllocEx(
        m_process_handle,
        nullptr,
        m_dll_name.size() + 1,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if(m_dll_address == nullptr)
        return;

    WriteProcessMemory(m_process_handle, m_dll_address, m_dll_name.data(), m_dll_name.size() + 1, nullptr);
}

void DLLInject::startRemoteThread()
{
    HANDLE remote_thread = CreateRemoteThread(
        m_process_handle,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        m_dll_address,
        0,
        nullptr);

    if(remote_thread != nullptr && remote_thread != INVALID_HANDLE_VALUE)
        CloseHandle(remote_thread);
}
