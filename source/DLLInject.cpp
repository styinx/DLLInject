#include "DLLInject.hpp"

#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"

#include <tlhelp32.h>

static const char* LOGGER_NAME = "log_dll_inject";

DLLInject::DLLInject(
    const String&& process_name,
    const String&& dll_name,
    const Uint32   poll_interval,
    const uint32   timeout)
    : m_process_name(process_name)
    , m_dll_name(dll_name)
    , m_poll_interval(poll_interval)
    , m_timeout(timeout)
{
    auto logger = spdlog::basic_logger_mt(LOGGER_NAME, "dll_inject.log", true);
    spdlog::set_level(spdlog::level::info);

    logger->debug("[+] Start Injector");
}

DLLInject::~DLLInject()
{
    if(m_info.process_handle)
        CloseHandle(m_info.process_handle);

    spdlog::get(LOGGER_NAME)->debug("[+] Stop Injector");
}

// Public

bool DLLInject::run()
{
    bool success = false;

    auto logger = spdlog::get(LOGGER_NAME);

    logger->debug(" +  Run Injector");
    if(findPID())
        if(openProcess())
            if(allocateDLLSpace())
                if(injectDLL())
                    success = startRemoteThread();

    logger->debug(" +  Finished Injector");

    return success;
}

ProcessInfo DLLInject::getProcessInfo() const
{
    return m_info;
}

// Private

bool DLLInject::findPID()
{
    auto logger = spdlog::get(LOGGER_NAME);

    logger->debug(" +  Find PID");
    Uint32 timer = 0;
    while(m_info.process_id == 0)
    {
        if(m_timeout > 0 && timer > m_timeout)
        {
            logger->debug(" +> Stopped with timeout");
            break;
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if(hSnap == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 procEntry{};
        procEntry.dwSize = sizeof(PROCESSENTRY32);

        if(Process32First(hSnap, &procEntry))
        {
            do
            {
                String process = procEntry.szExeFile;
                if(process == m_process_name)
                {
                    m_info.process_id = procEntry.th32ProcessID;
                    break;
                }
            } while(Process32Next(hSnap, &procEntry));
        }

        CloseHandle(hSnap);
        Sleep(m_poll_interval);
        timer += m_poll_interval;
    }

    bool success = m_info.process_id != 0;

    if(success)
        logger->debug(" +> PID: {}", m_info.process_id);

    return success;
}

bool DLLInject::openProcess()
{
    spdlog::get(LOGGER_NAME)->debug(" +  Open Process");

    m_info.process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_info.process_id);

    return m_info.process_handle != nullptr;
}

bool DLLInject::allocateDLLSpace()
{
    spdlog::get(LOGGER_NAME)->debug(" +  Allocating Memory");

    m_info.dll_address = VirtualAllocEx(
        m_info.process_handle,
        nullptr,
        m_dll_name.size() + 1,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if(m_info.dll_address == nullptr)
        return false;

    return true;
}

bool DLLInject::injectDLL()
{
    spdlog::get(LOGGER_NAME)->debug(" +  Writing DLL Address");

    return WriteProcessMemory(
               m_info.process_handle,
               m_info.dll_address,
               m_dll_name.data(),
               m_dll_name.size() + 1,
               nullptr) == TRUE;
}

bool DLLInject::startRemoteThread()
{
    spdlog::get(LOGGER_NAME)->debug(" +  Start Remote Thread with '{}'", m_dll_name.c_str());

    HANDLE remote_thread = CreateRemoteThread(
        m_info.process_handle,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        m_info.dll_address,
        0,
        nullptr);

    bool success = remote_thread != nullptr && remote_thread != INVALID_HANDLE_VALUE;

    if(success)
        CloseHandle(remote_thread);

    return success;
}
