#include "DLLInject.hpp"

#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"

#include <tlhelp32.h>

DLLInject::DLLInject(
    const std::string&& process_name,
    const std::string&& dll_name,
    const std::uint32_t poll_interval,
    const std::uint32_t timeout)
    : m_process_handle(nullptr)
    , m_process_id(0)
    , m_process_name(process_name)
    , m_dll_name(dll_name)
    , m_dll_address(nullptr)
    , m_poll_interval(poll_interval)
    , m_timeout(timeout)
{
    auto logger = spdlog::basic_logger_mt("log_dll_inject", "DLLInject.log", true);
    spdlog::set_level(spdlog::level::info);

    logger->debug("Start Injector");
}

DLLInject::~DLLInject()
{
    if(m_process_handle)
        CloseHandle(m_process_handle);

    spdlog::get("log_dll_inject")->debug("Stop Injector");
}

void DLLInject::run()
{
    auto logger = spdlog::get("log_dll_inject");

    logger->debug("Run Injector");
    if(findPID())
        if(openProcess())
            if(allocate())
                startRemoteThread();

    logger->debug("Finished Injector");
}

bool DLLInject::findPID()
{
    auto logger = spdlog::get("log_dll_inject");

    logger->debug(" - Get PID");
    std::uint32_t timer = 0;
    while(m_process_id == 0)
    {
        if(m_timeout > 0 && timer > m_timeout)
        {
            logger->debug(" -> Stopped with timeout");
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
                std::string process = procEntry.szExeFile;
                if(process == m_process_name)
                {
                    m_process_id = procEntry.th32ProcessID;
                    break;
                }
            } while(Process32Next(hSnap, &procEntry));
        }

        CloseHandle(hSnap);
        Sleep(m_poll_interval);
        timer += m_poll_interval;
    }

    bool success = m_process_id != 0;

    if(success)
        logger->debug(" -> PID: {}", m_process_id);

    return success;
}

bool DLLInject::openProcess()
{
    spdlog::get("log_dll_inject")->debug(" - Open Process");
    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_process_id);
    return m_process_handle != nullptr;
}

bool DLLInject::allocate()
{
    auto logger = spdlog::get("log_dll_inject");

    logger->debug(" - Allocating Memory");
    m_dll_address = VirtualAllocEx(
        m_process_handle,
        nullptr,
        m_dll_name.size() + 1,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if(m_dll_address == nullptr)
        return false;

    logger->debug(" - Writing DLL Address");
    return WriteProcessMemory(
               m_process_handle,
               m_dll_address,
               m_dll_name.data(),
               m_dll_name.size() + 1,
               nullptr) == TRUE;
}

bool DLLInject::startRemoteThread()
{
    spdlog::get("log_dll_inject")->debug(" - Start Remote Thread with '{}'", m_dll_name.c_str());

    HANDLE remote_thread = CreateRemoteThread(
        m_process_handle,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        m_dll_address,
        0,
        nullptr);

    bool success = remote_thread != nullptr && remote_thread != INVALID_HANDLE_VALUE;

    if(success)
        CloseHandle(remote_thread);

    return success;
}
