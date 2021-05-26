#ifndef DLLINJECT_HPP
#define DLLINJECT_HPP

#include <cstdint>
#include <string>
#include <windows.h>

#include "tlhelp32.h"

/**
 * @brief Opens a windows application and injects an external DLL into the process.
 */
class DLLInject
{
private:
    HANDLE        m_process_handle;
    std::uint32_t m_process_pid;
    std::string   m_process_name;
    std::string   m_dll_name;
    void*         m_dll_address;
    std::uint32_t m_poll_interval;

    /**
     * @brief   Polls windows process names until the name of the target executable is found.
     *          Polls with a fixed 1 second interval.
     */
    void getPID()
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

    /**
     * @brief   Opens the process and stores its handle.
     *          Execute this function only after the PID is found.
     */
    void openProcess()
    {
        m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_process_pid);
    }

    /**
     * @brief   Allocates memory in the target process and stores the name of the DLL in the opened
     *          process.
     */
    void allocate()
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

    /**
     * @brief   Calls a thread in the target process and loads the DLL. Once the DLL is injected
     *          the program stops
     */
    void startRemoteThread()
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

public:
    /**
     * @brief Takes all necessary parameters to inject the DLL into another process.
     * @param process_name      Name of the process ("myProgram.exe")
     * @param dll_name          Path and name to the DLL ("C:/myDLLs/myDLL.dll").
     * @param poll_interval     Poll interval to refresh process list (in ms).
     */
    explicit DLLInject(
        const std::string&& process_name,
        const std::string&& dll_name,
        const std::uint32_t poll_interval = 1000)
        : m_process_handle(nullptr)
        , m_process_pid(0)
        , m_process_name(process_name)
        , m_dll_name(dll_name)
        , m_dll_address(nullptr)
        , m_poll_interval(poll_interval)
    {
    }

    /**
     * @brief Starts the injection process (blocking function).
     */
    void run()
    {
        getPID();
        openProcess();
        allocate();
        startRemoteThread();
    }
};

#endif  // DLLINJECT_HPP
