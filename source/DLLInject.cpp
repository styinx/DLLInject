#include "dllInject.hpp"

#include <tlhelp32.h>

InjectResult injectDLL(
    const std::string&& process_name,
    const std::string&& dll_name,
    const unsigned int  poll_interval,
    const unsigned int  timeout)
{

    // Find PID
    DWORD        process_id = 0;
    unsigned int timer      = 0;
    while(process_id == 0)
    {
        if(timeout > 0 && timer > timeout)
            return InjectResult::TIMEOUT;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if(snapshot == INVALID_HANDLE_VALUE)
            return InjectResult::UNKOWN;

        PROCESSENTRY32 process_entry{};
        process_entry.dwSize = sizeof(PROCESSENTRY32);

        if(Process32First(snapshot, &process_entry))
        {
            do
            {
                std::string process = process_entry.szExeFile;
                if(process == process_name)
                {
                    process_id = process_entry.th32ProcessID;
                    break;
                }
            } while(Process32Next(snapshot, &process_entry));
        }

        CloseHandle(snapshot);
        Sleep(poll_interval);
        timer += poll_interval;
    }

    // Open target process
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if(process_handle == nullptr)
        return InjectResult::COULD_NOT_OPEN_PROCESS;

    // Allocate space for the DLL name and a zero byte.
    void* dll_address =
        VirtualAllocEx(process_handle, nullptr, dll_name.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if(dll_address == nullptr)
        return InjectResult::COULD_NOT_ALLOCATE_MEMORY;

    // Write the DLL name into the allocated memory.
    if(WriteProcessMemory(process_handle, dll_address, dll_name.data(), dll_name.size() + 1, nullptr) !=
       TRUE)
        return InjectResult::COULD_NOT_WRITE_PROCESS_MEMORY;

    // Load the DLL into the target process.
    HANDLE remote_thread = CreateRemoteThread(
        process_handle,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        dll_address,
        0,
        nullptr);

    if(remote_thread != nullptr && remote_thread != INVALID_HANDLE_VALUE)
        CloseHandle(remote_thread);

    // Finalize
    if(process_handle)
        CloseHandle(process_handle);

    return InjectResult::SUCCESS;
}
