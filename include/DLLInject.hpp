#ifndef DLLINJECT_HPP
#define DLLINJECT_HPP

#include <Windows.h>
#include <cstdint>
#include <string>

using Uint32 = std::uint32_t;
using String = std::string;

/**
 * @brief Stores properties of the process that was injected.
 */
struct ProcessInfo
{
    void*  dll_address    = nullptr;
    HANDLE process_handle = nullptr;
    DWORD  process_id     = 0;
};

/**
 * @brief Opens a windows application and injects an external DLL into the process.
 */
class DLLInject
{
private:
    ProcessInfo m_info;
    String      m_process_name;
    String      m_dll_name;
    Uint32      m_poll_interval;
    Uint32      m_timeout;

    /**
     * @brief   Polls windows process names until the name of the target executable is found.
     *
     * @return  Result of getting the PID target process.
     */
    bool findPID();

    /**
     * @brief   Opens the process and stores its handle.
     *          Execute this function only after the PID is found.
     *
     * @return  Result of opening the target process.
     */
    bool openProcess();

    /**
     * @brief   Allocates memory in the target process and stores the name of the DLL in the opened
     *          process.
     *
     * @return  Result of the memory allocation in the target process.
     */
    bool allocateDLLSpace();

    /**
     * @brief   Injects the DLL into the process at the allocated memory region.
     *
     * @return  Result of injection.
     */
    bool injectDLL();

    /**
     * @brief   Calls a thread in the target process and loads the DLL. Once the DLL is injected
     *          the program stops.
     *
     * @return  Result of starting a remote thread in the target process.
     */
    bool startRemoteThread();

public:
    /**
     * @brief   Takes all necessary parameters to inject the DLL into another process.
     *
     * @param process_name      Name of the process ("myProgram.exe")
     * @param dll_name          Path and name to the DLL ("C:/myDLLs/myDLL.dll").
     * @param poll_interval     Poll interval to refresh process list (in ms).
     * @param timeout           Maximum time in milliseconds to wait for the injections process.
     *                          Defaults to -1 indicating no timeout.
     */
    explicit DLLInject(
        const String&& process_name,
        const String&& dll_name,
        const Uint32   poll_interval = 1000,
        const Uint32   timeout       = 0);

    virtual ~DLLInject();

    /**
     * @brief   Starts the injection process (blocking function).
     *
     * @return  Result of the complete injection process.
     */
    bool run();

    /**
     * @return  Returns a structure of the information from the injected process.
     */
    ProcessInfo getProcessInfo() const;
};

#endif  // DLLINJECT_HPP
