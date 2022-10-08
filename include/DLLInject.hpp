#ifndef DLLINJECT_HPP
#define DLLINJECT_HPP

#include <cstdint>
#include <string>
#include <Windows.h>

/**
 * @brief Opens a windows application and injects an external DLL into the process.
 */
class DLLInject
{
private:
    HANDLE        m_process_handle;
    std::uint32_t m_process_id;
    std::string   m_process_name;
    std::string   m_dll_name;
    void*         m_dll_address;
    std::uint32_t m_poll_interval;
    std::uint32_t m_timeout;

    /**
     * @brief   Polls windows process names until the name of the target executable is found.
     * 
     * @return  Result of getting the PID target process.
     */
    bool getPID();

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
    bool allocate();

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
        const std::string&& process_name,
        const std::string&& dll_name,
        const std::uint32_t poll_interval = 1000,
        const std::uint32_t timeout = 0);

    virtual ~DLLInject();

    /**
     * @brief Starts the injection process (blocking function).
     */
    void run();
};

#endif  // DLLINJECT_HPP
