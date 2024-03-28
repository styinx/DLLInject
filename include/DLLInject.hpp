#ifndef DLLINJECT_HPP
#define DLLINJECT_HPP

#include <Windows.h>
#include <string>

enum InjectResult
{
    SUCCESS,
    TIMEOUT,
    COULD_NOT_OPEN_PROCESS,
    COULD_NOT_ALLOCATE_MEMORY,
    COULD_NOT_WRITE_PROCESS_MEMORY,
    UNKOWN,
};

/**
 * @brief   Polls windows process names until the name of the target executable is found.
 *          If found, the given DLL is loaded into the target executable.
 *
 * @param process_name      Name of the process ("myProgram.exe")
 * @param dll_name          Path and name to the DLL ("C:/myDLLs/myDLL.dll").
 * @param timeout           Maximum time in milliseconds to wait for the injection process.
 *                          Defaults to 0 indicating no timeout.
 * @param poll_interval     Poll interval to refresh process list (in ms).
 *
 * @return  The result of the injection process.
 */
InjectResult injectDLL(
    const std::string&& process_name,
    const std::string&& dll_name,
    const unsigned int  timeout       = 0,
    const unsigned int  poll_interval = 1000);

#endif  // DLLINJECT_HPP
