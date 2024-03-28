# DLLInject

Inject a DLL into a windows process.

## Build

```
cmake -S . -B build
cmake --build build
```

## How to use

```c++
#include "DLLInject.hpp"

int main(int argc, char** argv)
{
    if(injectDLL("your.exe", "your.dll", 5000, 1000) == InjectResult::SUCCESS)
        printf("DLL was injected successfully.\n");

    return 0;
}
```
