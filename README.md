# DLLInject

Inject a DLL into a windows process.

## Build

```
mkdir build
cd build
cmake ..
```

## How to use

See also `/examples` folder.

```c++
#include "DLLInject.hpp"

int main(int argc, char** argv)
{
    DLLInject injector{"myprocess.exe", "path\\to_my_dll\\mydll.dll"};
    injector.run();
    return 0;
}
```
