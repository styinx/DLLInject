#include "DLLInject_headeronly.hpp"

int main(int argc, char** argv)
{
    DLLInject injector{"myprocess.exe", "path\\to_my_dll\\mydll.dll"};
    injector.run();
    return 0;
}
