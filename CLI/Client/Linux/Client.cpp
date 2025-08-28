#include "Client.hpp"

#include <vector>
#include <chrono>
#include <thread>

int main(int argc, char** argv)
{
    Start(argv, argc - 1);
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
