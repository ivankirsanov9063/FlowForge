#include "Server.hpp"

#include <vector>
#include <chrono>
#include <thread>
#include <csignal>

bool working = true;

void OnExit(int)
{
    Stop();
    working = false;
}

int main(int argc, char** argv)
{
    Start(argv, argc - 1);
    std::signal(SIGINT,  OnExit);
    std::signal(SIGTERM, OnExit);

    while (working)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
