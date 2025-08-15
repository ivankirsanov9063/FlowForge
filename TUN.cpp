#include "TUN.hpp"

#ifdef __linux__

#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

int TunAlloc(const std::string &interface_name)
{
    int descriptor = open("/dev/net/tun",
                          O_RDWR | O_CLOEXEC);

    if (descriptor < 0)
    {
        std::cerr << "Error in open /dev/net/tun\n";
        return -1;
    }

    struct ifreq request {};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;

    std::strncpy(request.ifr_name,
                 interface_name.c_str(),
                 IFNAMSIZ);

    if (ioctl(descriptor, TUNSETIFF,
              (void *)&request) < 0)
    {
        std::cerr << "Error in ioctl TUNSETIFF\n";
        close(descriptor);
        return -1;
    }

    std::cout << "TUN up: " << request.ifr_name << "\n";
    return descriptor;
}

#elif _WIN32

bool WintunApi::load()
{
    dll = LoadLibraryW(L"wintun.dll");
    if (!dll)
    {
        return false;
    }
    Open  = (WintunOpenAdapter_t)  GetProcAddress(dll, "WintunOpenAdapter");
    Create= (WintunCreateAdapter_t)GetProcAddress(dll, "WintunCreateAdapter");
    Close = (WintunCloseAdapter_t) GetProcAddress(dll, "WintunCloseAdapter");
    Delete= (WintunDeleteAdapter_t)GetProcAddress(dll, "WintunDeleteAdapter");
    Start = (WintunStartSession_t) GetProcAddress(dll, "WintunStartSession");
    End   = (WintunEndSession_t)   GetProcAddress(dll, "WintunEndSession");
    ReadEvent=(WintunGetReadWaitEvent_t)GetProcAddress(dll, "WintunGetReadWaitEvent");
    Recv  = (WintunReceivePacket_t)GetProcAddress(dll, "WintunReceivePacket");
    RecvRelease=(WintunReleaseReceivePacket_t)GetProcAddress(dll, "WintunReleaseReceivePacket");
    AllocSend=(WintunAllocateSendPacket_t)GetProcAddress(dll, "WintunAllocateSendPacket");
    Send  = (WintunSendPacket_t)  GetProcAddress(dll, "WintunSendPacket");
    GetLuid=(WintunGetAdapterLUID_t)GetProcAddress(dll, "WintunGetAdapterLUID");
    return Open && Create && Close && Start && End && ReadEvent && Recv && RecvRelease && AllocSend && Send && GetLuid;
}

WintunApi::~WintunApi()
{
    if (dll)
    {
        FreeLibrary(dll);
    }
}


#endif
