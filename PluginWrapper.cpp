#include "PluginWrapper.hpp"

#include <iostream>
#include <string>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>

  static std::wstring utf8_to_wide(const std::string& s)
  {
      if (s.empty()) return {};
      int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
      std::wstring w(n, L'\0');
      MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
      return w;
  }

  static std::string last_error_string()
  {
      DWORD err = GetLastError();
      if (!err) return {};
      LPWSTR msg = nullptr;
      FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr, err, 0, (LPWSTR)&msg, 0, nullptr);
      std::wstring w = msg ? msg : L"";
      if (msg) LocalFree(msg);
      int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
      std::string s(n, '\0');
      WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
      return s;
  }

  static void* Sym(void* h, const char* name)
  {
      FARPROC p = GetProcAddress((HMODULE)h, name);
      if (!p)
      {
          std::cerr << "GetProcAddress failed: " << name
                    << " : " << last_error_string() << "\n";
      }
      return reinterpret_cast<void*>(p);
  }

#else
  #include <dlfcn.h>

  static void* Sym(void* h, const char* name)
  {
      dlerror(); // clear
      void* p = dlsym(h, name);
      if (!p)
      {
          const char* err = dlerror();
          std::cerr << "dlsym failed: " << name
                    << " : " << (err ? err : "unknown") << "\n";
      }
      return p;
  }
#endif

namespace PluginWrapper
{
    Plugin Load(const std::string &path)
    {
        Plugin plugin;

#ifdef _WIN32
        HMODULE mod = LoadLibraryW(utf8_to_wide(path).c_str());
        if (!mod)
        {
            std::cerr << "LoadLibrary failed: " << last_error_string() << "\n";
            return plugin;
        }
        plugin.handle = (void*)mod;
#else
        void* mod = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!mod)
        {
            std::cerr << "dlopen failed: " << dlerror() << "\n";
            return plugin;
        }
        plugin.handle = mod;
#endif

        plugin.Client_Connect =
            reinterpret_cast<Client_Connect_t>(Sym(plugin.handle, "Client_Connect"));

        plugin.Client_Disconnect =
            reinterpret_cast<Client_Disconnect_t>(Sym(plugin.handle, "Client_Disconnect"));

        plugin.Client_Serve =
            reinterpret_cast<Client_Serve_t>(Sym(plugin.handle, "Client_Serve"));

        plugin.Server_Bind =
            reinterpret_cast<Server_Bind_t>(Sym(plugin.handle, "Server_Bind"));

        plugin.Server_Serve =
            reinterpret_cast<Server_Serve_t>(Sym(plugin.handle, "Server_Serve"));

        const bool fine =
            plugin.Client_Connect &&
            plugin.Client_Disconnect &&
            plugin.Client_Serve &&
            plugin.Server_Bind &&
            plugin.Server_Serve;

        if (!fine)
        {
            std::cerr << "Plugin missing required symbols\n";
#ifdef _WIN32
            FreeLibrary((HMODULE)plugin.handle);
#else
            dlclose(plugin.handle);
#endif
            plugin.handle = nullptr;
        }

        return plugin;
    }

    void Unload(const Plugin &plugin)
    {
        if (!plugin.handle) return;
#ifdef _WIN32
        FreeLibrary((HMODULE)plugin.handle);
#else
        dlclose(plugin.handle);
#endif
    }

    bool Client_Connect(const Plugin &plugin,
                        const std::string &server_ip,
                        std::uint16_t port) noexcept
    {
        return plugin.Client_Connect(server_ip, port);
    }

    void Client_Disconnect(const Plugin &plugin) noexcept
    {
        plugin.Client_Disconnect();
    }

    int Client_Serve(const Plugin &plugin,
                     const std::function<ssize_t(std::uint8_t *,
                                                 std::size_t)> &receive_from_net,
                     const std::function<ssize_t(const std::uint8_t *,
                                                 std::size_t)> &send_to_net,
                     const volatile sig_atomic_t *working_flag) noexcept
    {
        return plugin.Client_Serve(receive_from_net, send_to_net, working_flag);
    }

    bool Server_Bind(const Plugin &plugin, std::uint16_t port) noexcept
    {
        return plugin.Server_Bind(port);
    }

    int Server_Serve(const Plugin &plugin,
                     const std::function<ssize_t(std::uint8_t *,
                                                 std::size_t)> &receive_from_net,
                     const std::function<ssize_t(const std::uint8_t *,
                                                 std::size_t)> &send_to_net,
                     const volatile sig_atomic_t *working_flag) noexcept
    {
        return plugin.Server_Serve(receive_from_net, send_to_net, working_flag);
    }
}
