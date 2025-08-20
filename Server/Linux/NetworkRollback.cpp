#include "NetworkRollback.hpp"

// Проектные заголовки — отсутствуют

// Стандартные заголовки
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>

// Внешние зависимости
#include <nftables/libnftables.h>

namespace
{
    std::string ToProcSysPath(const std::string &dotted)
    {
        std::string p = "/proc/sys/";
        p.reserve(p.size() + dotted.size());
        for (char c : dotted)
        {
            p.push_back(c == '.' ? '/' : c);
        }
        return p;
    }

    std::string ReadAllFromFd(int fd)
    {
        std::string out;
        char buf[4096];
        for (;;)
        {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n > 0)
            {
                out.append(buf, buf + n);
                continue;
            }
            if (n == 0)
            {
                break;
            }
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        return out;
    }
}

std::optional<std::string> NetworkRollback::ReadSysctl(const std::string &dotted)
{
    const std::string path = ToProcSysPath(dotted);
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return std::nullopt;
    }
    std::string data = ReadAllFromFd(fd);
    ::close(fd);
    if (data.empty())
    {
        return std::nullopt;
    }
    // trim trailing whitespace/newlines
    while (!data.empty() && (data.back() == '\n' || data.back() == ' ' || data.back() == '\t'))
    {
        data.pop_back();
    }
    return data;
}

bool NetworkRollback::WriteSysctl(const std::string &dotted,
                                  const std::string &value)
{
    const std::string path = ToProcSysPath(dotted);
    int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0)
    {
        std::cerr << "[netrb] WriteSysctl: open failed path=" << path
                  << " errno=" << errno << "\n";
        return false;
    }
    const size_t  need = value.size();
    const ssize_t n    = ::write(fd, value.c_str(), need);

    ::close(fd);
    if (n != static_cast<ssize_t>(need))
    {
        std::cerr << "[netrb] WriteSysctl: write failed path=" << path
                  << " errno=" << errno << "\n";
        return false;
    }
    return true;
}

std::vector<std::string> NetworkRollback::ListIpv6ConfIfaces()
{
    std::vector<std::string> names;
    DIR *d = ::opendir("/proc/sys/net/ipv6/conf");
    if (!d)
    {
        return names;
    }
    while (dirent *e = ::readdir(d))
    {
        if (e->d_name[0] == '.')
        {
            continue;
        }
        names.emplace_back(e->d_name);
    }
    ::closedir(d);
    return names;
}

std::string NetworkRollback::NftExportRuleset()
{
    nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
    {
        std::cerr << "[netrb] nft_ctx_new failed\n";
        return {};
    }
    // буферизуем stdout/err
    nft_ctx_buffer_output(ctx);
    nft_ctx_buffer_error(ctx);

    // По умолчанию вывод в текстовом формате (как в конфигурационных файлах nft)
    int rc = nft_run_cmd_from_buffer(ctx, "list ruleset");
    if (rc != 0)
    {
        const char *err = nft_ctx_get_error_buffer(ctx);
        std::cerr << "[netrb] nft list ruleset failed rc=" << rc
                  << " err=" << (err ? err : "") << "\n";
        nft_ctx_free(ctx);
        return {};
    }
    const char *buf = nft_ctx_get_output_buffer(ctx);
    std::string out = buf ? std::string(buf) : std::string();
    nft_ctx_free(ctx);
    return out;
}

bool NetworkRollback::NftRun(const std::string &script)
{
    nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
    {
        std::cerr << "[netrb] nft_ctx_new failed\n";
        return false;
    }
    nft_ctx_buffer_output(ctx);
    nft_ctx_buffer_error(ctx);
    int rc = nft_run_cmd_from_buffer(ctx, script.c_str());
    if (rc != 0)
    {
        const char *err = nft_ctx_get_error_buffer(ctx);
        std::cerr << "[netrb] nft run failed rc=" << rc
                  << " err=" << (err ? err : "") << "\n";
        nft_ctx_free(ctx);
        return false;
    }
    nft_ctx_free(ctx);
    return true;
}

NetworkRollback::NetworkRollback()
{
    // 1) Сохраняем важные sysctl
    ip_forward_prev_  = ReadSysctl("net.ipv4.ip_forward");
    ip6_forward_prev_ = ReadSysctl("net.ipv6.conf.all.forwarding");

    // 2) Сохраняем accept_ra для всех известных интерфейсов
    for (const std::string &iface : ListIpv6ConfIfaces())
    {
        const std::string key = "net.ipv6.conf." + iface + ".accept_ra";
        if (auto v = ReadSysctl(key))
        {
            accept_ra_prev_.emplace(iface, *v);
        }
    }

    // 3) Сохраняем ruleset nftables (как текст конфигурации)
    nft_ruleset_prev_ = NftExportRuleset();

    // Считаем snapshot успешным, если ruleset считан (даже если каких-то sysctl нет)
    ok_ = !nft_ruleset_prev_.empty();
}

NetworkRollback::~NetworkRollback()
{
    Restore_();
}

bool NetworkRollback::Ok() const
{
    return ok_;
}

void NetworkRollback::Restore_() noexcept
{
    // 1) Восстановление sysctl (делаем best-effort, не прерываемся при ошибках)
    if (ip_forward_prev_)
    {
        (void) WriteSysctl("net.ipv4.ip_forward", *ip_forward_prev_);
    }
    if (ip6_forward_prev_)
    {
        (void) WriteSysctl("net.ipv6.conf.all.forwarding", *ip6_forward_prev_);
    }
    for (const auto &kv : accept_ra_prev_)
    {
        const std::string key = "net.ipv6.conf." + kv.first + ".accept_ra";
        (void) WriteSysctl(key, kv.second);
    }

    // 2) Полный откат nftables: flush ruleset + загрузка сохранённого ruleset
    //    Важно: это восстановит ровно то, что было на момент создания объекта.
    //    Если за это время кто-то ещё менял правила — они будут потеряны.
    if (!nft_ruleset_prev_.empty())
    {
        (void) NftRun("flush ruleset");
        (void) NftRun(nft_ruleset_prev_);
    }
}
