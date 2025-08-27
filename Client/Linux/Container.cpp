#include "Container.hpp"

namespace Container
{

bool FileExists(const char *path)
{
    std::ifstream f(path);
    return f.good();
}

std::optional<std::string> ReadAll(const char *path)
{
    std::ifstream f(path);
    if (!f)
    {
        return std::nullopt;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void TrimInPlace(std::string &s)
{
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a])))
    {
        ++a;
    }
    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
    {
        --b;
    }
    if (a != 0 || b != s.size())
    {
        s = s.substr(a, b - a);
    }
}

bool FindTokenI(const std::string &hay, const char *needle)
{
    if (!needle || *needle == '\0')
    {
        return true;
    }
    const std::string n(needle);
    return std::search(
            hay.begin(), hay.end(),
            n.begin(), n.end(),
            [](unsigned char a, unsigned char b)
            {
                return std::tolower(a) == std::tolower(b);
            }) != hay.end();
}

// Быстрый и простой ответ на вопрос: мы в контейнере?
bool IsRunningInContainer()
{
    // 1) Явные “сильные” маркеры файлов от Docker/Podman
    if (FileExists("/.dockerenv") || FileExists("/.containerenv"))
    {
        return true;
    }

    // 2) Маркер systemd
    if (auto v = ReadAll("/run/systemd/container"))
    {
        TrimInPlace(*v);
        if (!v->empty())
        {
            return true;
        }
    }

    // 3) ENV-переменная, которую часто выставляют контейнерные рантаймы
    if (const char *c = std::getenv("container"); c != nullptr && *c != '\0')
    {
        return true;
    }

    // 4) cgroup v1/v2 — универсальный, но всё ещё “быстрый” признак
    const char *tokens[] = {
            "docker", "kubepods", "containerd", "libpod", "podman",
            "lxc", "garden", "rkt", "ecs"
    };

    auto check_cgroup = [&](const char *path) -> bool
    {
        auto txt = ReadAll(path);
        if (!txt) return false;
        for (const char *t : tokens)
        {
            if (FindTokenI(*txt, t))
            {
                return true;
            }
        }
        return false;
    };

    if (check_cgroup("/proc/1/cgroup") || check_cgroup("/proc/self/cgroup"))
    {
        return true;
    }

    return false; // ничего не нашли — считаем, что не контейнер
}

}