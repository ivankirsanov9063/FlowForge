#pragma once

#include <string>
#include <optional>

bool is_ipv6_literal(const std::string &s);
std::string strip_brackets(std::string s);

// Унифицированные утилиты (возвращают 0 при успехе, <0 при ошибке)
int if_set_up(const std::string &ifname);
int if_set_mtu(const std::string &ifname, int mtu);

struct GwInfo
{
    int         ifindex;   // Linux: ifindex; Windows: InterfaceIndex
    std::string gw_text;   // Текст шлюза ("1.2.3.4" или "fe80::1")
};

std::optional<int> get_default_metric(int family);

// --- Платформенные ветки API для адресов/маршрутов ---
#ifdef __linux__
  #include <netlink/netlink.h>
  // Linux (libnl) сигнатуры
  void flush_addrs(struct nl_sock *sk, int ifindex, int family);
  void add_addr_p2p(struct nl_sock *sk, int ifindex, int family,
                    const std::string &local_str, int prefix,
                    const std::string &peer_str);
  std::optional<GwInfo> find_default_gw(struct nl_sock *sk, int family);
  void add_host_route_via_gw(struct nl_sock *sk, int family,
                             const std::string &host_ip,
                             const GwInfo &gw);
  void replace_default_via_dev(struct nl_sock *sk, int family, int oif);

  // Только для Linux
  void write_proc(const char *path, const char *data);
  void write_proc_if_sysctl(const std::string &ifname,
                            const char *key, const char *value);
#else
  // Windows (без libnl): те же действия, но без nl_sock
  void flush_addrs_win(const std::string &ifname, int family);
  void add_addr_p2p_win(const std::string &ifname, int family,
                        const std::string &local_str, int prefix,
                        const std::string &peer_str);
  std::optional<GwInfo> find_default_gw_win(int family);
  void add_host_route_via_gw_win(int family,
                                 const std::string &host_ip,
                                 const GwInfo &gw);
  void replace_default_via_dev_win(int family, const std::string &ifname);

  // Заглушки (на Windows нет /proc/sys)
  inline void write_proc(const char*, const char*) {}
  inline void write_proc_if_sysctl(const std::string&, const char*, const char*) {}
#endif
