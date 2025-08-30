#include "Core/Plugin.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <cstring>
#include <csignal>
#include <optional>
#include <array>
#include <system_error>
// --- платф. заголовки для htons/ntohs и др. ---
#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
  #ifdef _MSC_VER
  #pragma comment(lib, "Ws2_32.lib")
  #pragma comment(lib, "Crypt32.lib") // часто нужен OpenSSL на Windows
  #endif
#else
  #include <arpa/inet.h>
#endif

// ---------- Traffic accounting (global atomic counters) ----------
// Client side
static std::atomic<std::uint64_t> client_recv_net_bytes{0};     // bytes read via receive_from_net (client.up: TUN->client)
static std::atomic<std::uint64_t> client_send_net_bytes{0};     // bytes written via send_to_net   (client.down: client->TUN)
static std::atomic<std::uint64_t> client_to_server_bytes{0};    // payload bytes sent to server over TLS
static std::atomic<std::uint64_t> client_from_server_bytes{0};  // payload bytes received from server over TLS
// Server side
static std::atomic<std::uint64_t> server_recv_net_bytes{0};     // bytes read via receive_from_net (server.down: TUN->server)
static std::atomic<std::uint64_t> server_send_net_bytes{0};     // bytes written via send_to_net   (server.session: server->TUN)
static std::atomic<std::uint64_t> server_from_client_bytes{0};  // payload bytes received from clients over TLS
static std::atomic<std::uint64_t> server_to_client_bytes{0};    // payload bytes sent to clients over TLS


// Компактная TLS-библиотека для VPN-транспорта
// - TLS (TCP) через Boost.Asio (OpenSSL)
// - Mutual TLS (verify_peer + client cert) через env-пути:
//   MBEDTLS_CA, MBEDTLS_CERT, MBEDTLS_KEY
// - Фрейминг: [uint16_be length][payload]
// - Сервер с несколькими клиентами и маршрутизацией по dest IP
// - Логи в std::cerr, корректная остановка по working_flag

namespace ff
{
    using boost::asio::ip::tcp;
    namespace ssl = boost::asio::ssl;

    static constexpr std::size_t MAX_FRAME = 65535;

    // ---------- Логирование ----------
    static inline void LogErr(const char* where, const std::string& msg)
    {
        std::cerr << "[error] [" << where << "] " << msg << std::endl;
    }
    static inline void LogWarn(const char* where, const std::string& msg)
    {
        std::cerr << "[warning] [" << where << "] " << msg << std::endl;
    }
    static inline void LogInfo(const char* where, const std::string& msg)
    {
        std::cerr << "[info ] [" << where << "] " << msg << std::endl;
    }

    static inline std::string EcStr(const boost::system::error_code& ec)
    {
        return std::to_string(ec.value()) + " (" + ec.category().name() + "): " + ec.message();
    }

    // ---------- Env ----------
    static std::optional<std::string> GetEnvPath(const char* name)
    {
        const char* v = std::getenv(name);
        if (!v || !*v)
        {
            LogErr("env", std::string("env var not set: ") + name);
            return std::nullopt;
        }
        return std::string(v);
    }

    static bool LoadMutualTLSClient(ssl::context& ctx)
    {
        auto ca   = GetEnvPath("MBEDTLS_CA");
        auto cert = GetEnvPath("MBEDTLS_CERT");
        auto key  = GetEnvPath("MBEDTLS_KEY");
        if (!ca || !cert || !key) { return false; }

        ctx.set_options(ssl::context::default_workarounds |
                        ssl::context::no_sslv2 |
                        ssl::context::no_sslv3 |
                        ssl::context::no_tlsv1 |
                        ssl::context::no_tlsv1_1);

        ctx.load_verify_file(*ca);
        ctx.set_verify_mode(ssl::verify_peer);
        ctx.use_certificate_chain_file(*cert);
        ctx.use_private_key_file(*key, ssl::context::file_format::pem);
        return true;
    }

    static bool LoadMutualTLSServer(ssl::context& ctx)
    {
        auto ca   = GetEnvPath("MBEDTLS_CA");
        auto cert = GetEnvPath("MBEDTLS_CERT");
        auto key  = GetEnvPath("MBEDTLS_KEY");
        if (!ca || !cert || !key) { return false; }

        ctx.set_options(ssl::context::default_workarounds |
                        ssl::context::no_sslv2 |
                        ssl::context::no_sslv3 |
                        ssl::context::no_tlsv1 |
                        ssl::context::no_tlsv1_1);

        ctx.load_verify_file(*ca);
        ctx.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
        ctx.use_certificate_chain_file(*cert);
        ctx.use_private_key_file(*key, ssl::context::file_format::pem);
        return true;
    }

    // --- Фрейминг: write/read [uint16_be len][payload] ---
    template<class Stream>
    static bool WriteFrame(Stream& s, const std::uint8_t* data, std::size_t len)
    {
        if (len > MAX_FRAME)
        {
            LogErr("WriteFrame", "payload too large");
            return false;
        }
        std::uint16_t be_len = htons(static_cast<std::uint16_t>(len));
        std::array<boost::asio::const_buffer, 2> bufs =
                {
                        boost::asio::buffer(&be_len, sizeof(be_len)),
                        boost::asio::buffer(data, len)
                };
        boost::asio::write(s, bufs);
        return true;
    }

    template<class Stream>
    static ssize_t ReadFrame(Stream& s, std::uint8_t* out, std::size_t cap,
                             boost::system::error_code& ec)
    {
        std::uint16_t be_len = 0;
        boost::asio::read(s, boost::asio::buffer(&be_len, sizeof(be_len)), ec);
        if (ec) return -1;

        std::size_t need = ntohs(be_len);
        if (need > cap)
        {
            std::vector<std::uint8_t> trash(need);
            boost::asio::read(s, boost::asio::buffer(trash.data(), trash.size()), ec);
            if (!ec) LogWarn("ReadFrame", "frame too large; dropped");
            return -1;
        }

        if (need == 0)
        {
            return 0; // keepalive frame
        }

        boost::asio::read(s, boost::asio::buffer(out, need), ec);
        if (ec) return -1;
        return static_cast<ssize_t>(need);
    }

    // --- Парсинг IP заголовков для маршрутизации ---
    enum class PktKind { Unknown, IPv4, IPv6 };

    static PktKind DetectKind(const std::uint8_t* p, std::size_t n)
    {
        if (n < 1) return PktKind::Unknown;
        std::uint8_t v = static_cast<std::uint8_t>(p[0] >> 4);
        if (v == 4) return PktKind::IPv4;
        if (v == 6) return PktKind::IPv6;
        return PktKind::Unknown;
    }

    static bool ExtractIPv4(const std::uint8_t* p, std::size_t n,
                            std::string& src, std::string& dst)
    {
        if (n < 20) return false;
        std::uint8_t ihl = static_cast<std::uint8_t>(p[0] & 0x0F) * 4;
        if (ihl < 20 || n < ihl) return false;
        std::array<unsigned char, 4> srcb{}, dstb{};
        std::memcpy(srcb.data(), p + 12, 4);
        std::memcpy(dstb.data(), p + 16, 4);
        src = boost::asio::ip::address_v4(srcb).to_string();
        dst = boost::asio::ip::address_v4(dstb).to_string();
        return true;
    }

    static bool ExtractIPv6(const std::uint8_t* p, std::size_t n,
                            std::string& src, std::string& dst)
    {
        if (n < 40) return false;
        std::array<unsigned char, 16> srcb{}, dstb{};
        std::memcpy(srcb.data(), p + 8, 16);
        std::memcpy(dstb.data(), p + 24, 16);
        src = boost::asio::ip::address_v6(srcb).to_string();
        dst = boost::asio::ip::address_v6(dstb).to_string();
        return true;
    }

    static bool ExtractSrcDstKey(const std::uint8_t* p, std::size_t n,
                                 std::string& src, std::string& dst)
    {
        PktKind k = DetectKind(p, n);
        if (k == PktKind::IPv4) return ExtractIPv4(p, n, src, dst);
        if (k == PktKind::IPv6) return ExtractIPv6(p, n, src, dst);
        return false;
    }

    // ---------- CLIENT ----------
    struct ClientState
    {
        std::unique_ptr<boost::asio::io_context> io;
        std::unique_ptr<ssl::context>           tls_ctx;
        std::unique_ptr<ssl::stream<tcp::socket>> tls;
        std::thread up_thread;
        std::thread down_thread;
        std::atomic_bool connected{false};
        std::mutex write_mtx;
    };

    static ClientState g_client;

    // ---------- SERVER ----------
    struct ServerSession;
    struct ServerState
    {
        std::unique_ptr<boost::asio::io_context> io;
        std::unique_ptr<ssl::context>            tls_ctx;
        std::unique_ptr<tcp::acceptor>           acceptor;

        std::function<ssize_t(std::uint8_t*, std::size_t)> recv_net;
        std::function<ssize_t(const std::uint8_t*, std::size_t)> send_net;
        const volatile sig_atomic_t* working_flag = nullptr;

        std::unordered_set<std::shared_ptr<ServerSession>> sessions;
        std::mutex sessions_mtx;

        std::unordered_map<std::string, std::weak_ptr<ServerSession>> route; // dest_ip -> session
        std::mutex route_mtx;

        std::thread accept_thread;
        std::thread down_thread; // чтение из TUN и отправка клиентам
        std::mutex tun_write_mtx; // синхронизация send_net
        std::atomic_bool running{false};
    };

    struct ServerSession : std::enable_shared_from_this<ServerSession>
    {
        std::unique_ptr<ssl::stream<tcp::socket>> tls;
        ServerState* parent = nullptr;
        std::thread up_thread; // чтение от клиента -> TUN
        std::mutex write_mtx;
        std::atomic_bool alive{true};

        explicit ServerSession(std::unique_ptr<ssl::stream<tcp::socket>> s, ServerState* p)
                : tls(std::move(s)), parent(p) {}

        void Start()
        {
            auto self = shared_from_this();
            up_thread = std::thread([self]()
                                    {
                                        std::vector<std::uint8_t> buf(MAX_FRAME);
                                        while (self->alive.load())
                                        {
                                            boost::system::error_code ec;
                                            ssize_t got = ReadFrame(*self->tls, buf.data(), buf.size(), ec);
                                            if (ec)
                                            {
                                                if (!self->alive.load()) break;
                                                if (ec == boost::asio::ssl::error::stream_truncated ||
                                                    ec == boost::asio::error::eof ||
                                                    ec == boost::asio::error::operation_aborted)
                                                {
                                                    LogWarn("server.session", std::string("read EOF/aborted: ") + EcStr(ec));
                                                }
                                                else
                                                {
                                                    LogWarn("server.session", std::string("read error: ") + EcStr(ec));
                                                }
                                                break;
                                            }
                                            if (got < 0) continue;
                                            if (got > 0)
                                            {
                                                server_from_client_bytes.fetch_add(static_cast<std::uint64_t>(got),
                                                                                   std::memory_order_relaxed);
                                                LogInfo("server.session", "from client: " + std::to_string(got)
                                                                          + " B; server_from_client_total=" +
                                                                          std::to_string(
                                                                                  server_from_client_bytes.load()) +
                                                                          " B");
                                            }


                                            // Обновить маршрут: source IP -> эта сессия
                                            if (got > 0)
                                            {
                                                std::string src_key, dst_dummy;
                                                if (ExtractSrcDstKey(buf.data(), static_cast<std::size_t>(got), src_key, dst_dummy))
                                                {
                                                    std::lock_guard<std::mutex> lk(self->parent->route_mtx);
                                                    self->parent->route[src_key] = self;
                                                }
                                            }

                                            // Записать в TUN
                                            if (got > 0)
                                            {
                                                std::lock_guard<std::mutex> lk(self->parent->tun_write_mtx);
                                                ssize_t wr = self->parent->send_net(buf.data(), static_cast<std::size_t>(got));
                                                if (wr > 0)
                                                {
                                                    server_send_net_bytes.fetch_add(static_cast<std::uint64_t>(wr),
                                                                                    std::memory_order_relaxed);
                                                    LogInfo("server.session", "send_to_net: " + std::to_string(wr)
                                                                              + " B; server_send_net_total=" +
                                                                              std::to_string(
                                                                                      server_send_net_bytes.load()) +
                                                                              " B");
                                                }

                                                if (wr < 0)
                                                {
                                                    LogWarn("server.session", "send_to_net returned error");
                                                }
                                            }
                                        }
                                        self->alive.store(false);
                                    });
        }

        bool WriteToClient(const std::uint8_t* data, std::size_t len)
        {
            std::lock_guard<std::mutex> lk(write_mtx);
            try
            {
                return WriteFrame(*tls, data, len);
            }
            catch (const boost::system::system_error& se)
            {
                LogWarn("server.session", std::string("write error: ") + EcStr(se.code()));
                return false;
            }
            catch (const std::exception& e)
            {
                LogWarn("server.session", std::string("write exception: ") + e.what());
                return false;
            }
        }

        void Close()
        {
            alive.store(false);
            try { tls->lowest_layer().shutdown(tcp::socket::shutdown_both); } catch (...) {}
            try { tls->lowest_layer().close(); } catch (...) {}
            if (up_thread.joinable()) up_thread.join();
        }
    };

    static ServerState g_server;

    // ---------- CLIENT API ----------
    bool Client_Connect(const std::string& server_ip, std::uint16_t port) noexcept
    {
        try
        {
            if (g_client.connected.load())
            {
                LogWarn("client", "already connected");
                return true;
            }

            g_client.io      = std::make_unique<boost::asio::io_context>();
            g_client.tls_ctx = std::make_unique<ssl::context>(ssl::context::tls_client);

            if (!LoadMutualTLSClient(*g_client.tls_ctx))
            {
                LogErr("client", "TLS context init failed");
                return false;
            }

            g_client.tls = std::make_unique<ssl::stream<tcp::socket>>(*g_client.io, *g_client.tls_ctx);

            tcp::resolver res(*g_client.io);
            auto results = res.resolve(server_ip, std::to_string(port));
            boost::asio::connect(g_client.tls->lowest_layer(), results);

            // Тюнинг
            g_client.tls->lowest_layer().set_option(tcp::no_delay(true));
            g_client.tls->lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));

            g_client.tls->handshake(ssl::stream_base::client);

            g_client.connected.store(true);
            LogInfo("client", "TLS handshake complete (client)");
            return true;
        }
        catch (const std::exception& e)
        {
            LogErr("client", std::string("connect failed: ") + e.what());
            g_client.connected.store(false);
            return false;
        }
    }

    void Client_Disconnect() noexcept
    {
        try
        {
            if (!g_client.connected.load()) return;

            try { g_client.tls->lowest_layer().shutdown(tcp::socket::shutdown_both); } catch (...) {}
            try { g_client.tls->lowest_layer().close(); } catch (...) {}

            if (g_client.up_thread.joinable())   g_client.up_thread.join();
            if (g_client.down_thread.joinable()) g_client.down_thread.join();

            g_client.tls.reset();
            g_client.tls_ctx.reset();
            g_client.io.reset();
            g_client.connected.store(false);
            LogInfo("client", "disconnected");
        }
        catch (...) { /* noexcept */ }
    }

    int Client_Serve(
            const std::function<ssize_t(std::uint8_t*, std::size_t)>& receive_from_net,
            const std::function<ssize_t(const std::uint8_t*, std::size_t)>& send_to_net,
            const volatile sig_atomic_t* working_flag) noexcept
    {
        if (!working_flag)
        {
            LogErr("client.serve", "working_flag is null");
            return -1;
        }
        if (*working_flag == 0)
        {
            LogWarn("client.serve", "working_flag==0 at entry; refusing to start");
            return -2;
        }
        if (!g_client.connected.load())
        {
            LogErr("client", "not connected");
            return -1;
        }

        try
        {
            std::atomic_bool running{true};

            // Вверх: TUN -> сервер (TLS)
            g_client.up_thread = std::thread([&]()
                                             {
                                                 std::vector<std::uint8_t> buf(MAX_FRAME);
                                                 while (running.load() && *working_flag)
                                                 {
                                                     ssize_t got = receive_from_net(buf.data(), buf.size());
                                                     if (got > 0)
                                                     {
                                                         client_recv_net_bytes.fetch_add(
                                                                 static_cast<std::uint64_t>(got),
                                                                 std::memory_order_relaxed);
                                                         LogInfo("client.up", "receive_from_net: " + std::to_string(got)
                                                                              + " B; client_recv_net_total=" +
                                                                              std::to_string(
                                                                                      client_recv_net_bytes.load()) +
                                                                              " B");
                                                     }

                                                     if (got < 0)
                                                     {
                                                         LogWarn("client.up", "receive_from_net error");
                                                         continue;
                                                     }
                                                     if (got == 0) { continue; }
                                                     std::lock_guard<std::mutex> lk(g_client.write_mtx);
                                                     try
                                                     {
                                                         bool ok = WriteFrame(*g_client.tls, buf.data(), static_cast<std::size_t>(got));
                                                         if (!ok)
                                                         {
                                                             LogWarn("client.up", "WriteFrame failed");
                                                             break;
                                                         }
                                                         client_to_server_bytes.fetch_add(static_cast<std::uint64_t>(got), std::memory_order_relaxed);
                                                         LogInfo("client.up", "to server: " + std::to_string(got)
                                                            + " B; client_to_server_total=" + std::to_string(client_to_server_bytes.load()) + " B");
                                                     }
                                                     catch (const boost::system::system_error& se)
                                                     {
                                                         LogWarn("client.up", std::string("write error ") + EcStr(se.code()));
                                                         break;
                                                     }
                                                     catch (const std::exception& e)
                                                     {
                                                         LogWarn("client.up", std::string("write exception: ") + e.what());
                                                         break;
                                                     }
                                                 }
                                             });

            // Вниз: сервер (TLS) -> TUN
            g_client.down_thread = std::thread([&]()
                                               {
                                                   std::vector<std::uint8_t> buf(MAX_FRAME);
                                                   while (running.load() && *working_flag)
                                                   {
                                                       boost::system::error_code ec;
                                                       ssize_t got = ReadFrame(*g_client.tls, buf.data(), buf.size(), ec);
                                                       if (ec)
                                                       {
                                                           if (!running.load() || !*working_flag)
                                                               break; // штатная остановка
                                                           const bool is_ssl_short_read =
                                                                   (ec.category().name() &&
                                                                    std::string(ec.category().name()) ==
                                                                    std::string("asio.ssl.stream")
                                                                    && (ec.value() == 1 /*stream_truncated*/ ||
                                                                        ec.value() == 2 /*short read/unspecified*/));
                                                           const bool is_eof_like =
                                                                   is_ssl_short_read ||
                                                                   ec == boost::asio::ssl::error::stream_truncated ||
                                                                   ec == boost::asio::error::eof ||
                                                                   ec == boost::asio::error::operation_aborted;
                                                           LogWarn("client.down",
                                                                   std::string(is_eof_like ? "read EOF/aborted: "
                                                                                           : "read error ")
                                                                   + EcStr(ec) + " {cat=" + ec.category().name() +
                                                                   ", val=" + std::to_string(ec.value()) + "}");
                                                           break;
                                                       }
                                                       if (got <= 0) { continue; }
                                                       client_from_server_bytes.fetch_add(static_cast<std::uint64_t>(got), std::memory_order_relaxed);
                                                       LogInfo("client.down", "from server: " + std::to_string(got)
                                                            + " B; client_from_server_total=" + std::to_string(client_from_server_bytes.load()) + " B");

                                                       ssize_t wr = send_to_net(buf.data(), static_cast<std::size_t>(got));
                                                       if (wr > 0)
                                                       {
                                                           client_send_net_bytes.fetch_add(
                                                                   static_cast<std::uint64_t>(wr),
                                                                   std::memory_order_relaxed);
                                                           LogInfo("client.down", "send_to_net: " + std::to_string(wr)
                                                                                  + " B; client_send_net_total=" +
                                                                                  std::to_string(
                                                                                          client_send_net_bytes.load()) +
                                                                                  " B");
                                                       }
                                                       if (wr < 0)
                                                       {
                                                           LogWarn("client.down", "send_to_net error");
                                                       }
                                                   }
                                               });

            // Блокирующее ожидание остановки
            while (*working_flag) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
            running.store(false);

            // Разбудить блокирующие read()/write()
            try { g_client.tls->lowest_layer().cancel(); } catch (...) {}
            try { g_client.tls->lowest_layer().shutdown(tcp::socket::shutdown_both); } catch (...) {}
            try { g_client.tls->lowest_layer().close(); } catch (...) {}

            if (g_client.up_thread.joinable())   g_client.up_thread.join();
            if (g_client.down_thread.joinable()) g_client.down_thread.join();

            return 0;
        }
        catch (const std::exception& e)
        {
            LogErr("client.serve", e.what());
            return -1;
        }
    }

    // ---------- SERVER API ----------
    bool Server_Bind(std::uint16_t port) noexcept
    {
        try
        {
            if (g_server.running.load())
            {
                LogWarn("server", "already running");
                return true;
            }

            g_server.io      = std::make_unique<boost::asio::io_context>();
            g_server.tls_ctx = std::make_unique<ssl::context>(ssl::context::tls_server);

            if (!LoadMutualTLSServer(*g_server.tls_ctx))
            {
                LogErr("server", "TLS context init failed");
                return false;
            }

            tcp::endpoint ep(tcp::v4(), port);
            g_server.acceptor = std::make_unique<tcp::acceptor>(*g_server.io);
            g_server.acceptor->open(ep.protocol());
            g_server.acceptor->set_option(tcp::acceptor::reuse_address(true));
            g_server.acceptor->bind(ep);
            g_server.acceptor->listen();

            LogInfo("server", "bind ok");
            return true;
        }
        catch (const std::exception& e)
        {
            LogErr("server.bind", e.what());
            return false;
        }
    }

    int Server_Serve(
            const std::function<ssize_t(std::uint8_t*, std::size_t)>& receive_from_net,
            const std::function<ssize_t(const std::uint8_t*, std::size_t)>& send_to_net,
            const volatile sig_atomic_t* working_flag) noexcept
    {
        if (!working_flag)
        {
            LogErr("server.serve", "working_flag is null");
            return -1;
        }
        if (*working_flag == 0)
        {
            LogWarn("server.serve", "working_flag==0 at entry; refusing to start");
            return -2;
        }
        if (!g_server.acceptor)
        {
            LogErr("server", "not bound");
            return -1;
        }

        g_server.recv_net    = receive_from_net;
        g_server.send_net    = send_to_net;
        g_server.working_flag= working_flag;
        g_server.running.store(true);

        try
        {
            // Поток приёма соединений
            g_server.accept_thread = std::thread([&]()
                                                 {
                                                     while (g_server.running.load() && *g_server.working_flag)
                                                     {
                                                         try
                                                         {
                                                             tcp::socket sock(*g_server.io);
                                                             g_server.acceptor->accept(sock);

                                                             auto tls = std::make_unique<ssl::stream<tcp::socket>>(std::move(sock), *g_server.tls_ctx);
                                                             tls->set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
                                                             tls->handshake(ssl::stream_base::server);

                                                             // Тюнинг сокета
                                                             tls->lowest_layer().set_option(tcp::no_delay(true));
                                                             tls->lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));

                                                             auto sess = std::make_shared<ServerSession>(std::move(tls), &g_server);
                                                             {
                                                                 std::lock_guard<std::mutex> lk(g_server.sessions_mtx);
                                                                 g_server.sessions.insert(sess);
                                                             }
                                                             LogInfo("server", "TLS handshake complete (server); new client");

                                                             // Keepalive: нулевой фрейм
                                                             try
                                                             {
                                                                 std::lock_guard<std::mutex> lk(sess->write_mtx);
                                                                 std::uint8_t dummy = 0;
                                                                 WriteFrame(*sess->tls, &dummy, 0);
                                                                 LogInfo("server", "sent keepalive frame to new client");
                                                             }
                                                             catch (const std::exception& e)
                                                             {
                                                                 LogWarn("server", std::string("keepalive send failed: ") + e.what());
                                                             }

                                                             sess->Start();
                                                         }
                                                         catch (const boost::system::system_error& se)
                                                         {
                                                             if (g_server.running.load() && *g_server.working_flag)
                                                             {
                                                                 LogWarn("server.accept", EcStr(se.code()));
                                                             }
                                                             else { break; }
                                                         }
                                                         catch (const std::exception& e)
                                                         {
                                                             if (g_server.running.load() && *g_server.working_flag)
                                                             {
                                                                 LogWarn("server.accept", e.what());
                                                             }
                                                             else { break; }
                                                         }
                                                     }
                                                 });

            // Поток чтения из TUN и отправки конкретным клиентам
            g_server.down_thread = std::thread([&]()
                                               {
                                                   std::vector<std::uint8_t> buf(MAX_FRAME);
                                                   while (g_server.running.load() && *g_server.working_flag)
                                                   {
                                                       ssize_t got = g_server.recv_net(buf.data(), buf.size());
                                                       if (got < 0)
                                                       {
                                                           LogWarn("server.down", "receive_from_net error");
                                                           continue;
                                                       }
                                                       if (got == 0) continue;
                                                       server_recv_net_bytes.fetch_add(static_cast<std::uint64_t>(got), std::memory_order_relaxed);
                                                       LogInfo("server.down", "receive_from_net: " + std::to_string(got)
                                                            + " B; server_recv_net_total=" + std::to_string(server_recv_net_bytes.load()) + " B");

                                                       std::string src_key, dst_key;
                                                       if (!ExtractSrcDstKey(buf.data(), static_cast<std::size_t>(got), src_key, dst_key))
                                                       {
                                                           LogWarn("server.down", "unknown packet kind; drop");
                                                           continue;
                                                       }

                                                       std::shared_ptr<ServerSession> target;
                                                       {
                                                           std::lock_guard<std::mutex> lk(g_server.route_mtx);
                                                           auto it = g_server.route.find(dst_key);
                                                           if (it != g_server.route.end())
                                                           {
                                                               target = it->second.lock();
                                                               if (!target) { g_server.route.erase(it); }
                                                           }
                                                       }

                                                       if (target)
                                                       {
                                                           bool ok2 = target->WriteToClient(buf.data(), static_cast<std::size_t>(got));
                                                           if (!ok2)
                                                           {
                                                               LogWarn("server.down", "write to client failed");
                                                           }
                                                               else
                                                           {
                                                               server_to_client_bytes.fetch_add(
                                                                       static_cast<std::uint64_t>(got),
                                                                       std::memory_order_relaxed);
                                                               LogInfo("server.down",
                                                                       "to client: " + std::to_string(got)
                                                                       + " B; server_to_client_total=" +
                                                                       std::to_string(server_to_client_bytes.load()) +
                                                                       " B");
                                                           }
                                                       }
                                                       else
                                                       {
                                                           LogWarn("server.down", "no route for dest=" + dst_key + " (drop)");
                                                       }
                                                   }
                                               });

            // Блокируемся до остановки
            while (*working_flag) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
            g_server.running.store(false);

            // Прервать блокирующие операции
            try { g_server.acceptor->close(); } catch (...) {}

            if (g_server.accept_thread.joinable()) g_server.accept_thread.join();
            if (g_server.down_thread.joinable())   g_server.down_thread.join();

            // Закрыть все сессии
            {
                std::lock_guard<std::mutex> lk(g_server.sessions_mtx);
                for (auto& s : g_server.sessions) { s->Close(); }
                g_server.sessions.clear();
            }
            return 0;
        }
        catch (const std::exception& e)
        {
            LogErr("server.serve", e.what());
            g_server.running.store(false);
            return -1;
        }
    }
} // namespace ff

// ---------- C ABI EXPORTS ----------
PLUGIN_API bool Client_Connect(const std::string& server_ip, std::uint16_t port) noexcept
{
    return ff::Client_Connect(server_ip, port);
}
PLUGIN_API void Client_Disconnect() noexcept
{
    ff::Client_Disconnect();
}
PLUGIN_API int Client_Serve(
        const std::function<ssize_t(std::uint8_t*, std::size_t)>& receive_from_net,
        const std::function<ssize_t(const std::uint8_t*, std::size_t)>& send_to_net,
        const volatile sig_atomic_t* working_flag) noexcept
{
    return ff::Client_Serve(receive_from_net, send_to_net, working_flag);
}

PLUGIN_API bool Server_Bind(std::uint16_t port) noexcept
{
    return ff::Server_Bind(port);
}
PLUGIN_API int Server_Serve(
        const std::function<ssize_t(std::uint8_t*, std::size_t)>& receive_from_net,
        const std::function<ssize_t(const std::uint8_t*, std::size_t)>& send_to_net,
        const volatile sig_atomic_t* working_flag) noexcept
{
    return ff::Server_Serve(receive_from_net, send_to_net, working_flag);
}