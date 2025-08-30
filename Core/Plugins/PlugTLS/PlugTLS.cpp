// PlugTLS.cpp
// Compact TLS (OpenSSL via Boost.Asio) client/server for a VPN-style plugin.
// - Mutual TLS authentication by certificates (paths via env MBEDTLS_CA/MBEDTLS_CERT/MBEDTLS_KEY).
// - Threaded Asio for concurrency. Multi-client server with per-client routing.
// - Length-prefixed framing over TLS. Payloads are raw IP packets from TUN.
// - Server demux: routes TUN packets to a client by IPv4 destination address, learned
//   from client->server packets (source IPv4 observed on first uplink packet).
// - All runtime errors are logged to std::cerr and do not *intentionally* tear down
//   the process; where recovery is impossible (e.g., dead socket), we keep looping
//   while the working flag stays set.
//
// Build (example):
//   g++ -std=c++23 -fPIC -shared PlugTLS.cpp -o libPlugTLS.so \
//       -lssl -lcrypto -lboost_system -lpthread
//
// Notes:
// - This is a minimal, compact implementation. It prefers higher-level Boost.Asio APIs.
// - It avoids closing connections on transient errors; for hard errors we log and keep
//   the service loop alive until the working flag turns off (the broken peer socket
//   will simply keep failing reads/writes, which we continue to log).
// - For production, consider: bounded queues, backpressure, per-client rate limits,
//   TLS options hardening, graceful reconnection logic, and stronger error taxonomy.

#include "Core/Plugin.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>

#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <chrono>
#include <array>

#include <unistd.h>
#include <arpa/inet.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using ssize_t = ::ssize_t;

namespace
{
    using tcp = boost::asio::ip::tcp;
    namespace ssl = boost::asio::ssl;
    using boost::asio::ip::address_v4;

    // --------- Utilities ---------

    static inline void LogErr(const char* tag, const std::string& msg)
    {
        std::cerr << "[error] [" << tag << "] " << msg << std::endl;
    }

    static inline void LogWarn(const char* tag, const std::string& msg)
    {
        std::cerr << "[warning] [" << tag << "] " << msg << std::endl;
    }

    static inline void LogInfo(const char* tag, const std::string& msg)
    {
        std::cerr << "[info ] [" << tag << "] " << msg << std::endl;
    }

    static inline uint32_t ReadBE32(const uint8_t* p)
    {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }

    static inline void WriteBE32(uint8_t* p, uint32_t v)
    {
        p[0] = uint8_t((v >> 24) & 0xFF);
        p[1] = uint8_t((v >> 16) & 0xFF);
        p[2] = uint8_t((v >> 8) & 0xFF);
        p[3] = uint8_t((v) & 0xFF);
    }

    // Quick IPv4 parser to extract src/dst. Returns false if not IPv4.
    static bool ParseIPv4SrcDst(const uint8_t* data, size_t len, uint32_t& src, uint32_t& dst)
    {
        if (len < 20) return false;
        uint8_t vihl = data[0];
        uint8_t version = vihl >> 4;
        uint8_t ihl = (vihl & 0x0F) * 4;
        if (version != 4) return false;
        if (ihl < 20 || ihl > len) return false;
        // total length check (optional):
        // uint16_t totlen = (data[2] << 8) | data[3];
        // if (totlen > len) return false;
        std::memcpy(&src, data + 12, 4);
        std::memcpy(&dst, data + 16, 4);
        // src/dst are in network byte order now; we keep them as big-endian keys
        return true;
    }

    // Write/Read framed payloads over TLS: [4-byte big-endian length][payload]
    template <typename Stream>
    static bool WriteFrame(Stream& s, const uint8_t* data, size_t len, boost::system::error_code& ec)
    {
        uint8_t hdr[4];
        WriteBE32(hdr, static_cast<uint32_t>(len));
        std::array<boost::asio::const_buffer, 2> bufs {
                boost::asio::buffer(hdr, 4),
                boost::asio::buffer(data, len)
        };
        boost::asio::write(s, bufs, ec);
        return !ec;
    }

    template <typename Stream>
    static bool ReadFrame(Stream& s, std::vector<uint8_t>& out, boost::system::error_code& ec)
    {
        uint8_t hdr[4];
        boost::asio::read(s, boost::asio::buffer(hdr, 4), ec);
        if (ec) return false;
        uint32_t len = ReadBE32(hdr);
        if (len == 0 || len > (16u * 1024u * 1024u))
        {
            ec = make_error_code(boost::system::errc::invalid_argument);
            return false;
        }
        out.resize(len);
        boost::asio::read(s, boost::asio::buffer(out.data(), len), ec);
        return !ec;
    }

    // Load certs/keys from env (same names user provided even if using OpenSSL under the hood).
    static bool ConfigureSSLContext(ssl::context& ctx, bool is_server)
    {
        try
        {
            const char* ca    = std::getenv("MBEDTLS_CA");
            const char* cert  = std::getenv("MBEDTLS_CERT");
            const char* pkey  = std::getenv("MBEDTLS_KEY");
            if (!ca || !cert || !pkey)
            {
                LogErr(is_server ? "server" : "client", "Env MBEDTLS_CA/MBEDTLS_CERT/MBEDTLS_KEY must be set");
                return false;
            }

            ctx.set_options(
                    ssl::context::default_workarounds |
                    ssl::context::no_sslv2 |
                    ssl::context::no_sslv3 |
                    ssl::context::no_tlsv1 |
                    ssl::context::no_tlsv1_1 |
                    ssl::context::single_dh_use
            );

            ctx.set_verify_mode(ssl::verify_peer | (is_server ? ssl::verify_fail_if_no_peer_cert : 0));
            ctx.load_verify_file(ca);
            ctx.use_certificate_chain_file(cert);
            ctx.use_private_key_file(pkey, ssl::context::pem);

            return true;
        }
        catch (const std::exception& e)
        {
            LogErr(is_server ? "server" : "client", std::string("SSL ctx error: ") + e.what());
            return false;
        }
    }

    // Sleep helper that ignores signals
    static void SleepMs(int ms)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // ------------- CLIENT STATE -------------

    boost::asio::io_context                 g_client_io(1);
    std::unique_ptr<ssl::context>           g_client_ssl;
    std::shared_ptr<ssl::stream<tcp::socket>> g_client_tls;
    std::mutex                              g_client_mx;
    std::atomic<bool>                       g_client_connected{false};

    // ------------- SERVER STATE -------------

    boost::asio::io_context                 g_server_io;
    std::unique_ptr<ssl::context>           g_server_ssl;
    std::unique_ptr<tcp::acceptor>          g_server_acceptor;
    std::vector<std::thread>                g_server_threads;

    struct ServerSession;
    std::mutex                              g_sess_mx;
    std::unordered_set<std::shared_ptr<ServerSession>> g_sessions;

    // Map client's inner IPv4 (big-endian key) -> session
    std::unordered_map<uint32_t, std::weak_ptr<ServerSession>> g_ip_to_session;

    // Queue of frames from clients destined to server's TUN
    struct TunFrame
    {
        std::vector<uint8_t> data;
    };
    std::mutex              g_tunq_mx;
    std::condition_variable g_tunq_cv;
    std::deque<TunFrame>    g_to_tun_q;

    volatile const sig_atomic_t*            g_server_working_flag = nullptr;

    struct ServerSession : public std::enable_shared_from_this<ServerSession>
    {
        explicit ServerSession(ssl::context& ctx)
                : tls(g_server_io, ctx)
        {
        }

        ssl::stream<tcp::socket> tls;
        std::atomic<bool>         alive{false};
        std::string               peer;

        void Start()
        {
            auto self = shared_from_this();
            tls.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
            tls.lowest_layer().set_option(tcp::no_delay(true));
            alive.store(true);
            tls.async_handshake(ssl::stream_base::server,
                                [self](const boost::system::error_code& ec)
                                {
                                    if (ec)
                                    {
                                        LogWarn("server", std::string("TLS handshake failed: ") + ec.message());
                                        self->alive.store(false);
                                        return;
                                    }
                                    try
                                    {
                                        self->peer = self->tls.lowest_layer().remote_endpoint().address().to_string();
                                    }
                                    catch (...) { self->peer = "unknown"; }
                                    LogInfo("server", std::string("TLS handshake complete; new client from ") + self->peer);
                                    self->ReadLoop();
                                });
        }

        void ReadLoop()
        {
            auto self = shared_from_this();
            // Read frames forever; on any error, log and keep trying (if working flag is set).
            boost::asio::post(g_server_io, [self]
            {
                std::vector<uint8_t> buf;
                while (self->alive.load())
                {
                    if (g_server_working_flag && *g_server_working_flag == 0)
                    {
                        break;
                    }
                    boost::system::error_code ec;
                    bool ok = ReadFrame(self->tls, buf, ec);
                    if (!ok)
                    {
                        LogWarn("server.down", std::string("read error: ") + ec.message());
                        // Simple backoff to avoid tight loop on dead socket:
                        SleepMs(100);
                        continue;
                    }

                    // Learn mapping: client's *source* IPv4 is this session's inner address.
                    uint32_t src_be = 0, dst_be = 0;
                    if (ParseIPv4SrcDst(buf.data(), buf.size(), src_be, dst_be))
                    {
                        std::lock_guard<std::mutex> lk(g_sess_mx);
                        g_ip_to_session[src_be] = self;
                    }

                    // Push to TUN queue
                    {
                        std::lock_guard<std::mutex> ql(g_tunq_mx);
                        g_to_tun_q.push_back(TunFrame{buf});
                    }
                    g_tunq_cv.notify_one();
                }
            });
        }

        // Send one framed payload to this client.
        void Send(const uint8_t* data, size_t len)
        {
            auto self = shared_from_this();
            boost::asio::post(g_server_io, [self, p = std::vector<uint8_t>(data, data + len)]() mutable
            {
                if (!self->alive.load())
                    return;
                boost::system::error_code ec;
                if (!WriteFrame(self->tls, p.data(), p.size(), ec))
                {
                    LogWarn("server.up", std::string("write error: ") + ec.message());
                    // Do not close; just keep alive flag; next writes may fail again.
                }
            });
        }

        void Close()
        {
            alive.store(false);
            boost::system::error_code ignored;
            self_shutdown(ignored);
        }

        void self_shutdown(boost::system::error_code& ignored)
        {
            boost::system::error_code ec1;
            tls.shutdown(ec1); // TLS close_notify
            boost::system::error_code ec2;
            tls.lowest_layer().shutdown(tcp::socket::shutdown_both, ec2);
            boost::system::error_code ec3;
            tls.lowest_layer().close(ec3);
        }
    };

    // Accept loop (runs in server io threads)
    static void ServerAcceptLoop(std::shared_ptr<bool> accepting_guard)
    {
        if (!g_server_acceptor) return;

        auto new_sess = std::make_shared<ServerSession>(*g_server_ssl);
        g_server_acceptor->async_accept(new_sess->tls.lowest_layer(),
                                        [accepting_guard, new_sess](const boost::system::error_code& ec)
                                        {
                                            if (ec)
                                            {
                                                LogWarn("server", std::string("accept error: ") + ec.message());
                                            }
                                            else
                                            {
                                                {
                                                    std::lock_guard<std::mutex> lk(g_sess_mx);
                                                    g_sessions.insert(new_sess);
                                                }
                                                new_sess->Start();
                                            }

                                            // Continue accepting
                                            ServerAcceptLoop(accepting_guard);
                                        });
    }

    // Send frame from server's TUN to a specific client (by dst IPv4)
    static void ServerSendToClientByDst(const uint8_t* data, size_t len)
    {
        uint32_t src_be = 0, dst_be = 0;
        if (!ParseIPv4SrcDst(data, len, src_be, dst_be))
        {
            LogWarn("server.up", "non-IPv4 packet from TUN; dropped");
            return;
        }

        std::shared_ptr<ServerSession> target;
        {
            std::lock_guard<std::mutex> lk(g_sess_mx);
            auto it = g_ip_to_session.find(dst_be);
            if (it != g_ip_to_session.end())
            {
                target = it->second.lock();
                if (!target)
                {
                    g_ip_to_session.erase(it);
                }
            }
        }
        if (target)
        {
            target->Send(data, len);
        }
        else
        {
            // No mapping yet; drop (strict "only to intended client" rule).
            struct in_addr ina;
            ina.s_addr = dst_be;
            LogWarn("server.up", std::string("no session for dst=") + inet_ntoa(ina) + "; dropped");
        }
    }
} // anonymous namespace

PLUGIN_API bool Client_Connect(const std::string &server_ip, std::uint16_t port) noexcept
{
    try
    {
        std::lock_guard<std::mutex> lk(g_client_mx);
        if (!g_client_ssl)
        {
            g_client_ssl = std::make_unique<ssl::context>(ssl::context::tls_client);
            if (!ConfigureSSLContext(*g_client_ssl, false))
                return false;
        }

        g_client_tls = std::make_shared<ssl::stream<tcp::socket>>(g_client_io, *g_client_ssl);
        boost::system::error_code ec;

        tcp::resolver resolver(g_client_io);
        auto results = resolver.resolve(server_ip, std::to_string(port), ec);
        if (ec)
        {
            LogErr("client", std::string("resolve failed: ") + ec.message());
            return false;
        }

        boost::asio::connect(g_client_tls->lowest_layer(), results, ec);
        if (ec)
        {
            LogErr("client", std::string("connect failed: ") + ec.message());
            return false;
        }

        g_client_tls->set_verify_mode(ssl::verify_peer);
        g_client_tls->lowest_layer().set_option(tcp::no_delay(true));

        g_client_tls->handshake(ssl::stream_base::client, ec);
        if (ec)
        {
            LogErr("client", std::string("TLS handshake failed: ") + ec.message());
            return false;
        }
        LogInfo("client", "TLS handshake complete (client)");

        g_client_connected.store(true);
        return true;
    }
    catch (const std::exception& e)
    {
        LogErr("client", std::string("exception in Client_Connect: ") + e.what());
        return false;
    }
}

PLUGIN_API void Client_Disconnect() noexcept
{
    std::lock_guard<std::mutex> lk(g_client_mx);
    if (!g_client_tls) return;

    boost::system::error_code ec1, ec2, ec3;
    g_client_tls->shutdown(ec1);
    g_client_tls->lowest_layer().shutdown(tcp::socket::shutdown_both, ec2);
    g_client_tls->lowest_layer().close(ec3);
    g_client_connected.store(false);
    LogInfo("client", "disconnected");
}

PLUGIN_API int Client_Serve(
        const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
        const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
        const volatile sig_atomic_t *working_flag) noexcept
{
    if (!working_flag)
    {
        LogErr("client", "working_flag is null");
        return -1;
    }
    if (!g_client_tls)
    {
        LogErr("client", "not connected");
        return -2;
    }

    std::atomic<bool> run{true};

    // Uplink thread: TUN -> server
    std::thread up_thr([&]
                       {
                           std::vector<uint8_t> buf(65536);
                           while (run.load())
                           {
                               if (*working_flag == 0) break;
                               ssize_t n = receive_from_net(buf.data(), buf.size());
                               if (n <= 0)
                               {
                                   SleepMs(10);
                                   continue;
                               }
                               boost::system::error_code ec;
                               if (!WriteFrame(*g_client_tls, buf.data(), static_cast<size_t>(n), ec))
                               {
                                   LogWarn("client.up", std::string("write error ") + ec.message());
                                   SleepMs(50);
                                   continue;
                               }
                           }
                       });

    // Downlink thread: server -> TUN
    std::thread down_thr([&]
                         {
                             std::vector<uint8_t> frame;
                             while (run.load())
                             {
                                 if (*working_flag == 0) break;
                                 boost::system::error_code ec;
                                 bool ok = ReadFrame(*g_client_tls, frame, ec);
                                 if (!ok)
                                 {
                                     SleepMs(50);
                                     continue;
                                 }
                                 ssize_t w = send_to_net(frame.data(), frame.size());
                                 if (w < 0)
                                 {
                                     LogWarn("client.down", "send_to_net returned error");
                                     // continue
                                 }
                             }
                         });

    // Busy-wait loop to keep this call blocking
    while (*working_flag)
    {
        SleepMs(50);
    }

    run.store(false);
    try { if (up_thr.joinable()) up_thr.join(); } catch (...) {}
    try { if (down_thr.joinable()) down_thr.join(); } catch (...) {}

    LogInfo("client", "Serve end rc=0");
    return 0;
}

PLUGIN_API bool Server_Bind(std::uint16_t port) noexcept
{
    try
    {
        if (!g_server_ssl)
        {
            g_server_ssl = std::make_unique<ssl::context>(ssl::context::tls_server);
            if (!ConfigureSSLContext(*g_server_ssl, true))
                return false;
        }

        if (!g_server_acceptor)
        {
            g_server_acceptor = std::make_unique<tcp::acceptor>(g_server_io);
        }

        tcp::endpoint ep(tcp::v4(), port);
        boost::system::error_code ec;
        g_server_acceptor->open(ep.protocol(), ec);
        if (ec) { LogErr("server", std::string("acceptor open: ") + ec.message()); return false; }

        g_server_acceptor->set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec) { LogWarn("server", std::string("reuse_address: ") + ec.message()); }

        g_server_acceptor->bind(ep, ec);
        if (ec) { LogErr("server", std::string("bind: ") + ec.message()); return false; }

        g_server_acceptor->listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) { LogErr("server", std::string("listen: ") + ec.message()); return false; }

        // Start io threads (choose count ~ hardware concurrency)
        if (g_server_threads.empty())
        {
            unsigned n = std::max(2u, std::thread::hardware_concurrency());
            for (unsigned i = 0; i < n; ++i)
            {
                g_server_threads.emplace_back([]
                                              {
                                                  try { g_server_io.run(); }
                                                  catch (const std::exception& e) { LogErr("server", std::string("io thread exception: ") + e.what()); }
                                              });
            }
        }

        // Begin accepting
        ServerAcceptLoop(std::make_shared<bool>(true));
        LogInfo("server", "listening");
        return true;
    }
    catch (const std::exception& e)
    {
        LogErr("server", std::string("exception in Server_Bind: ") + e.what());
        return false;
    }
}

PLUGIN_API int Server_Serve(
        const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
        const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
        const volatile sig_atomic_t *working_flag) noexcept
{
    if (!working_flag)
    {
        LogErr("server", "working_flag is null");
        return -1;
    }
    g_server_working_flag = working_flag;

    // Thread 1: dequeue frames from clients and write to TUN
    std::atomic<bool> run{true};
    std::thread to_tun_thread([&]
                              {
                                  while (run.load())
                                  {
                                      if (*working_flag == 0) break;

                                      std::unique_lock<std::mutex> lk(g_tunq_mx);
                                      if (g_to_tun_q.empty())
                                      {
                                          g_tunq_cv.wait_for(lk, std::chrono::milliseconds(50));
                                          if (g_to_tun_q.empty())
                                              continue;
                                      }
                                      TunFrame f = std::move(g_to_tun_q.front());
                                      g_to_tun_q.pop_front();
                                      lk.unlock();

                                      ssize_t w = send_to_net(f.data.data(), f.data.size());
                                      if (w < 0)
                                      {
                                          LogWarn("server.down", "send_to_net returned error");
                                      }
                                  }
                              });

    // Thread 2: read from TUN and route only to intended client
    std::thread from_tun_thread([&]
                                {
                                    std::vector<uint8_t> buf(65536);
                                    while (run.load())
                                    {
                                        if (*working_flag == 0) break;
                                        ssize_t n = receive_from_net(buf.data(), buf.size());
                                        if (n <= 0)
                                        {
                                            SleepMs(10);
                                            continue;
                                        }
                                        ServerSendToClientByDst(buf.data(), static_cast<size_t>(n));
                                    }
                                });

    // Keep this call blocking
    while (*working_flag)
    {
        SleepMs(50);
    }

    run.store(false);
    g_server_working_flag = nullptr;

    try { if (to_tun_thread.joinable()) to_tun_thread.join(); } catch (...) {}
    try { if (from_tun_thread.joinable()) from_tun_thread.join(); } catch (...) {}

    // Stop accepting new clients and close sessions gracefully
    try
    {
        if (g_server_acceptor)
        {
            boost::system::error_code ec;
            g_server_acceptor->close(ec);
        }
    }
    catch (...) {}

    {
        std::lock_guard<std::mutex> lk(g_sess_mx);
        for (auto& s : g_sessions)
        {
            if (s) s->alive.store(false);
        }
    }

    // Stop io context
    try { g_server_io.stop(); } catch (...) {}

    for (auto& t : g_server_threads)
    {
        try { if (t.joinable()) t.join(); } catch (...) {}
    }
    g_server_threads.clear();

    LogInfo("server", "Serve end rc=0");
    return 0;
}
