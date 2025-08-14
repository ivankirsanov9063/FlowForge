#include "Plugin.hpp"

#include <boost/asio.hpp>

#include <cstring>
#include <deque>
#include <array>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <memory>

#include <cstdarg>
#include <cstdio>

static inline void vlog_print(const char* lvl, const char* fmt, va_list ap) {
    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);
#if defined(_WIN32)
    std::fprintf(stderr, "[%s] %s\n", lvl, msg);
    OutputDebugStringA("["); OutputDebugStringA(lvl); OutputDebugStringA("] ");
    OutputDebugStringA(msg); OutputDebugStringA("\n");
#else
    std::fprintf(stderr, "[%s] %s\n", lvl, msg);
#endif
}

static inline void log_print(const char* lvl, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); vlog_print(lvl, fmt, ap); va_end(ap);
}

#define LOGE(...) log_print("E", __VA_ARGS__)
#define LOGW(...) log_print("W", __VA_ARGS__)
#define LOGI(...) log_print("I", __VA_ARGS__)

// ===== cross-platform socket bits =====
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <BaseTsd.h>
  #ifndef ssize_t
  using ssize_t = SSIZE_T;
  #endif
  using socklen_t = int;
  #pragma comment(lib, "Ws2_32.lib")

  static void wsa_init_once() {
      static std::once_flag once;
      std::call_once(once, []{
          WSADATA w{};
          WSAStartup(MAKEWORD(2,2), &w);
      });
  }
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
#endif

using boost::asio::ip::udp;

namespace iphelpers
{
    inline bool ExtractIPv4Src(const std::uint8_t *p,
                               std::size_t n,
                               std::uint32_t &out_host) noexcept
    {
        if (n < 20 || (p[0] >> 4) != 4) return false;
        std::size_t ihl = (p[0] & 0x0Fu) * 4u;
        if (ihl < 20 || n < ihl) return false;
        std::uint32_t src;
        std::memcpy(&src, p + 12, 4);
        out_host = ntohl(src);
        return true;
    }

    inline bool ExtractIPv4Dst(const std::uint8_t *p,
                               std::size_t n,
                               std::uint32_t &out_host) noexcept
    {
        if (n < 20 || (p[0] >> 4) != 4) return false;
        std::size_t ihl = (p[0] & 0x0Fu) * 4u;
        if (ihl < 20 || n < ihl) return false;
        std::uint32_t dst;
        std::memcpy(&dst, p + 16, 4);
        out_host = ntohl(dst);
        return true;
    }

    inline bool ExtractIPv6Src(const std::uint8_t *p,
                               std::size_t n,
                               std::array<std::uint8_t, 16> &out) noexcept
    {
        if (n < 40 || ((p[0] >> 4) != 6)) return false;
        std::memcpy(out.data(), p + 8, 16);
        return true;
    }

    inline bool ExtractIPv6Dst(const std::uint8_t *p,
                               std::size_t n,
                               std::array<std::uint8_t, 16> &out) noexcept
    {
        if (n < 40 || ((p[0] >> 4) != 6)) return false;
        std::memcpy(out.data(), p + 24, 16);
        return true;
    }
}

// ===================== CLIENT (async UDP) =====================
namespace ClientSide
{
    constexpr std::size_t BufCap     = 65536;
    constexpr unsigned    IoThreads  = 1;

    std::unique_ptr<boost::asio::io_context> io;

    using WorkGuard =
        boost::asio::executor_work_guard<
            boost::asio::io_context::executor_type>;

    std::unique_ptr<WorkGuard> work;
    std::vector<std::thread>   threads;

    std::unique_ptr<udp::socket> sock;
    udp::endpoint                server_ep;

    std::mutex              m_rx;
    std::deque<std::string> q_rx;

    std::mutex              m_tx;
    std::deque<std::string> q_tx;
    bool                    tx_in_flight = false;

    inline void StopIo()
    {
        if (work) { work->reset(); work.reset(); }
        if (io) io->stop();
        for (auto &t : threads) if (t.joinable()) t.join();
        threads.clear();

        if (sock && sock->is_open())
        {
            boost::system::error_code ec;
            sock->close(ec);
        }
        sock.reset();
        io.reset();

        { std::lock_guard<std::mutex> lk(m_rx); q_rx.clear(); }
        { std::lock_guard<std::mutex> lk(m_tx); q_tx.clear(); tx_in_flight = false; }
    }

    inline void KickSendLocked()
    {
        LOGI("kick: sock=%s inflight=%d q=%zu", sock ? "ok":"null", (int)tx_in_flight, q_tx.size());

        if (tx_in_flight || !sock) return;
        if (q_tx.empty()) return;

        tx_in_flight = true;
        std::string payload = std::move(q_tx.front());
        q_tx.pop_front();

        auto buf = std::make_shared<std::string>(std::move(payload));

        sock->async_send(
            boost::asio::buffer(*buf),
            [buf](const boost::system::error_code &ec, std::size_t n)
            {
                if (ec) {
                    LOGE("async_send -> ec=%d %s, sent=%zu", ec.value(), ec.message().c_str(), n);
                } else {
                    LOGI("async_send -> ok, sent=%zu bytes", n);
                }
                std::lock_guard<std::mutex> lk(m_tx);
                tx_in_flight = false;
                if (!ec && !q_tx.empty())
                    KickSendLocked();
            }
        );

    }

    inline void EnqueueTx(const std::uint8_t *p, std::size_t n)
    {
        std::lock_guard<std::mutex> lk(m_tx);
        q_tx.emplace_back(reinterpret_cast<const char *>(p),
                          reinterpret_cast<const char *>(p) + n);
        LOGI("enqueue: %zu bytes, q=%zu", n, q_tx.size());
        KickSendLocked();
    }

    inline void StartRecvLoop()
    {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(BufCap);

        sock->async_receive(
            boost::asio::buffer(*buf),
            [buf](const boost::system::error_code &ec, std::size_t n)
            {
                if (ec) {
                    LOGE("async_receive -> ec=%d %s", ec.value(), ec.message().c_str());
                } else if (n > 0) {
                    {
                        std::lock_guard<std::mutex> lk(m_rx);
                        q_rx.emplace_back(reinterpret_cast<const char *>(buf->data()),
                                          reinterpret_cast<const char *>(buf->data()) + n);
                    }
                    LOGI("async_receive -> got %zu bytes", n);
                }
                if (sock) StartRecvLoop();
            }
        );
    }

    inline bool Connect(const std::string &ip, std::uint16_t port) noexcept
    {
        try {
        #ifdef _WIN32
            wsa_init_once();
        #endif
            io = std::make_unique<boost::asio::io_context>();
            work = std::make_unique<WorkGuard>(boost::asio::make_work_guard(*io));

            boost::system::error_code ec;
            auto addr = boost::asio::ip::make_address(ip, ec);
            if (ec) {
                LOGE("make_address('%s') failed: %d %s", ip.c_str(), ec.value(), ec.message().c_str());
                StopIo(); return false;
            }

            sock = std::make_unique<udp::socket>(*io);

            if (addr.is_v6()) {
                sock->open(udp::v6(), ec);
                if (ec) { LOGE("udp::socket::open(v6) failed: %d %s", ec.value(), ec.message().c_str()); StopIo(); return false; }
                boost::asio::ip::v6_only v6only(false);
                boost::system::error_code ig;
                sock->set_option(v6only, ig); // игнорируем, но не критично
            } else {
                sock->open(udp::v4(), ec);
                if (ec) { LOGE("udp::socket::open(v4) failed: %d %s", ec.value(), ec.message().c_str()); StopIo(); return false; }
            }

            // (необязательно) увеличим буферы
            {
                boost::system::error_code ig;
                boost::asio::socket_base::receive_buffer_size rcv(1 << 20);
                boost::asio::socket_base::send_buffer_size    snd(1 << 20);
                sock->set_option(rcv, ig);
                sock->set_option(snd, ig);
            }

            server_ep = udp::endpoint{ addr, port };
            sock->connect(server_ep, ec);
            if (ec) {
                LOGE("udp::socket::connect(%s:%u) failed: %d %s",
                     ip.c_str(), (unsigned)port, ec.value(), ec.message().c_str());
                StopIo(); return false;
            }
            LOGI("Client connected to %s:%u", ip.c_str(), (unsigned)port);

            std::thread([]{
                for(;;){
                    static const char ping[] = "DBG";
                    boost::system::error_code ec;
                    if (ClientSide::sock)
                        ClientSide::sock->send(boost::asio::buffer(ping, sizeof(ping)), 0, ec);
                    if (ec) std::fprintf(stderr, "[E] heartbeat send failed: %d %s\n", ec.value(), ec.message().c_str());
                    else     std::fprintf(stderr, "[I] heartbeat sent\n");
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }).detach();

            StartRecvLoop();
            threads.reserve(IoThreads);
            for (unsigned i = 0; i < IoThreads; ++i)
                threads.emplace_back([&] { io->run(); });

            return true;
        } catch (const std::exception& e) {
            LOGE("Connect exception: %s", e.what());
            StopIo(); return false;
        } catch (...) {
            LOGE("Connect: unknown exception");
            StopIo(); return false;
        }
    }
}

// ===================== SERVER (async UDP, многоклиентный) =====================
namespace ServerSide
{
    constexpr std::size_t    BufCap             = 65536;
    constexpr unsigned       IoThreads          = 2;
    constexpr std::uint64_t  ClientTtlMs        = 5 * 60 * 1000; // 5 минут
    constexpr std::uint64_t  GcPeriodMs         = 5 * 1000;      // 5 сек
    constexpr std::size_t    MaxQueuePerClient  = 2048;

    std::unique_ptr<boost::asio::io_context> io;

    using WorkGuard =
        boost::asio::executor_work_guard<
            boost::asio::io_context::executor_type>;

    std::unique_ptr<WorkGuard> work;
    std::vector<std::thread>   threads;

    std::unique_ptr<udp::socket>               sock;
    std::unique_ptr<boost::asio::steady_timer> gc_timer;

    struct Client
    {
        udp::endpoint           ep;
        std::uint64_t           last_seen_ms = 0;
        std::deque<std::string> q_tx;
        bool                    tx_in_flight = false;
        std::mutex              mtx;
    };

    struct VipKey
    {
        bool                          v6 = false;
        std::uint32_t                 v4 = 0;
        std::array<std::uint8_t, 16>  v6addr{};

        static VipKey FromV4(std::uint32_t a) { VipKey k; k.v6=false; k.v4=a; return k; }
        static VipKey FromV6(const std::array<std::uint8_t, 16> &a)
        { VipKey k; k.v6=true; k.v6addr=a; return k; }

        bool operator==(const VipKey &o) const noexcept
        { return v6 ? (o.v6 && v6addr==o.v6addr) : (!o.v6 && v4==o.v4); }

        struct Hasher {
            std::size_t operator()(const VipKey &k) const noexcept
            {
                if (!k.v6) return std::hash<std::uint32_t>{}(k.v4);
                std::size_t h = 1469598103934665603ull; // FNV-1a
                for (auto b : k.v6addr) { h ^= b; h *= 1099511628211ull; }
                return h;
            }
        };
    };

    std::mutex              m_from;
    std::deque<std::string> from_clients;

    std::mutex m_clients;
    std::unordered_map<VipKey,
                       std::unique_ptr<Client>,
                       VipKey::Hasher> vip_to_client;

    inline std::uint64_t NowMs() noexcept
    {
        using namespace std::chrono;
        return static_cast<std::uint64_t>(
            duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    }

    static inline bool MakeVipKeyFromSrc(const std::uint8_t *p, std::size_t n, VipKey &out) noexcept
    {
        if (n < 1) return false;
        unsigned ver = (p[0] >> 4);
        if (ver == 4)
        {
            std::uint32_t v4{};
            if (!iphelpers::ExtractIPv4Src(p, n, v4)) return false;
            if ((v4 & 0xF0000000u) == 0xE0000000u || v4 == 0u) return false;
            out = VipKey::FromV4(v4);
            return true;
        }
        else if (ver == 6)
        {
            if (n < 40) return false;
            std::array<std::uint8_t, 16> v6{};
            if (!iphelpers::ExtractIPv6Src(p, n, v6)) return false;
            bool zero = true; for (auto b : v6) if (b) { zero=false; break; }
            if (zero || v6[0] == 0xFF) return false;
            out = VipKey::FromV6(v6);
            return true;
        }
        return false;
    }

    static inline bool MakeVipKeyFromDst(const std::uint8_t *p, std::size_t n, VipKey &out) noexcept
    {
        if (n < 1) return false;
        unsigned ver = (p[0] >> 4);
        if (ver == 4)
        {
            std::uint32_t v4{};
            if (!iphelpers::ExtractIPv4Dst(p, n, v4)) return false;
            if ((v4 & 0xF0000000u) == 0xE0000000u || v4 == 0u) return false;
            out = VipKey::FromV4(v4);
            return true;
        }
        else if (ver == 6)
        {
            if (n < 40) return false;
            std::array<std::uint8_t, 16> v6{};
            if (!iphelpers::ExtractIPv6Dst(p, n, v6)) return false;
            bool zero = true; for (auto b : v6) if (b) { zero=false; break; }
            if (zero || v6[0] == 0xFF) return false;
            out = VipKey::FromV6(v6);
            return true;
        }
        return false;
    }

    inline void StartRecvLoop()
    {
        auto buf  = std::make_shared<std::vector<std::uint8_t>>(BufCap);
        auto peer = std::make_shared<udp::endpoint>();

        sock->async_receive_from(
            boost::asio::buffer(*buf), *peer,
            [buf, peer](const boost::system::error_code &ec, std::size_t n)
            {
                if (!ec && n > 0)
                {
                    VipKey key{};
                    if (MakeVipKeyFromSrc(buf->data(), n, key))
                    {
                        std::lock_guard<std::mutex> lk(ServerSide::m_clients);
                        auto &cl_ptr = ServerSide::vip_to_client[key];
                        if (!cl_ptr) cl_ptr = std::make_unique<Client>();
                        cl_ptr->ep           = *peer;
                        cl_ptr->last_seen_ms = NowMs();
                    }

                    {
                        std::lock_guard<std::mutex> lk(ServerSide::m_from);
                        ServerSide::from_clients.emplace_back(
                            reinterpret_cast<const char *>(buf->data()),
                            reinterpret_cast<const char *>(buf->data()) + n
                        );
                    }
                }

                if (ServerSide::sock) StartRecvLoop();
            }
        );
    }

    inline void ContinueSend(VipKey vip)
    {
        std::unique_ptr<Client> *cl_slot = nullptr;
        {
            std::lock_guard<std::mutex> lk(m_clients);
            auto it = vip_to_client.find(vip);
            if (it == vip_to_client.end()) return;
            cl_slot = &it->second;
        }
        if (!cl_slot || !*cl_slot || !sock) return;

        Client &c = *(*cl_slot);

        std::string   payload;
        udp::endpoint ep;
        {
            std::lock_guard<std::mutex> lk(c.mtx);
            if (c.tx_in_flight || c.q_tx.empty()) return;
            c.tx_in_flight = true;
            payload        = std::move(c.q_tx.front());
            c.q_tx.pop_front();
            ep             = c.ep;
        }

        auto buf = std::make_shared<std::string>(std::move(payload));
        sock->async_send_to(
            boost::asio::buffer(*buf), ep,
            [buf, vip](const boost::system::error_code &ec, std::size_t)
            {
                std::unique_ptr<Client> *cl_slot2 = nullptr;
                {
                    std::lock_guard<std::mutex> lk(m_clients);
                    auto it = vip_to_client.find(vip);
                    if (it == vip_to_client.end()) return;
                    cl_slot2 = &it->second;
                }
                if (!cl_slot2 || !*cl_slot2) return;

                Client &c2 = *(*cl_slot2);
                bool has_more = false;
                {
                    std::lock_guard<std::mutex> lk2(c2.mtx);
                    c2.tx_in_flight = false;
                    has_more        = (!ec && !c2.q_tx.empty());
                }

                if (has_more && sock)
                    boost::asio::post(sock->get_executor(), [vip] { ContinueSend(vip); });
            }
        );
    }

    inline void EnqueueToClient(const std::uint8_t *p, std::size_t n)
    {
        VipKey key{};
        if (!MakeVipKeyFromDst(p, n, key)) return;

        std::unique_ptr<Client> *cl_slot = nullptr;
        {
            std::lock_guard<std::mutex> lk(m_clients);
            auto it = vip_to_client.find(key);
            if (it == vip_to_client.end()) return;
            cl_slot = &it->second;
        }
        if (!cl_slot || !*cl_slot) return;

        Client &c = *(*cl_slot);
        {
            std::lock_guard<std::mutex> lk(c.mtx);
            if (c.q_tx.size() >= MaxQueuePerClient) c.q_tx.pop_front();
            c.q_tx.emplace_back(reinterpret_cast<const char *>(p),
                                reinterpret_cast<const char *>(p) + n);
        }

        if (sock)
            boost::asio::post(sock->get_executor(), [key] { ContinueSend(key); });
    }

    inline std::uint64_t NowMsSafe() { return NowMs(); }

    inline void GcTick(const boost::system::error_code &ec)
    {
        if (ec || !gc_timer) return;
        const std::uint64_t now = NowMsSafe();

        {
            std::lock_guard<std::mutex> lk(m_clients);
            for (auto it = vip_to_client.begin(); it != vip_to_client.end();)
            {
                Client *c = it->second.get();
                if (!c || now - c->last_seen_ms > ClientTtlMs)
                    it = vip_to_client.erase(it);
                else
                    ++it;
            }
        }

        gc_timer->expires_after(std::chrono::milliseconds(GcPeriodMs));
        gc_timer->async_wait(GcTick);
    }

    inline bool Bind(std::uint16_t port) noexcept
    {
        try
        {
#ifdef _WIN32
            wsa_init_once();
#endif
            io = std::make_unique<boost::asio::io_context>();
            work = std::make_unique<WorkGuard>(boost::asio::make_work_guard(*io));

            sock = std::make_unique<udp::socket>(*io);
            boost::system::error_code ec;

            sock->open(udp::v6(), ec);
            {
                boost::system::error_code ig;
                boost::asio::socket_base::receive_buffer_size rcv(1 << 20);
                boost::asio::socket_base::send_buffer_size    snd(1 << 20);
                sock->set_option(rcv, ig);
                sock->set_option(snd, ig);
            }
            if (ec) throw 1;

            {
                boost::asio::ip::v6_only v6only(false);
                boost::system::error_code ig;
                sock->set_option(v6only, ig);
            }
            sock->bind(udp::endpoint(udp::v6(), port), ec);
            if (ec) throw 2;

            gc_timer = std::make_unique<boost::asio::steady_timer>(*io);
            StartRecvLoop();
            gc_timer->expires_after(std::chrono::milliseconds(GcPeriodMs));
            gc_timer->async_wait(GcTick);

            threads.reserve(IoThreads);
            for (unsigned i = 0; i < IoThreads; ++i)
                threads.emplace_back([&] { io->run(); });

            return true;
        }
        catch (...)
        {
            if (work) { work->reset(); work.reset(); }
            if (io) io->stop();
            for (auto &t : threads) if (t.joinable()) t.join();
            threads.clear();

            if (sock && sock->is_open()) { boost::system::error_code e; sock->close(e); }
            sock.reset();
            gc_timer.reset();
            io.reset();
            return false;
        }
    }

    inline void Stop()
    {
        if (work) { work->reset(); work.reset(); }
        if (io) io->stop();
        for (auto &t : threads) if (t.joinable()) t.join();
        threads.clear();

        if (sock && sock->is_open()) { boost::system::error_code ec; sock->close(ec); }
        sock.reset();
        gc_timer.reset();
        io.reset();

        { std::lock_guard<std::mutex> lk(m_from); from_clients.clear(); }
        { std::lock_guard<std::mutex> lk(m_clients); vip_to_client.clear(); }
    }

    inline bool DequeueFromClients(std::string &out)
    {
        std::lock_guard<std::mutex> lk(m_from);
        if (from_clients.empty()) return false;
        out = std::move(from_clients.front());
        from_clients.pop_front();
        return true;
    }
}

// ===================== C API (extern "C") =====================
extern "C"
{
    // ===== Client ABI =====
    void Client_Disconnect() noexcept
    { ClientSide::StopIo(); }

    bool Client_Connect(const std::string &server_ip, std::uint16_t port) noexcept
    {
        Client_Disconnect();
        return ClientSide::Connect(server_ip, port);
    }

    int Client_Serve(
        const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
        const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
        const volatile sig_atomic_t *working_flag) noexcept
    {
        if (!ClientSide::sock) return 1;

        std::array<std::uint8_t, ClientSide::BufCap> buf{};

        while (*working_flag)
        {
            for (;;)
            {
                ssize_t got = receive_from_net(buf.data(), buf.size());
                if (got > 0) {
                    LOGI("net->udp enqueue %zd bytes", got);
                    ClientSide::EnqueueTx(buf.data(), static_cast<std::size_t>(got));
                    continue;
                }
                if (got == 0) break;
                else { LOGE("receive_from_net error (got=%zd) -> stop", got); return 1; }
            }

            for (;;)
            {
                std::string pkt;
                {
                    std::lock_guard<std::mutex> lk(ClientSide::m_rx);
                    if (ClientSide::q_rx.empty()) break;
                    pkt = std::move(ClientSide::q_rx.front());
                    ClientSide::q_rx.pop_front();
                }
                if (!pkt.empty())
                {
                    auto snt = send_to_net(reinterpret_cast<const std::uint8_t *>(pkt.data()),
                       static_cast<std::size_t>(pkt.size()));
                    if (snt < 0) LOGE("send_to_net failed (ret=%zd)", snt);
                }
            }
        }
        return 0;
    }

    // ===== Server ABI =====
    bool Server_Bind(std::uint16_t port) noexcept
    { return ServerSide::Bind(port); }

    int Server_Serve(
        const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
        const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
        const volatile sig_atomic_t *working_flag) noexcept
    {
        if (!ServerSide::sock) return 1;

        std::array<std::uint8_t, ServerSide::BufCap> buf{};

        while (*working_flag)
        {
            for (;;)
            {
                std::string pkt;
                if (!ServerSide::DequeueFromClients(pkt)) break;
                if (!pkt.empty())
                {
                    (void) send_to_net(
                        reinterpret_cast<const std::uint8_t *>(pkt.data()),
                        static_cast<std::size_t>(pkt.size()));
                }
            }

            for (;;)
            {
                ssize_t got = receive_from_net(buf.data(), buf.size());
                if (got > 0)
                {
                    ServerSide::EnqueueToClient(buf.data(),
                                                static_cast<std::size_t>(got));
                    continue;
                }
                if (got == 0) break;
                else
                {
                    ServerSide::Stop();
                    return 1;
                }
            }
        }

        ServerSide::Stop();
        return 0;
    }
}
