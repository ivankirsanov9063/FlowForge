#include "Core/Plugins/PlugDTLS/PlugDTLS.hpp"

#include "Core/Plugins/Vip.hpp"  // VipKey, MakeVipKeyFromSrc/Dst
#include <array>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <iostream>
#include <memory>
#include <cstdlib>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  define CLOSESOCK ::closesocket
   using socklen_t = int;
   static bool g_wsa_init = false;
   static void EnsureWsa()
   {
       if (!g_wsa_init)
       {
           WSADATA wsa;
           WSAStartup(MAKEWORD(2,2), &wsa);
           g_wsa_init = true;
       }
   }
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/time.h>
#  define CLOSESOCK ::close
#endif

namespace
{
    constexpr std::size_t BUF_CAP = 65536;
    constexpr long DTLS_MTU = 1200;

    inline void SetNonBlocking(int fd)
    {
#if defined(_WIN32)
        u_long mode = 1;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
    }

    inline void SetReuse(int fd)
    {
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
#if defined(SO_REUSEPORT)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char*)&yes, sizeof(yes));
#endif
    }

    inline void OpensslOnce()
    {
        static std::once_flag once;
        std::call_once(once, []
        {
            SSL_library_init();
            OpenSSL_add_ssl_algorithms();
            SSL_load_error_strings();
        });
    }

    inline void LogLastSsl(const char *tag)
    {
        unsigned long e = ERR_get_error();
        if (e)
        {
            char buf[256]{};
            ERR_error_string_n(e, buf, sizeof(buf));
            std::cerr << "[" << tag << "] " << buf << "\n";
        }
    }

    // Эфемерный self-signed для сервера (если нет CVPN_CERT/CVPN_KEY)
    bool GenerateSelfSigned(SSL_CTX *ctx)
    {
        EVP_PKEY *pkey = EVP_PKEY_new();
        RSA *rsa = RSA_new();
        BIGNUM *bn = BN_new();
        if (!pkey || !rsa || !bn) return false;
        BN_set_word(bn, RSA_F4);
        if (RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) { BN_free(bn); RSA_free(rsa); EVP_PKEY_free(pkey); return false; }
        BN_free(bn);
        EVP_PKEY_assign_RSA(pkey, rsa);

        X509 *x = X509_new();
        if (!x) { EVP_PKEY_free(pkey); return false; }
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_gmtime_adj(X509_get_notBefore(x), 0);
        X509_gmtime_adj(X509_get_notAfter(x), 60*60*24);
        X509_set_pubkey(x, pkey);

        X509_NAME *name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"XX", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"DTLS-Plugin", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
        X509_set_issuer_name(x, name);

        if (!X509_sign(x, pkey, EVP_sha256()))
        {
            X509_free(x); EVP_PKEY_free(pkey); return false;
        }

        if (SSL_CTX_use_certificate(ctx, x) != 1 ||
            SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
        {
            X509_free(x); EVP_PKEY_free(pkey);
            LogLastSsl("selfsigned");
            return false;
        }

        X509_free(x);
        EVP_PKEY_free(pkey);
        return true;
    }

    // -------- Client state --------
    struct ClientState
    {
        int      fd {-1};
        SSL_CTX *ctx {nullptr};
        SSL     *ssl {nullptr};
        sockaddr_in server{};   // IPv4 only
        socklen_t   server_len {sizeof(sockaddr_in)};
    };

    std::unique_ptr<ClientState> g_client;

    // -------- Server state --------
    struct DtlsSession
    {
        int      fd {-1};
        SSL     *ssl {nullptr};
        VipKey   vip{}; // последний VIP, замеченный по uplink
    };

    struct ServerState
    {
        int      listen_fd {-1};   // AF_INET
        SSL_CTX *ctx {nullptr};
        std::vector<std::shared_ptr<DtlsSession>> all_sessions;
        std::uint16_t port {0};
    };

    std::unique_ptr<ServerState> g_server;

    // --- helpers ---

    // Только IPv4
    bool ResolvePeerIPv4(const std::string &ip, std::uint16_t port, sockaddr_in &out)
    {
        std::memset(&out, 0, sizeof(out));
        out.sin_family = AF_INET;
        out.sin_port   = htons(port);
        if (::inet_pton(AF_INET, ip.c_str(), &out.sin_addr) != 1)
        {
            // fallback через getaddrinfo (вдруг hostname)
            addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM; hints.ai_protocol = IPPROTO_UDP;
            addrinfo *res = nullptr;
            char portstr[16]; std::snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
            int rc = getaddrinfo(ip.c_str(), portstr, &hints, &res);
            if (rc != 0 || !res) return false;
            auto *sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
            out = *sa;
            freeaddrinfo(res);
        }
        return true;
    }

    static int CreateUdpIPv4()
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        SetReuse(fd);
        SetNonBlocking(fd);
        return fd;
    }

    static int CreateListenIPv4(std::uint16_t port)
    {
        int fd = CreateUdpIPv4();
        if (fd < 0) return -1;
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY); sa.sin_port = htons(port);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0)
        {
            CLOSESOCK(fd);
            return -1;
        }
        return fd;
    }

    // SSL_read -> send_to_net
    int DrainSslToNet(SSL *ssl,
                      const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net)
    {
        std::uint8_t buf[BUF_CAP];
        int pushed = 0;
        for (;;)
        {
            int n = SSL_read(ssl, buf, (int)sizeof(buf));
            if (n > 0)
            {
                (void)send_to_net(buf, (std::size_t)n);
                pushed += n;
                continue;
            }
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                break;
            if (err == SSL_ERROR_ZERO_RETURN)
                break;
            LogLastSsl("ssl_read");
            break;
        }
        return pushed;
    }

    // receive_from_net -> SSL_write
    int DrainNetToSsl(SSL *ssl,
                      const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net)
    {
        std::uint8_t buf[BUF_CAP];
        int pulled = 0;
        for (;;)
        {
            ssize_t rn = receive_from_net(buf, sizeof(buf));
            if (rn <= 0) break;
            int n = SSL_write(ssl, buf, (int)rn);
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    break;
                LogLastSsl("ssl_write");
                break;
            }
            pulled += n;
        }
        return pulled;
    }

} // namespace

// ==================== CLIENT (IPv4 only) ====================

PLUGIN_API bool Client_Connect(const std::string &server_ip, std::uint16_t port) noexcept
{
#if defined(_WIN32)
    EnsureWsa();
#endif
    try
    {
        OpensslOnce();
        auto st = std::make_unique<ClientState>();

        if (!ResolvePeerIPv4(server_ip, port, st->server)) {
            std::cerr << "[dtls-client] resolve IPv4 failed\n";
            return false;
        }

        st->fd = CreateUdpIPv4();
        if (st->fd < 0) {
            std::cerr << "[dtls-client] socket() failed\n";
            return false;
        }

        if (::connect(st->fd, reinterpret_cast<sockaddr*>(&st->server), sizeof(st->server)) != 0) {
            std::cerr << "[dtls-client] connect() failed, errno=" << errno << "\n";
            CLOSESOCK(st->fd);
            return false;
        }

        st->ctx = SSL_CTX_new(DTLS_client_method());
        if (!st->ctx) {
            std::cerr << "[dtls-client] SSL_CTX_new failed\n";
            CLOSESOCK(st->fd);
            return false;
        }
        SSL_CTX_set_verify(st->ctx, SSL_VERIFY_NONE, nullptr); // включим verify при необходимости

        st->ssl = SSL_new(st->ctx);
        if (!st->ssl) {
            std::cerr << "[dtls-client] SSL_new failed\n";
            SSL_CTX_free(st->ctx);
            CLOSESOCK(st->fd);
            return false;
        }

        BIO *bio = BIO_new_dgram(st->fd, BIO_NOCLOSE);
        if (!bio) {
            std::cerr << "[dtls-client] BIO_new_dgram failed\n";
            SSL_free(st->ssl);
            SSL_CTX_free(st->ctx);
            CLOSESOCK(st->fd);
            return false;
        }

        // BIO connected к конкретному пиру (IPv4)
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &st->server);

        SSL_set_bio(st->ssl, bio, bio);
        SSL_set_mtu(st->ssl, DTLS_MTU);
        DTLS_set_link_mtu(st->ssl, DTLS_MTU);
        SSL_set_connect_state(st->ssl);

        // Handshake (неблокирующий цикл)
        for (;;) {
            int rc = SSL_do_handshake(st->ssl);
            if (rc == 1) break;
            int err = SSL_get_error(st->ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }
            std::cerr << "[dtls-client] handshake failed, err=" << err << "\n";
            LogLastSsl("client_handshake");
            SSL_free(st->ssl); st->ssl = nullptr;
            SSL_CTX_free(st->ctx); st->ctx = nullptr;
            CLOSESOCK(st->fd); st->fd = -1;
            return false;
        }

        g_client = std::move(st);
        return true;
    }
    catch (...) { return false; }
}

PLUGIN_API void Client_Disconnect() noexcept
{
    if (!g_client) return;
    if (g_client->ssl) { SSL_shutdown(g_client->ssl); SSL_free(g_client->ssl); g_client->ssl = nullptr; }
    if (g_client->ctx) { SSL_CTX_free(g_client->ctx); g_client->ctx = nullptr; }
    if (g_client->fd  != -1) { CLOSESOCK(g_client->fd); g_client->fd = -1; }
    g_client.reset();
}

PLUGIN_API int Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                            const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                            const volatile sig_atomic_t *working_flag) noexcept
{
    if (!g_client || !g_client->ssl) return -1;
    int total = 0;
    while (!working_flag || *working_flag)
    {
        int n1 = DrainSslToNet(g_client->ssl, send_to_net);
        int n2 = DrainNetToSsl(g_client->ssl, receive_from_net);
        total += n1 + n2;
        if (n1 == 0 && n2 == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return total;
}

// ==================== SERVER (IPv4 only) ====================

PLUGIN_API bool Server_Bind(std::uint16_t port) noexcept
{
#if defined(_WIN32)
    EnsureWsa();
#endif
    try
    {
        OpensslOnce();
        auto st = std::make_unique<ServerState>();
        st->listen_fd = CreateListenIPv4(port);
        if (st->listen_fd < 0)
        {
            std::cerr << "[dtls-server] listen socket/bind failed\n";
            return false;
        }

        st->ctx = SSL_CTX_new(DTLS_server_method());
        if (!st->ctx)
        {
            std::cerr << "[dtls-server] SSL_CTX_new failed\n";
            CLOSESOCK(st->listen_fd);
            return false;
        }

        // Загружаем cert/key если заданы, иначе — self-signed
        const char *cert = std::getenv("CVPN_CERT");
        const char *key  = std::getenv("CVPN_KEY");
        if (cert && key && *cert && *key)
        {
            if (SSL_CTX_use_certificate_chain_file(st->ctx, cert) != 1 ||
                SSL_CTX_use_PrivateKey_file(st->ctx, key, SSL_FILETYPE_PEM) != 1)
            {
                std::cerr << "[dtls-server] cert/key load failed\n";
                LogLastSsl("server_cert");
                SSL_CTX_free(st->ctx);
                CLOSESOCK(st->listen_fd);
                return false;
            }
        }
        else
        {
            if (!GenerateSelfSigned(st->ctx))
            {
                std::cerr << "[dtls-server] self-signed generation failed\n";
                SSL_CTX_free(st->ctx);
                CLOSESOCK(st->listen_fd);
                return false;
            }
        }

        st->port = port;
        g_server = std::move(st);
        return true;
    }
    catch (...) { return false; }
}

// Корректный accept для DTLS (IPv4) с DTLSv1_listen и BIO_ADDR
static bool AcceptOneDtlsClient(ServerState &S)
{
    SSL *probe = SSL_new(S.ctx);
    if (!probe) return false;

    BIO *probe_bio = BIO_new_dgram(S.listen_fd, BIO_NOCLOSE);
    if (!probe_bio) { SSL_free(probe); return false; }

    // Неблокирующее ожидание
    timeval tv; tv.tv_sec = 0; tv.tv_usec = 1000; // 1 ms
    BIO_ctrl(probe_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv);
    SSL_set_bio(probe, probe_bio, probe_bio);

    BIO_ADDR *peer = BIO_ADDR_new();
    if (!peer) { SSL_free(probe); return false; }

    int rc = DTLSv1_listen(probe, peer);
    if (rc <= 0)
    {
        BIO_ADDR_free(peer);
        SSL_free(probe);
        return false; // сейчас нечего принимать
    }

    if (BIO_ADDR_family(peer) != AF_INET)
    {
        // Мы работаем только по IPv4
        BIO_ADDR_free(peer);
        SSL_free(probe);
        return false;
    }

    // Создаём сессионный сокет IPv4
    int fd = CreateUdpIPv4();
    if (fd < 0) { BIO_ADDR_free(peer); SSL_free(probe); return false; }

    // Биндимся на тот же порт (если нельзя — на эфемерный)
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY); sa.sin_port = htons(S.port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        sa.sin_port = htons(0);
        ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    }

    // connect к peer
    unsigned char addrbuf[4]; size_t alen = sizeof(addrbuf);
    BIO_ADDR_rawaddress(peer, addrbuf, &alen);
    unsigned short p = BIO_ADDR_rawport(peer);
    sockaddr_in peer4{}; peer4.sin_family = AF_INET; peer4.sin_port = htons(p);
    std::memcpy(&peer4.sin_addr, addrbuf, 4);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&peer4), sizeof(peer4)) != 0) {
        CLOSESOCK(fd); BIO_ADDR_free(peer); SSL_free(probe); return false;
    }

    // Создаём SSL на сессионном сокете
    SSL *sess_ssl = SSL_new(S.ctx);
    if (!sess_ssl) { BIO_ADDR_free(peer); SSL_free(probe); CLOSESOCK(fd); return false; }
    BIO *sess_bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!sess_bio) { SSL_free(sess_ssl); BIO_ADDR_free(peer); SSL_free(probe); CLOSESOCK(fd); return false; }

    // Важно: установить connected-пира для BIO (DTLS)
    BIO_ctrl(sess_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer4);

    SSL_set_bio(sess_ssl, sess_bio, sess_bio);
    SSL_set_mtu(sess_ssl, DTLS_MTU);
    DTLS_set_link_mtu(sess_ssl, DTLS_MTU);
    SSL_set_accept_state(sess_ssl);

    // Handshake
    for (;;)
    {
        int h = SSL_do_handshake(sess_ssl);
        if (h == 1) break;
        int err = SSL_get_error(sess_ssl, h);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        LogLastSsl("server_accept");
        SSL_free(sess_ssl); CLOSESOCK(fd); BIO_ADDR_free(peer); SSL_free(probe);
        return false;
    }

    auto sess = std::make_shared<DtlsSession>();
    sess->fd  = fd;
    sess->ssl = sess_ssl;
    S.all_sessions.emplace_back(sess);

    BIO_ADDR_free(peer);
    SSL_free(probe);
    return true;
}

PLUGIN_API int Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                            const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                            const volatile sig_atomic_t *working_flag) noexcept
{
    if (!g_server || g_server->listen_fd < 0 || !g_server->ctx) return -1;
    int total = 0;

    std::uint8_t tmp[BUF_CAP];

    while (!working_flag || *working_flag)
    {
        // Новые клиенты — оппортунистически
        AcceptOneDtlsClient(*g_server);

        // Uplink из каждой сессии -> хост
        for (auto it = g_server->all_sessions.begin(); it != g_server->all_sessions.end(); )
        {
            auto &sess = *it;
            if (!sess || !sess->ssl)
            {
                it = g_server->all_sessions.erase(it);
                continue;
            }

            bool alive = true;
            for (;;)
            {
                int n = SSL_read(sess->ssl, tmp, (int)sizeof(tmp));
                if (n > 0)
                {
                    (void)send_to_net(tmp, (std::size_t)n);

                    VipKey key{};
                    if (MakeVipKeyFromSrc(tmp, (std::size_t)n, key))
                        sess->vip = key;

                    total += n;
                    continue;
                }
                int err = SSL_get_error(sess->ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    break;
                if (err == SSL_ERROR_ZERO_RETURN)
                {
                    SSL_free(sess->ssl); sess->ssl = nullptr;
                    CLOSESOCK(sess->fd); sess->fd = -1;
                    sess.reset();
                    alive = false;
                    break;
                }
                LogLastSsl("server_read");
                break;
            }
            if (!alive) it = g_server->all_sessions.erase(it);
            else ++it;
        }

        // Downlink из хоста -> нужной сессии по VIP dst
        for (;;)
        {
            ssize_t rn = receive_from_net(tmp, sizeof(tmp));
            if (rn <= 0) break;

            VipKey dst{};
            if (!MakeVipKeyFromDst(tmp, (std::size_t)rn, dst))
            {
                // нет маршрута — дроп
                continue;
            }

            std::shared_ptr<DtlsSession> target;
            for (auto &s : g_server->all_sessions)
            {
                if (s && s->ssl && s->vip == dst)
                {
                    target = s;
                    break;
                }
            }
            if (!target) continue;

            int wn = SSL_write(target->ssl, tmp, (int)rn);
            if (wn <= 0)
            {
                int err = SSL_get_error(target->ssl, wn);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    LogLastSsl("server_write");
                continue;
            }
            total += wn;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Cleanup
    for (auto &s : g_server->all_sessions)
    {
        if (s && s->ssl) { SSL_shutdown(s->ssl); SSL_free(s->ssl); s->ssl = nullptr; }
        if (s && s->fd  != -1) { CLOSESOCK(s->fd); s->fd = -1; }
    }
    g_server->all_sessions.clear();
    return total;
}
