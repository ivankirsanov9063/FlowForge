// Core/Plugins/PlugDTLS/PlugDTLS.cpp
// mbed TLS DTLS 1.2 over UDP (single-session client/server).
// Сертификат для сервера: переменные окружения CVPN_CERT / CVPN_KEY (PEM).
// Клиент по умолчанию не проверяет сертификат (как в исходнике на OpenSSL).

#include "Core/Plugins/PlugDTLS/PlugDTLS.hpp"

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <memory>

#ifdef _WIN32
#define NOMINMAX
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #ifndef CLOSESOCK
    #define CLOSESOCK closesocket
  #endif
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET
#define SOCKET int
#endif
#ifndef CLOSESOCK
#define CLOSESOCK ::close
#endif
#endif

// mbed TLS
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
// MBEDTLS_ERR_NET_* error codes live here
#include <mbedtls/net_sockets.h>
#include <mbedtls/timing.h>


// -------------------- Logging --------------------
#ifndef TAG
#define TAG "dtls"
#endif

static void vlogf(const char *lvl, const char *tag, const char *fmt, va_list ap)
{
    std::fprintf(stderr, "[%s] [%s] ", lvl, tag);
    std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
}

static void logf(const char *lvl, const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlogf(lvl, tag, fmt, ap);
    va_end(ap);
}

#define LOGD(...) logf("debug", TAG, __VA_ARGS__)
#define LOGI(...) logf("info ", TAG, __VA_ARGS__)
#define LOGW(...) logf("warn ", TAG, __VA_ARGS__)
#define LOGE(...) logf("error", TAG, __VA_ARGS__)

// -------------------- Helpers --------------------
static const char* errno_name(int e)
{
#ifdef _WIN32
    (void)e;
    return "WSAError";
#else
    // На некоторых платформах EAGAIN == EWOULDBLOCK, поэтому без switch/duplicate-case
    if (e == EAGAIN) return "EAGAIN";
#ifdef EWOULDBLOCK
    if (e == EWOULDBLOCK && EWOULDBLOCK != EAGAIN) return "EWOULDBLOCK";
#endif
    if (e == EINTR) return "EINTR";
    return "ERR";
#endif
}

static void set_nonblock(SOCKET fd)
{
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(fd, FIONBIO, &nb);
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#endif
}

static int last_sock_err()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static void msleep(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
#endif
}

static const char* mbed_err(int code, char *buf, size_t n)
{
    if (!buf || n == 0) return "mbed_err";
    mbedtls_strerror(code, buf, n);
    return buf;
}

static constexpr int DEFAULT_MTU = 1200;

// -------------------- BIO (send/recv) wrappers --------------------
struct UdpBio {
    SOCKET                   fd {INVALID_SOCKET};
    sockaddr_storage         peer{};
    socklen_t                peer_len {0};
    bool                     fixed_peer {false}; // true for client, false during server accept until we lock
};

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    UdpBio *b = static_cast<UdpBio*>(ctx);
    if (b->fd == INVALID_SOCKET) return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    if (b->peer_len == 0) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

    int rc = (int) ::sendto(b->fd, (const char*)buf, (int)len, 0,
                            (const sockaddr*)&b->peer, b->peer_len);
    if (rc >= 0) return rc;

    int e = last_sock_err();
#ifdef _WIN32
    if (e == WSAEWOULDBLOCK || e == WSAEINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
#else
    if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
    return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    UdpBio *b = static_cast<UdpBio*>(ctx);
    if (b->fd == INVALID_SOCKET) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    sockaddr_storage from{};
    socklen_t flen = sizeof(from);
    int rc = (int) ::recvfrom(b->fd, (char*)buf, (int)len, 0,
                              (sockaddr*)&from, &flen);
    if (rc >= 0) {
        // If server not yet pinned a peer — pin it to first sender to continue handshake.
        if (!b->fixed_peer && b->peer_len == 0) {
            b->peer     = from;
            b->peer_len = flen;
        }
        // If peer pinned and datagram from another address — ignore (pretend no data).
        if (b->peer_len && (std::memcmp(&b->peer, &from, std::min<size_t>(b->peer_len, flen)) != 0))
            return MBEDTLS_ERR_SSL_WANT_READ;

        return rc;
    }

    int e = last_sock_err();
#ifdef _WIN32
    if (e == WSAEWOULDBLOCK || e == WSAEINTR) return MBEDTLS_ERR_SSL_WANT_READ;
#else
    if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
#endif
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

// -------------------- mbed TLS wrappers --------------------
struct MbedCommon {
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  drbg;

    MbedCommon() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        const char *pers = "cvpn-dtls";
        int rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char*)pers, std::strlen(pers));
        if (rc != 0) {
            char buf[128];
            LOGE("ctr_drbg_seed: %s", mbed_err(rc, buf, sizeof(buf)));
        }
    }

    ~MbedCommon() {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
    }
};

struct DtlsClient : MbedCommon {
    mbedtls_ssl_config  conf;
    mbedtls_ssl_context ssl;
    UdpBio              bio;
    mbedtls_timing_delay_context timer;
    SOCKET              fd {INVALID_SOCKET};

    DtlsClient() {
        mbedtls_ssl_config_init(&conf);
        mbedtls_ssl_init(&ssl);
    }

    ~DtlsClient() {
        if (fd != INVALID_SOCKET) { CLOSESOCK(fd); fd = INVALID_SOCKET; }
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
    }
};

struct DtlsServer : MbedCommon {
    mbedtls_ssl_config     conf;
    mbedtls_x509_crt       cert;
    mbedtls_pk_context     key;
    mbedtls_ssl_cookie_ctx cookie;

    SOCKET                 fd {INVALID_SOCKET};

    DtlsServer() {
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cert);
        mbedtls_pk_init(&key);
        mbedtls_ssl_cookie_init(&cookie);
    }

    ~DtlsServer() {
        if (fd != INVALID_SOCKET) { CLOSESOCK(fd); fd = INVALID_SOCKET; }
        mbedtls_ssl_cookie_free(&cookie);
        mbedtls_pk_free(&key);
        mbedtls_x509_crt_free(&cert);
        mbedtls_ssl_config_free(&conf);
    }
};

static std::unique_ptr<DtlsClient> g_client;
static std::unique_ptr<DtlsServer> g_server;

static void winsock_once()
{
#ifdef _WIN32
    static std::atomic<bool> inited{false};
    bool expect = false;
    if (inited.compare_exchange_strong(expect, true)) {
        WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    }
#endif
}

// -------------------- DTLS handshake helpers --------------------
static int dtls_handshake_blocking(mbedtls_ssl_context &ssl, int total_timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(total_timeout_ms);

    int rc;
    do {
        rc = mbedtls_ssl_handshake(&ssl);
        if (rc == 0) return 0;
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (std::chrono::steady_clock::now() > deadline) return MBEDTLS_ERR_SSL_TIMEOUT;
            msleep(10);
            continue;
        }
        char buf[128];
        LOGE("handshake: %s", mbed_err(rc, buf, sizeof(buf)));
        return rc;
    } while (true);
}

// -------------------- Client --------------------
PLUGIN_API bool Client_Connect(const std::string &server_ip, std::uint16_t port) noexcept
{
    winsock_once();

    auto cli = std::make_unique<DtlsClient>();
    if (!cli) { LOGE("OOM"); return false; }

    int rc = mbedtls_ssl_config_defaults(&cli->conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) { char b[128]; LOGE("ssl_config_defaults: %s", mbed_err(rc,b,sizeof(b))); return false; }

    mbedtls_ssl_conf_authmode(&cli->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&cli->conf, mbedtls_ctr_drbg_random, &cli->drbg);
    mbedtls_ssl_conf_min_version(&cli->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // DTLS 1.2
    mbedtls_ssl_conf_max_version(&cli->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    rc = mbedtls_ssl_setup(&cli->ssl, &cli->conf);
    if (rc != 0) { char b[128]; LOGE("ssl_setup: %s", mbed_err(rc,b,sizeof(b))); return false; }

    cli->fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (cli->fd == INVALID_SOCKET) { LOGE("socket: %s", errno_name(last_sock_err())); return false; }
    set_nonblock(cli->fd);

    sockaddr_in peer{}; peer.sin_family = AF_INET; peer.sin_port = htons(port);
#ifdef _WIN32
    inet_pton(AF_INET, server_ip.c_str(), &peer.sin_addr);
#else
    if (inet_pton(AF_INET, server_ip.c_str(), &peer.sin_addr) != 1) { LOGE("inet_pton failed"); CLOSESOCK(cli->fd); return false; }
#endif

    cli->bio.fd       = cli->fd;
    std::memcpy(&cli->bio.peer, &peer, sizeof(peer));
    cli->bio.peer_len = sizeof(peer);
    cli->bio.fixed_peer = true;

    mbedtls_ssl_set_bio(&cli->ssl, &cli->bio, bio_send, bio_recv, nullptr);
    mbedtls_ssl_set_mtu(&cli->ssl, DEFAULT_MTU);
    // DTLS требует таймер для ретрансляции Flight-ов:
    mbedtls_ssl_set_timer_cb(&cli->ssl, &cli->timer,
                             mbedtls_timing_set_delay, mbedtls_timing_get_delay);

    int hs = dtls_handshake_blocking(cli->ssl, 15000);
    if (hs != 0) { LOGE("client handshake failed: %d", hs); return false; }

    g_client = std::move(cli);
    LOGI("Client_Connect ok: peer=%s:%u", server_ip.c_str(), (unsigned)port);
    return true;
}

PLUGIN_API void Client_Disconnect() noexcept
{
    if (g_client && g_client->fd != INVALID_SOCKET) {
        // Try to send close_notify
        mbedtls_ssl_close_notify(&g_client->ssl);
    }
    g_client.reset();
}

// Serve: pumps DTLS <-> app plaintext via callbacks.
PLUGIN_API int Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                            const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                            const volatile sig_atomic_t *working_flag) noexcept
{
    if (!g_client || g_client->fd == INVALID_SOCKET) return -1;

    std::vector<std::uint8_t> inbuf(64 * 1024), outbuf(64 * 1024);

    while (!working_flag || *working_flag)
    {
        // UDP -> app (DTLS read -> plaintext up)
        int n = mbedtls_ssl_read(&g_client->ssl, inbuf.data(), (int)inbuf.size());
        if (n > 0) {
            send_to_net(inbuf.data(), (std::size_t)n);
        } else if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // ignore, just continue
        } else if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            LOGI("peer close_notify");
            return 0;
        } else if (n < 0) {
            char b[128]; LOGE("ssl_read: %s", mbed_err(n, b, sizeof(b)));
            // Not fatal — keep loop unless it's a hard error.
        }

        // app -> UDP (plaintext down -> DTLS write)
        ssize_t got = receive_from_net(outbuf.data(), outbuf.size());
        if (got > 0) {
            int wn = mbedtls_ssl_write(&g_client->ssl, outbuf.data(), (int)got);
            if (wn < 0 && wn != MBEDTLS_ERR_SSL_WANT_WRITE && wn != MBEDTLS_ERR_SSL_WANT_READ) {
                char b[128]; LOGE("ssl_write: %s", mbed_err(wn, b, sizeof(b)));
                return -2;
            }
        }

        // Small sleep to avoid busy-loop
        msleep(1);
    }

    return 0;
}

// -------------------- Server --------------------
static bool load_server_cert_key(DtlsServer &srv)
{
    const char *cert = std::getenv("CVPN_CERT");
    const char *key  = std::getenv("CVPN_KEY");
    if (!cert || !key) {
        LOGW("No CVPN_CERT/CVPN_KEY provided; TLS auth may fail (DEV ONLY)");
        return true; // Allow running without cert, but handshake will fail with real clients
    }

    int rc = mbedtls_x509_crt_parse_file(&srv.cert, cert);
    if (rc != 0) { char b[128]; LOGE("x509_crt_parse_file: %s", mbed_err(rc,b,sizeof(b))); return false; }

    rc = mbedtls_pk_parse_keyfile(&srv.key, key, nullptr);
    if (rc != 0) { char b[128]; LOGE("pk_parse_keyfile: %s", mbed_err(rc,b,sizeof(b))); return false; }

    return true;
}

PLUGIN_API bool Server_Bind(std::uint16_t port) noexcept
{
    winsock_once();

    auto srv = std::make_unique<DtlsServer>();
    if (!srv) { LOGE("OOM"); return false; }

    if (!load_server_cert_key(*srv)) return false;

    int rc = mbedtls_ssl_config_defaults(&srv->conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) { char b[128]; LOGE("ssl_config_defaults: %s", mbed_err(rc,b,sizeof(b))); return false; }

    mbedtls_ssl_conf_authmode(&srv->conf, (srv->cert.raw.p && srv->key.pk_info) ? MBEDTLS_SSL_VERIFY_NONE
                                                                                : MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&srv->conf, mbedtls_ctr_drbg_random, &srv->drbg);
    mbedtls_ssl_conf_min_version(&srv->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // DTLS 1.2
    mbedtls_ssl_conf_max_version(&srv->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    // DTLS cookies
    rc = mbedtls_ssl_cookie_setup(&srv->cookie, mbedtls_ctr_drbg_random, &srv->drbg);
    if (rc != 0) { char b[128]; LOGE("cookie_setup: %s", mbed_err(rc,b,sizeof(b))); return false; }
    mbedtls_ssl_conf_dtls_cookies(&srv->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &srv->cookie);

    // Certificate (optional, but recommended)
    if (srv->cert.raw.p && srv->key.pk_info) {
        rc = mbedtls_ssl_conf_own_cert(&srv->conf, &srv->cert, &srv->key);
        if (rc != 0) { char b[128]; LOGE("conf_own_cert: %s", mbed_err(rc,b,sizeof(b))); /* continue anyway */ }
    }

    // Bind UDP
    srv->fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (srv->fd == INVALID_SOCKET) { LOGE("socket: %s", errno_name(last_sock_err())); return false; }

    int one = 1;
#ifndef _WIN32
    setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(srv->fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGE("bind: %s", errno_name(last_sock_err()));
        CLOSESOCK(srv->fd);
        return false;
    }
    set_nonblock(srv->fd);

    g_server = std::move(srv);
    LOGI("Server_Bind ok on *:%u", (unsigned)port);
    return true;
}

PLUGIN_API int Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                            const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                            const volatile sig_atomic_t *working_flag) noexcept
{
    if (!g_server || g_server->fd == INVALID_SOCKET) return -1;

    // Create per-session SSL on demand.
    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    int rc = mbedtls_ssl_setup(&ssl, &g_server->conf);
    if (rc != 0) { char b[128]; LOGE("ssl_setup: %s", mbed_err(rc,b,sizeof(b))); return -1; }

    UdpBio bio{};
    bio.fd = g_server->fd;
    bio.fixed_peer = false; // accept first client automatically
    mbedtls_ssl_set_bio(&ssl, &bio, bio_send, bio_recv, nullptr);
    mbedtls_ssl_set_mtu(&ssl, DEFAULT_MTU);

    mbedtls_timing_delay_context timer; // <-- перессессионный таймер
    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

            // Pin client transport id for cookies (when we learn peer)
    auto set_client_transport_id_if_needed = [&]() {
        if (bio.peer_len) {
            // Use (addr,port) bytes as transport ID.
            unsigned char idbuf[64];
            size_t idlen = (size_t) std::min<int>((int)bio.peer_len, (int)sizeof(idbuf));
            std::memcpy(idbuf, &bio.peer, idlen);
            (void)mbedtls_ssl_set_client_transport_id(&ssl, idbuf, idlen);
        }
    };

    // Perform blocking handshake (with WANT_READ/WRITE polling).
    int hs_timeout_ms = 15000;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(hs_timeout_ms);
    while (true) {
        set_client_transport_id_if_needed();
        int hs = mbedtls_ssl_handshake(&ssl);
        if (hs == 0) break;
        if (hs == MBEDTLS_ERR_SSL_WANT_READ || hs == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (std::chrono::steady_clock::now() > deadline) {
                LOGE("server handshake timeout");
                mbedtls_ssl_free(&ssl);
                return -2;
            }
            msleep(10);
            continue;
        }
        char b[128]; LOGE("server handshake: %s", mbed_err(hs,b,sizeof(b)));
        mbedtls_ssl_free(&ssl);
        return -2;
    }

    // From now — one active peer:
    bio.fixed_peer = true;
    LOGI("Server handshake complete");

    std::vector<std::uint8_t> inbuf(64 * 1024), outbuf(64 * 1024);

    while (!working_flag || *working_flag)
    {
        // UDP -> app (DTLS read -> plaintext up)
        int n = mbedtls_ssl_read(&ssl, inbuf.data(), (int)inbuf.size());
        if (n > 0) {
            send_to_net(inbuf.data(), (std::size_t)n);
        } else if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // nothing to read now
        } else if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            LOGI("peer close_notify");
            break;
        } else if (n < 0) {
            char b[128]; LOGE("ssl_read: %s", mbed_err(n, b, sizeof(b)));
            // continue unless hard error repeats
        }

        // app -> UDP
        ssize_t got = receive_from_net(outbuf.data(), outbuf.size());
        if (got > 0) {
            int wn = mbedtls_ssl_write(&ssl, outbuf.data(), (int)got);
            if (wn < 0 && wn != MBEDTLS_ERR_SSL_WANT_WRITE && wn != MBEDTLS_ERR_SSL_WANT_READ) {
                char b[128]; LOGE("ssl_write: %s", mbed_err(wn, b, sizeof(b)));
                break;
            }
        }

        msleep(1);
    }

    // Graceful close
    (void) mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    return 0;
}
