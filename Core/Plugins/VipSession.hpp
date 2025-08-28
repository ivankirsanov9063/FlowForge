#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <functional>

#include "Core/Plugins/Vip.hpp"
#include "Core/Plugins/PeerEndpoint.hpp"

// Forward-declare transport interface
struct ISessionTransport
{
    virtual ~ISessionTransport() = default;
    virtual bool Send(const void *data, std::size_t size) = 0;
    virtual void Close() = 0;
};

struct VipSession
{
    VipKey           key{};
    PeerEndpoint     peer{};
    std::uint64_t    last_seen_ms {0};

    // Outbound queue to that peer (server->client direction).
    std::deque<std::string> out_q;

    // Optional transport owned externally (DTLS, QUIC, ...).
    std::shared_ptr<ISessionTransport> transport;
};

struct VipConfig
{
    std::size_t     max_sessions         { 10000 };
    std::size_t     max_queue_per_vip    { 2048 };
    std::uint64_t   ttl_ms               { 5 * 60 * 1000 };
};

class VipSessionManager
{
public:
    explicit VipSessionManager(const VipConfig &cfg);

    // Create or touch session; update endpoint; return reference.
    VipSession &Touch(const VipKey &key, const PeerEndpoint &ep, std::uint64_t now_ms);

    // Lookup session; nullptr if not found.
    VipSession *Find(const VipKey &key);

    // Enqueue data to VIP; returns false if dropped by policy.
    bool EnqueueToVip(const VipKey &key, const void *data, std::size_t size);

    // Pop one item from any VIP (round-robin) into out; returns false if nothing.
    bool DequeueFromAny(std::string &out);

    // Remove expired sessions.
    void GarbageCollect(std::uint64_t now_ms);

    // Attach transport handle to session.
    void AttachTransport(const VipKey &key, std::shared_ptr<ISessionTransport> t);

    std::size_t Size() const;

private:
    using Map = std::unordered_map<VipKey, VipSession, VipKey::Hasher>;

    VipConfig        cfg_;
    mutable std::mutex mtx_;
    Map              map_;
    std::size_t      rr_cursor_ {0};
};

std::uint64_t NowMs() noexcept;
