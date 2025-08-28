#include "Core/Plugins/VipSession.hpp"

#include <chrono>

VipSessionManager::VipSessionManager(const VipConfig &cfg)
        : cfg_(cfg)
{
}

VipSession &VipSessionManager::Touch(const VipKey &key,
                                     const PeerEndpoint &ep,
                                     std::uint64_t now_ms)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto &s = map_[key];
    s.key = key;
    s.peer = ep;
    s.last_seen_ms = now_ms;
    return s;
}

VipSession *VipSessionManager::Find(const VipKey &key)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = map_.find(key);
    if (it == map_.end()) return nullptr;
    return &it->second;
}

bool VipSessionManager::EnqueueToVip(const VipKey &key, const void *data, std::size_t size)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = map_.find(key);
    if (it == map_.end()) return false;

    auto &q = it->second.out_q;
    if (q.size() >= cfg_.max_queue_per_vip)
    {
        // drop-latest policy
        return false;
    }
    q.emplace_back(reinterpret_cast<const char*>(data),
                   reinterpret_cast<const char*>(data) + size);
    return true;
}

bool VipSessionManager::DequeueFromAny(std::string &out)
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (map_.empty()) return false;

    // simple round-robin over map buckets
    std::size_t n = map_.bucket_count();
    if (n == 0) return false;

    for (std::size_t tried = 0; tried < n; ++tried)
    {
        std::size_t b = (rr_cursor_ + tried) % n;
        for (auto it = map_.begin(b); it != map_.end(b); ++it)
        {
            auto &q = it->second.out_q;
            if (!q.empty())
            {
                out = std::move(q.front());
                q.pop_front();
                rr_cursor_ = (b + 1) % n;
                return true;
            }
        }
    }
    return false;
}

void VipSessionManager::GarbageCollect(std::uint64_t now_ms)
{
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto it = map_.begin(); it != map_.end(); )
    {
        if (now_ms - it->second.last_seen_ms > cfg_.ttl_ms)
        {
            if (it->second.transport) it->second.transport->Close();
            it = map_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void VipSessionManager::AttachTransport(const VipKey &key, std::shared_ptr<ISessionTransport> t)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = map_.find(key);
    if (it != map_.end())
        it->second.transport = std::move(t);
}

std::size_t VipSessionManager::Size() const
{
    std::lock_guard<std::mutex> lk(mtx_);
    return map_.size();
}

std::uint64_t NowMs() noexcept
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
            duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count()
    );
}
