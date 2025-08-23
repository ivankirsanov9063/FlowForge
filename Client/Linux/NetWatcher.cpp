#include "NetWatcher.hpp"
#include "Logger.hpp"

#include <thread>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/cache.h>
#include <netlink/handlers.h>
#include <linux/rtnetlink.h>

namespace
{
    static int OnNlValid(struct nl_msg* /*msg*/, void* arg)
    {
        auto* self = reinterpret_cast<NetWatcher*>(arg);
        if (self != nullptr)
        {
            self->Kick();
        }
        return NL_OK;
    }

    static void DrainEventFd(int fd)
    {
        std::uint64_t val = 0;
        while (true)
        {
            ssize_t rc = ::read(fd, &val, sizeof(val));
            if (rc < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                if (errno == EINTR) continue;
                return;
            }
            if (rc == 0) return;
        }
    }
}

NetWatcher::NetWatcher(ReapplyFn reapply, std::chrono::milliseconds debounce)
        : reapply_(std::move(reapply))
        , debounce_(debounce.count() > 0 ? debounce : std::chrono::milliseconds(1000))
{
    Start_();
}

NetWatcher::~NetWatcher()
{
    Shutdown_();
}

bool NetWatcher::IsRunning() const
{
    return running_;
}

void NetWatcher::SignalEventFd_(int fd)
{
    if (fd < 0) return;
    std::uint64_t one = 1;
    (void)::write(fd, &one, sizeof(one)); // неблокирующая запись; overflow игнорируем
}

void NetWatcher::Kick()
{
    SignalEventFd_(kick_fd_);
}

void NetWatcher::Stop()
{
    Shutdown_();
}

void NetWatcher::Start_()
{
    if (running_) return;

    stop_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    kick_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (stop_fd_ < 0 || kick_fd_ < 0)
    {
        LOGE("netwatcher") << "eventfd create failed";
        if (stop_fd_ >= 0) { ::close(stop_fd_); stop_fd_ = -1; }
        if (kick_fd_ >= 0) { ::close(kick_fd_); kick_fd_ = -1; }
        return;
    }

    nl_sock_ = nl_socket_alloc();
    if (!nl_sock_)
    {
        LOGE("netwatcher") << "nl_socket_alloc failed";
        ::close(stop_fd_); ::close(kick_fd_);
        stop_fd_ = kick_fd_ = -1;
        return;
    }

    if (nl_connect(nl_sock_, NETLINK_ROUTE) != 0)
    {
        LOGE("netwatcher") << "nl_connect(NETLINK_ROUTE) failed";
        nl_socket_free(nl_sock_);
        nl_sock_ = nullptr;
        ::close(stop_fd_); ::close(kick_fd_);
        stop_fd_ = kick_fd_ = -1;
        return;
    }

    int rc = nl_socket_add_memberships(nl_sock_,
                                       RTNLGRP_LINK,
                                       RTNLGRP_IPV4_IFADDR,
                                       RTNLGRP_IPV6_IFADDR,
                                       RTNLGRP_IPV4_ROUTE,
                                       RTNLGRP_IPV6_ROUTE,
                                       0);
    if (rc != 0)
    {
        LOGE("netwatcher") << "nl_socket_add_memberships rc=" << rc;
        nl_close(nl_sock_);
        nl_socket_free(nl_sock_);
        nl_sock_ = nullptr;
        ::close(stop_fd_); ::close(kick_fd_);
        stop_fd_ = kick_fd_ = -1;
        return;
    }

    nl_socket_disable_seq_check(nl_sock_);
    nl_socket_modify_cb(nl_sock_, NL_CB_VALID, NL_CB_CUSTOM, &OnNlValid, this);
    nl_socket_set_nonblocking(nl_sock_);
    nl_fd_ = nl_socket_get_fd(nl_sock_);

    running_ = true;

    thread_ = new std::thread([this]()
                              {
                                  LOGI("netwatcher") << "Thread started";
                                  pollfd pfds[3]{};

                                  while (running_)
                                  {
                                      pfds[0] = { stop_fd_, POLLIN, 0 };
                                      pfds[1] = { kick_fd_, POLLIN, 0 };
                                      pfds[2] = { nl_fd_,   POLLIN, 0 };

                                      int rc2 = ::poll(pfds, 3, -1);
                                      if (rc2 < 0)
                                      {
                                          if (errno == EINTR) continue;
                                          LOGE("netwatcher") << "poll failed";
                                          break;
                                      }

                                      if (pfds[0].revents & POLLIN)
                                      {
                                          DrainEventFd(stop_fd_);
                                          LOGD("netwatcher") << "Stop signal";
                                          break;
                                      }

                                      if (pfds[2].revents & POLLIN)
                                      {
                                          // Коллбек OnNlValid вызовет Kick()
                                          (void)nl_recvmsgs_default(nl_sock_);
                                      }

                                      if (pfds[1].revents & POLLIN)
                                      {
                                          // Коалесцируем события: ждём ещё debounce, собирая дополнительные "kick"
                                          DrainEventFd(kick_fd_);

                                          const auto start = std::chrono::steady_clock::now();
                                          while (running_)
                                          {
                                              const auto elapsed = std::chrono::steady_clock::now() - start;
                                              if (elapsed >= debounce_) break;

                                              const int timeout_ms = static_cast<int>(
                                                      std::chrono::duration_cast<std::chrono::milliseconds>(debounce_ - elapsed).count()
                                              );

                                              pollfd p2[2] = {
                                                      { stop_fd_, POLLIN, 0 },
                                                      { kick_fd_, POLLIN, 0 }
                                              };
                                              int rc3 = ::poll(p2, 2, timeout_ms);
                                              if (rc3 < 0)
                                              {
                                                  if (errno == EINTR) continue;
                                                  LOGE("netwatcher") << "poll(inner) failed";
                                                  break;
                                              }
                                              if (p2[0].revents & POLLIN)
                                              {
                                                  DrainEventFd(stop_fd_);
                                                  LOGD("netwatcher") << "Stop during debounce";
                                                  running_ = false;
                                                  break;
                                              }
                                              if (p2[1].revents & POLLIN)
                                              {
                                                  // ещё один kick — сливаем и продолжаем ждать до истечения окна
                                                  DrainEventFd(kick_fd_);
                                                  continue;
                                              }
                                              // timeout без событий — выходим
                                              if (rc3 == 0) break;
                                          }

                                          if (!running_) break;

                                          try
                                          {
                                              LOGI("netwatcher") << "Reapply begin";
                                              reapply_();
                                              LOGI("netwatcher") << "Reapply end";
                                          }
                                          catch (const std::exception& e)
                                          {
                                              LOGE("netwatcher") << "Reapply exception: " << e.what();
                                          }
                                          catch (...)
                                          {
                                              LOGE("netwatcher") << "Reapply unknown exception";
                                          }
                                      }
                                  }

                                  LOGI("netwatcher") << "Thread exiting";
                              });

    LOGD("netwatcher") << "Armed (debounce=" << debounce_.count() << " ms)";
}

void NetWatcher::Shutdown_()
{
    if (!running_)
    {
        // убедимся, что ресурсы точно закрыты
        if (thread_ != nullptr)
        {
            delete thread_;
            thread_ = nullptr;
        }
        if (nl_sock_ != nullptr)
        {
            nl_close(nl_sock_);
            nl_socket_free(nl_sock_);
            nl_sock_ = nullptr;
        }
        if (stop_fd_ >= 0) { ::close(stop_fd_); stop_fd_ = -1; }
        if (kick_fd_ >= 0) { ::close(kick_fd_); kick_fd_ = -1; }
        nl_fd_ = -1;
        return;
    }

    running_ = false;
    SignalEventFd_(stop_fd_);

    if (thread_ != nullptr)
    {
        if (thread_->joinable()) { thread_->join(); }
        delete thread_;
        thread_ = nullptr;
    }

    if (nl_sock_ != nullptr)
    {
        nl_close(nl_sock_);
        nl_socket_free(nl_sock_);
        nl_sock_ = nullptr;
    }

    if (stop_fd_ >= 0) { ::close(stop_fd_); stop_fd_ = -1; }
    if (kick_fd_ >= 0) { ::close(kick_fd_); kick_fd_ = -1; }
    nl_fd_ = -1;

    LOGD("netwatcher") << "Stopped";
}
