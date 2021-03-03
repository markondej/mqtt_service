#pragma once

#include <thread>
#include <mutex>
#include <atomic>

class Thread
{
public:
    Thread();
    Thread(const Thread &) = delete;
    Thread(Thread &&) = delete;
    Thread &operator=(const Thread &) = delete;
    virtual ~Thread();
    void Close();
    bool IsClosed() const;
protected:
    std::thread thread;
    std::atomic_bool closed;
};
