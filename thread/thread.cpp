#include "thread.hpp"

Thread::Thread() :
    closed(false)
{
}

Thread::~Thread()
{
}

void Thread::Close()
{
    closed = true;
    if (thread.joinable()) {
        thread.join();
    }
}

bool Thread::IsClosed() const
{
    return closed;
}
