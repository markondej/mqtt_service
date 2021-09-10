#pragma once

#include "../thread/thread.hpp"
#ifdef _WIN32
#include "../console_window.hpp"
using Console = ConsoleWindow;
#else
#include "../console.hpp"
#endif

#define SERVICE_DEFAULT_PORT 1883
#define SERVICE_DEFAULT_ADDRESS "0.0.0.0"

#ifndef SERVICE_DEFAULT_MAX_CONNECTIONS
#define SERVICE_DEFAULT_MAX_CONNECTIONS USHRT_MAX
#endif

#ifndef SERVICE_DEFAULT_KEEP_ALIVE_TIME
#define SERVICE_DEFAULT_KEEP_ALIVE_TIME 60
#endif


namespace mqtt {
    class Service : public Thread {
    public:
        struct Error {
            bool valid;
            std::string message;
        };
        Service(const std::string &address, uint16_t port, const std::shared_ptr<Console> &console = nullptr);
        virtual ~Service();
        Error GetError();
    private:
        static void ServiceThread(Service *instance, const std::string &address, uint16_t port) noexcept;
        Error error;
        std::mutex errorAccess;
        std::shared_ptr<Console> console;
    };
}
