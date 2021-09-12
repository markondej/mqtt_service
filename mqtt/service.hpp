#pragma once

#include "../thread/thread.hpp"
#include <functional>

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
        using MessageHandler = std::function<void(const std::string &message) noexcept>;
        using ExceptionHandler = std::function<void(const std::exception &exception) noexcept>;
        Service(const std::string &address, uint16_t port, const ExceptionHandler &exceptionHandler, const MessageHandler &messageHandler);
        virtual ~Service();
    private:
        static void ServiceThread(Service *instance, const std::string &address, uint16_t port) noexcept;
        ExceptionHandler handleException;
        MessageHandler printMessage;
    };
}
