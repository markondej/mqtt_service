#pragma once

#include "../thread/thread.hpp"
#include <functional>
#include <vector>
#include <mutex>

#define SERVICE_DEFAULT_PORT 1883
#define SERVICE_DEFAULT_ADDRESS "0.0.0.0"

#ifndef SERVICE_DEFAULT_MAX_CONNECTIONS
#define SERVICE_DEFAULT_MAX_CONNECTIONS USHRT_MAX
#endif

namespace mqtt {
    struct Payload;

    class Service : public Thread {
    public:
        using MessageHandler = std::function<void(const std::string &message) noexcept>;
        using ExceptionHandler = std::function<void(const std::exception &exception) noexcept>;
        Service(const std::string &address, uint16_t port, const ExceptionHandler &exceptionHandler, const MessageHandler &messageHandler);
        void Publish(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS = 0);
        virtual ~Service();
    private:
        static void ServiceThread(Service *instance, const std::string &address, uint16_t port) noexcept;
        std::vector<Payload> payloads;
        ExceptionHandler handleException;
        MessageHandler printMessage;
        std::mutex access;
    };
}
