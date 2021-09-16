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

#ifndef SERVICE_DEFAULT_TOPICS_FILENAME
#define SERVICE_DEFAULT_TOPICS_FILENAME std::string();
#endif

namespace mqtt {
    struct Payload;

    class Service : public Thread {
    public:
        using MessageHandler = std::function<void(const std::string &message) noexcept>;
        using ExceptionHandler = std::function<void(const std::exception &exception) noexcept>;
        Service(
            const std::string &address,
            uint16_t port,
#ifndef SERVICE_OPERATION_MODE_QUEUE
            const std::string &filename,
#endif
            const ExceptionHandler &exceptionHandler,
            const MessageHandler &messageHandler
        );
#ifndef SERVICE_OPERATION_MODE_QUEUE
        void Publish(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS = 0, bool retain = false);
#else
        void Publish(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS = 0);
#endif
        virtual ~Service();
    private:
        static void ServiceThread(Service *instance, const std::string &address, uint16_t port) noexcept;
        std::vector<Payload> payloads;
        ExceptionHandler handleException;
        MessageHandler printMessage;
        void *topics, *clients;
        std::mutex access;
    };
}
