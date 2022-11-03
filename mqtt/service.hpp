#pragma once

#include <functional>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

#define SERVICE_DEFAULT_ADDRESS "0.0.0.0"
#define SERVICE_DEFAULT_PORT 1883

#ifndef SERVICE_DEFAULT_TOPICS_FILENAME
#define SERVICE_DEFAULT_TOPICS_FILENAME std::string()
#endif

namespace mqtt {
    struct Payload;

    class Service {
    public:
        using ConnectHandler = std::function<bool(const std::string &clientId) noexcept>;
        using DisconnectHandler = std::function<void(const std::string &clientId) noexcept>;
        using PublishHandler = std::function<bool(const std::string &clientId, const std::string &topicName, const std::vector<uint8_t>&payload) noexcept>;
        using MessageHandler = std::function<void(const std::string &message) noexcept>;
        using ExceptionHandler = std::function<void(const std::exception &exception) noexcept>;
        Service(
            const std::string &address = SERVICE_DEFAULT_ADDRESS,
            uint16_t port = SERVICE_DEFAULT_PORT,
#ifndef SERVICE_OPERATION_MODE_QUEUE
            const std::string &filename = SERVICE_DEFAULT_TOPICS_FILENAME,
#endif
            const ConnectHandler &connectHandler = nullptr,
            const DisconnectHandler &disconnectHandler = nullptr,
            const PublishHandler &publishHandler = nullptr,
            const ExceptionHandler &exceptionHandler = nullptr,
            const MessageHandler &messageHandler = nullptr
        );
        Service(const Service &) = delete;
        Service(Service &&) = delete;
        Service &operator=(const Service &) = delete;
        virtual ~Service();
        void Publish(
            const std::string &clientId,
            const std::string &topicName,
            const std::vector<uint8_t> &payload,
            uint8_t requestedQoS = 0,
#ifndef SERVICE_OPERATION_MODE_QUEUE
            bool retain = false,
#endif
            bool handle = true
        );
        bool IsEnabled() const;
        void Disable() noexcept;
    private:
        static void ServiceThread(
            Service *instance,
            const std::string &address,
            uint16_t port,
            const ConnectHandler &connectHandler,
            const DisconnectHandler &disconnectHandler,
            const ExceptionHandler &exceptionHandler,
            const MessageHandler &messageHandler
        ) noexcept;
        PublishHandler publishHandler;
        std::atomic_bool enabled, disable;
        std::vector<Payload> payloads;
        std::thread thread;
        mutable std::mutex access;
        void *topics;
    };
}
