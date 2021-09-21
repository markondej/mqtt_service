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
        using MessageHandler = std::function<void(const std::string &message) noexcept>;
        using ExceptionHandler = std::function<void(const std::exception &exception) noexcept>;
        Service(
            const std::string &address = SERVICE_DEFAULT_ADDRESS,
            uint16_t port = SERVICE_DEFAULT_PORT,
#ifndef SERVICE_OPERATION_MODE_QUEUE
            const std::string &filename = SERVICE_DEFAULT_TOPICS_FILENAME,
#endif
            const ExceptionHandler &exceptionHandler = nullptr,
            const MessageHandler &messageHandler = nullptr
        );
        Service(const Service &) = delete;
        Service(Service &&) = delete;
        Service &operator=(const Service &) = delete;
        virtual ~Service();
        void Publish(
            const std::string &topicName,
            const std::vector<uint8_t> &payload,
#ifndef SERVICE_OPERATION_MODE_QUEUE
            uint8_t requestedQoS = 0,
            bool retain = false
#else
            uint8_t requestedQoS = 0
#endif
        );
        bool IsEnabled() const;
        void Disable() noexcept;
    private:
        static void ServiceThread(
            Service *instance,
            const std::string &address,
            uint16_t port,
            const ExceptionHandler &exceptionHandler,
            const MessageHandler &messageHandler
        ) noexcept;
        std::atomic_bool enabled;
        std::vector<Payload> payloads;
        std::thread thread;
        std::mutex access;
        void *topics;
    };
}
