#include "service.hpp"
#include "protocol.hpp"
#include <climits>

#ifndef SERVICE_TOPICS_LIMIT
#define SERVICE_TOPICS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_PAYLOAD_SIZE_LIMIT
#define SERVICE_PAYLOAD_SIZE_LIMIT 32 * 1024 * 1024
#endif
#ifndef SERVICE_PUBLISHED_PACKETS_LIMIT
#define SERVICE_PUBLISHED_PACKETS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_TOPIC_PAYLOADS_LIMIT
#define SERVICE_TOPIC_PAYLOADS_LIMIT USHRT_MAX
#endif

#define SERVICE_STATUS_INTERVAL 30
#define SERVICE_NOP_DELAY 1000

namespace mqtt {
    struct PublishedPacket {
        uint64_t connectionId;
        uint32_t topicId;
        uint16_t packetId, timeout;
        uint8_t selectedQoS, requestedQoS;
        std::string topicName;
        std::vector<uint8_t> data;
        enum class Status {
            Added,
            Sent,
            Acknowledged
        } status;
        std::chrono::time_point<std::chrono::system_clock> timestamp;
    };

    class Clients {
    public:
        struct Client {
            uint64_t connectionId;
            uint16_t keepAlive, packetIdSeq;
            std::string clientId;
            std::vector<uint16_t> packetIds;
        };
        Clients() { }
        Clients(const Clients &) = delete;
        Clients(Clients &&) = delete;
        Clients &operator=(const Clients &) = delete;
        Client Get(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    return client;
                }
            }
            throw std::runtime_error("Client does not exist");
        }
        Client Add(uint64_t connectionId, const std::string &clientId, uint16_t keepAlive) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    throw std::runtime_error("Duplicated connection identifier");
                }
            }
            clients.push_back({ connectionId, keepAlive ? keepAlive : static_cast<uint16_t>(SERVICE_DEFAULT_KEEP_ALIVE_TIME), USHRT_MAX, clientId });
            return *std::prev(clients.end());
        }
        void Delete(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (auto client = clients.begin(); client != clients.end();) {
                if (client->connectionId == connectionId) {
                    client = clients.erase(client);
                    return;
                }
                client++;
            }
            throw std::runtime_error("Client does not exist");
        }
        std::pair<uint16_t, uint16_t> AddPacket(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            auto getNextPacketId = [&](Client &client) -> uint16_t {
                for (uint16_t packetId = client.packetIdSeq + 1; packetId != client.packetIdSeq; packetId++) {
                    auto id = client.packetIds.begin();
                    while (id != client.packetIds.end()) {
                        if (*id == packetId) {
                            break;
                        }
                        id++;
                    }
                    if (id == client.packetIds.end()) {
                        client.packetIdSeq = packetId;
                        return client.packetIdSeq;
                    }
                }
                throw std::runtime_error("Cannot generate packet identifier");
            };
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    if (client.packetIds.size() < SERVICE_PUBLISHED_PACKETS_LIMIT) {
                        uint16_t packetId = getNextPacketId(client);
                        client.packetIds.push_back(packetId);
                        return { packetId, client.keepAlive };
                    }
                    break;
                }
            }
            throw std::runtime_error("Client does not exist");
        }
        void RemovePacket(uint64_t connectionId, uint16_t packetId) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    for (auto id = client.packetIds.begin(); id != client.packetIds.end();) {
                        if (*id == packetId) {
                            id = client.packetIds.erase(id);
                            return;
                        }
                        id++;
                    }
                    return;
                }
            }
        }
        unsigned long long Count() {
            std::lock_guard<std::mutex> lock(access);
            return clients.size();
        }
    private:
        std::vector<Client> clients;
        std::mutex access;
    };

    class Topics {
    public:
        struct Topic {
            uint32_t id;
            struct Subscription {
                uint64_t connectionId;
                uint8_t requestedQoS;
            };
            struct Payload {
                std::vector<uint8_t> data;
                uint8_t requestedQoS;
                std::vector<Subscription> recipients;
                bool assigned;
            };
            std::string name;
            std::vector<Subscription> subscriptions;
            std::vector<Payload> payloads;
        };
        Topics() { }
        Topics(const Topics &) = delete;
        Topics(Topics &&) = delete;
        Topics &operator=(const Topics &) = delete;
        void Subscribe(uint64_t connectionId, const std::string &topicName, uint8_t requestedQoS) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    for (Topic::Subscription &subscription : topic.subscriptions) {
                        if (subscription.connectionId == connectionId) {
                            subscription.requestedQoS = requestedQoS;
                            return;
                        }
                    }
                    topic.subscriptions.push_back({ connectionId, requestedQoS });
                    return;
                }
            }
            if (topics.size() >= SERVICE_TOPICS_LIMIT) {
                std::runtime_error("Topics limit exceeded");
            }
            topics.push_back({ ++topicSequence, topicName, { { connectionId, requestedQoS } } });
        }
        void Unsubscribe(uint64_t connectionId, const std::string &topicName) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    for (auto subscription = topic.subscriptions.begin(); subscription != topic.subscriptions.end();) {
                        if (subscription->connectionId == connectionId) {
                            subscription = topic.subscriptions.erase(subscription);
                            return;
                        }
                        subscription++;
                    }
                    std::runtime_error("Topic not subscribed by client");
                }
            }
            std::runtime_error("Topics does not exist");
        }
        std::vector<std::string> UnsubscribeAll(uint64_t connectionId) {
            std::vector<std::string> unsubscribed;
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                auto subscription = topic.subscriptions.begin();
                while (subscription != topic.subscriptions.end()) {
                    if (subscription->connectionId == connectionId) {
                        subscription = topic.subscriptions.erase(subscription);
                        unsubscribed.push_back(topic.name);
                        break;
                    }
                    subscription++;
                }
                if (subscription != topic.subscriptions.end()) {
                    for (Topic::Payload &payload : topic.payloads) {
                        if (!payload.assigned || payload.recipients.empty()) {
                            continue;
                        }
                        for (auto recipient = payload.recipients.begin(); recipient != payload.recipients.end();) {
                            if (recipient->connectionId == connectionId) {
                                recipient = payload.recipients.erase(recipient);
                                continue;
                            }
                            recipient++;
                        }
#ifdef SERVICE_OPERATION_MODE_QUEUE
                        if (payload.recipients.empty()) {
                            payload.assigned = false;
                        }
#endif
                    }
                }
            }
            return unsubscribed;
        }
        void Publish(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    if (topic.payloads.size() >= SERVICE_TOPIC_PAYLOADS_LIMIT) {
                        throw std::runtime_error("Topic payloads limit exceeded");
                    }
                    topic.payloads.push_back({ payload, requestedQoS });
                    return;
                }
            }
            if (topics.size() >= SERVICE_TOPICS_LIMIT) {
                throw std::runtime_error("Topics limit exceeded");
            }
            topics.push_back({ ++topicSequence, topicName, std::vector<Topic::Subscription>(), { { payload, requestedQoS } } });
        }
        unsigned long long Count() {
            std::lock_guard<std::mutex> lock(access);
            return topics.size();
        }
        std::vector<PublishedPacket> PublishPackets(Clients &clients) {
            std::vector<PublishedPacket> packets;
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.payloads.empty()) {
                    continue;
                }
                for (Topic::Payload &payload : topic.payloads) {
#ifndef SERVICE_OPERATION_MODE_QUEUE
                    if (!payload.assigned) {
                        payload.recipients = topic.subscriptions;
#else
                    if (!payload.assigned && !topic.subscriptions.empty()) {
                        Topic::Subscription subscription = topic.subscriptions[rand() % topic.subscriptions.size()];
                        payload.recipients.push_back(subscription);
#endif
                        payload.assigned = true;
                    }
                }
                for (auto payload = topic.payloads.begin(); payload != topic.payloads.end();) {
                    if (!payload->assigned) {
                        payload++;
                        continue;
                    }
                    for (auto recipient = payload->recipients.begin(); recipient != payload->recipients.end();) {
                        try {
                            auto added = clients.AddPacket(recipient->connectionId);
                            packets.push_back({ recipient->connectionId, topic.id, added.first, added.second, std::min(recipient->requestedQoS, payload->requestedQoS), payload->requestedQoS, topic.name, payload->data, PublishedPacket::Status::Added });
                            recipient = payload->recipients.erase(recipient);
                        } catch (...) {
                            recipient++;
                        }
                    }
                    if (payload->recipients.empty()) {
                        payload = topic.payloads.erase(payload);
                        continue;
                    }
                    payload++;
                }
            }
            return packets;
        };
        bool IsSubscribed(uint64_t connectionId, uint32_t topicId) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.id == topicId) {
                    for (Topic::Subscription &subscription : topic.subscriptions) {
                        if (subscription.connectionId == connectionId) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    private:
        uint32_t topicSequence = 0;
        std::vector<Topic> topics;
        std::mutex access;
    };

    class PublishedPackets {
    public:
        PublishedPackets() { }
        PublishedPackets(const PublishedPackets &) = delete;
        PublishedPackets(PublishedPackets &&) = delete;
        PublishedPackets &operator=(const PublishedPackets &) = delete;
        void Remove(uint64_t connectionId, uint16_t packetId, uint8_t requiredQoS, PublishedPacket::Status requiredStatus) {
            std::lock_guard<std::mutex> lock(access);
            for (auto packet = packets.begin(); packet != packets.end();) {
                if ((packet->connectionId == connectionId) && (packet->packetId == packetId)) {
                    if ((packet->selectedQoS != requiredQoS) || (packet->status != requiredStatus)) {
                        throw std::runtime_error("Bad QoS or packet status");
                    }
                    packet = packets.erase(packet);
                    return;
                }
                packet++;
            }
            throw std::runtime_error("Bad packet identifier");
        }
        std::vector<uint16_t> RemoveAll(uint64_t connectionId) {
            std::vector<uint16_t> removed;
            std::lock_guard<std::mutex> lock(access);
            for (auto packet = packets.begin(); packet != packets.end();) {
                if (packet->connectionId == connectionId) {
                    removed.push_back(packet->packetId);
                    packet = packets.erase(packet);
                    continue;
                }
                packet++;
            }
            return removed;
        }
        void UpdateStatus(uint64_t connectionId, uint16_t packetId, uint8_t requiredQoS, PublishedPacket::Status requiredStatus, PublishedPacket::Status status) {
            std::lock_guard<std::mutex> lock(access);
            for (auto packet = packets.begin(); packet != packets.end();) {
                if ((packet->packetId == packetId) && (packet->connectionId == connectionId)) {
                    if ((packet->selectedQoS != requiredQoS) || (packet->status != requiredStatus)) {
                        throw std::runtime_error("Bad QoS or packet status");
                    }
                    packet->timestamp = std::chrono::system_clock::now();
                    packet->status = status;
                    return;
                }
            }
            throw std::runtime_error("Bad packet identifier");
        }
        unsigned long long Count() {
            std::lock_guard<std::mutex> lock(access);
            return packets.size();
        }
        void Append(const std::vector<PublishedPacket> &packets) {
            if (packets.empty()) {
                return;
            }
            std::lock_guard<std::mutex> lock(access);
            this->packets.insert(this->packets.end(), packets.begin(), packets.end());
        }
        std::vector<std::pair<uint64_t, uint16_t>> Handle(Topics &topics, Server &server) {
            std::vector<std::pair<uint64_t, uint16_t>> handled;
            std::lock_guard<std::mutex> lock(access);
            for (auto packet = packets.begin(); packet != packets.end();) {
                auto now = std::chrono::system_clock::now();
                try {
                    bool resend = false;
                    if ((packet->status != PublishedPacket::Status::Added) && (std::chrono::duration_cast<std::chrono::seconds>(now - packet->timestamp).count() > packet->timeout)) {
#ifndef SERVICE_OPERATION_MODE_QUEUE
                        if (!topics.IsSubscribed(packet->connectionId, packet->topicId)) {
                            throw std::runtime_error("Unsubscribed");
                        }
                        resend = true;
#else
                        topics.Publish(packet->topicName, packet->data, packet->requestedQoS);
                        throw std::runtime_error("Timeout");
#endif
                    }
                    if ((packet->status == PublishedPacket::Status::Added) || resend) {
                        server.Publish(packet->connectionId, packet->packetId, packet->topicName, packet->data, { resend, static_cast<bool>(packet->selectedQoS & 0x1), static_cast<bool>(packet->selectedQoS & 0x2), false });
                        packet->status = PublishedPacket::Status::Sent;
                        packet->timestamp = now;
                        if (!packet->selectedQoS) {
                            handled.push_back({ packet->connectionId, packet->packetId });
                            packet = packets.erase(packet);
                            continue;
                        }
                    }
                } catch (...) {
                    handled.push_back({ packet->connectionId, packet->packetId });
                    packet = packets.erase(packet);
                    continue;
                }
                packet++;
            }
            return handled;
        }
    private:
        std::vector<PublishedPacket> packets;
        std::mutex access;
    };

    class QoSRequests {
    public:
        struct Request {
            uint64_t connectionId;
            uint16_t packetId, timeout;
            uint8_t requestedQoS;
            enum class Status {
                Acknowledged,
                Completed
            } status;
            std::chrono::time_point<std::chrono::system_clock> timestamp;
        };
        QoSRequests() { }
        QoSRequests(const QoSRequests &) = delete;
        QoSRequests(QoSRequests &&) = delete;
        QoSRequests &operator=(const QoSRequests &) = delete;
        bool Register(uint64_t connectionId, uint16_t packetId, uint8_t requestedQoS, bool duplicate, uint16_t timeout) {
            std::lock_guard<std::mutex> lock(access);
            for (auto request = requests.begin(); request != requests.end();) {
                if (request->connectionId == connectionId) {
                    if (request->packetId == packetId) {
                        if (duplicate) {
                            request->requestedQoS = requestedQoS;
                            request->status = (requestedQoS < 2) ? Request::Status::Completed : Request::Status::Acknowledged;
                            return false;
                        } else if (request->status != Request::Status::Completed) {
                            throw std::runtime_error("Duplicated packet identifier");
                        }
                    }
                    request = requests.erase(request);
                    break;
                }
                request++;
            }
            requests.push_back({ connectionId, packetId, timeout, requestedQoS, (requestedQoS < 2) ? Request::Status::Completed : Request::Status::Acknowledged, std::chrono::system_clock::now() });
            return true;
        };
        void Unregister(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (auto request = requests.begin(); request != requests.end();) {
                if (request->connectionId == connectionId) {
                    request = requests.erase(request);
                    return;
                }
                request++;
            }
        };
        void Complete(uint64_t connectionId, uint16_t packetId, Server &server) {
            std::lock_guard<std::mutex> lock(access);
            for (auto &request : requests) {
                if ((request.connectionId == connectionId) && (request.packetId == packetId)) {
                    if ((request.requestedQoS < 2) || (request.status != Request::Status::Acknowledged)) {
                        throw std::runtime_error("Bad QoS or packet status");
                    }
                    request.status = Request::Status::Completed;
                    return;
                }
            }
            throw std::runtime_error("Bad packet identifier");
        };
        void HandleExpired() {
            std::lock_guard<std::mutex> lock(access);
            for (auto request = requests.begin(); request != requests.end();) {
                auto now = std::chrono::system_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - request->timestamp).count() > request->timeout) {
                    request = requests.erase(request);
                    continue;
                }
                request++;
            }
        };
    private:
        std::vector<Request> requests;
        std::mutex access;
    };

    Service::Service(const std::string &address, uint16_t port, const std::shared_ptr<Console> &console)
        : error({ false, std::string() }), console(console)
    {
        thread = std::thread(ServiceThread, this, address, port);
    }

    Service::~Service()
    {
        Close();
    }

    Service::Error Service::GetError() {
        std::lock_guard<std::mutex> lock(errorAccess);
        return error;
    }

    void Service::ServiceThread(Service *instance, const std::string &address, uint16_t port) noexcept {
        Server server;
        Clients clients;
        PublishedPackets published;
        QoSRequests requests;
        Topics topics;

        auto print = [&](const std::string &text) {
            if (instance->console) {
                instance->console->Print(text);
            }
        };

        std::thread serverThread([&]() {
            print("Starting service at " + address + ":" + std::to_string(port));

            server.SetConnectHandler([&](uint64_t connectionId, const ConnectFlags &flags, const ConnectParams &params, bool &sessionPresent) -> ConnectResponse {
                if (flags.userName || flags.password) {
                    print("Connection refused [\"" + params.clientId + "\":" + std::to_string(connectionId) + "], authorization not supported");
                    return ConnectResponse::RefusedBadCredentials;
                }
                if (flags.willFlag) {
                    print("Connection refused [\"" + params.clientId + "\":" + std::to_string(connectionId) + "], Will not supported");
                    return ConnectResponse::RefusedUnavailable;
                }
                Clients::Client client = clients.Add(connectionId, params.clientId, params.keepAlive);
                print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] connected");
                return ConnectResponse::Accepted;
            });
            server.SetDisconnectHandler([&](uint64_t connectionId, bool graceful) {
                Clients::Client client = clients.Get(connectionId);
                for (std::string &topicName : topics.UnsubscribeAll(connectionId)) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] unsubscribed from \"" + topicName + "\"");
                }
                for (uint16_t packetId : published.RemoveAll(connectionId)) {
                    clients.RemovePacket(connectionId, packetId);
                }
                requests.Unregister(connectionId);
                clients.Delete(connectionId);
                print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] disconnected");
            });
            server.SetSubscribeHandler([&](uint64_t connectionId, const std::string &topicFilter, uint8_t requestedQoS) -> SubscribeResponse {
                Clients::Client client = clients.Get(connectionId);
                std::size_t found = topicFilter.find("*");
                if (found != std::string::npos) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to subscribe to \"" + topicFilter + "\", wildcards not supported");
                    return SubscribeResponse::Failure;
                }
                try {
                    topics.Subscribe(connectionId, topicFilter, requestedQoS);
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] subscribed to \"" + topicFilter + "\"");
                } catch (...) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to subscribe to \"" + topicFilter + "\", topic quantity limit exceeded");
                    return SubscribeResponse::Failure;
                }
                switch (requestedQoS) {
                case 2:
                    return SubscribeResponse::QoS2;
                case 1:
                    return SubscribeResponse::QoS2;
                default:
                    return SubscribeResponse::QoS0;
                }
            });
            server.SetUnsubscribeHandler([&](uint64_t connectionId, const std::string &topicFilter) {
                Clients::Client client = clients.Get(connectionId);
                try {
                    topics.Unsubscribe(connectionId, topicFilter);
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] unsubscribed from \"" + topicFilter + "\"");
                } catch (...) { }
            });
            server.SetPublishHandler([&](uint64_t connectionId, uint16_t packetId, const std::string &topicName, const std::vector<uint8_t> &payload, PublishFlags &flags) -> PublishResponse {
                Clients::Client client = clients.Get(connectionId);
                std::size_t found = topicName.find("*");
                if (found != std::string::npos) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to publish to \"" + topicName + "\", bad topic name");
                    throw NoPacketException();
                }
                if (payload.size() > SERVICE_PAYLOAD_SIZE_LIMIT) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to publish to \"" + topicName + "\", payload size limit exceeded");
                    throw NoPacketException();
                }
                bool publish;
                uint8_t requestedQoS = (static_cast<uint8_t>(flags.qos2) << 1) | static_cast<uint8_t>(flags.qos1);
                try {
                    publish = !requestedQoS || requests.Register(connectionId, packetId, requestedQoS, flags.dup, client.keepAlive);
                } catch (...) {
                    throw NoPacketException();
                }
                if (publish) {
                    try {
                        topics.Publish(topicName, payload, requestedQoS);
                    } catch (...) {
                        if (requestedQoS) {
                            requests.Unregister(connectionId);
                        }
                        print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to publish to \"" + topicName + "\", topic limit exceeded");
                        throw NoPacketException();
                    }
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] published to \"" + topicName + "\"");
                }
                switch (requestedQoS) {
                case 2:
                    return PublishResponse::QoS2;
                case 1:
                    return PublishResponse::QoS1;
                default:
                    return PublishResponse::QoS0;
                }
            });
            server.SetPubackHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    published.Remove(connectionId, packetId, 1, PublishedPacket::Status::Sent);
                    clients.RemovePacket(connectionId, packetId);
                } catch (...) {
                    throw NoPacketException();
                }
            });
            server.SetPubrecHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    published.UpdateStatus(connectionId, packetId, 2, PublishedPacket::Status::Sent, PublishedPacket::Status::Acknowledged);
                } catch (...) {
                    throw NoPacketException();
                }
            });
            server.SetPubcompHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    published.Remove(connectionId, packetId, 2, PublishedPacket::Status::Acknowledged);
                    clients.RemovePacket(connectionId, packetId);
                } catch (...) {
                    throw NoPacketException();
                }
            });
            server.SetPubrelHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    requests.Complete(connectionId, packetId, server);
                } catch (...) {
                    throw NoPacketException();
                }
            });

            try {
                server.Enable(address, port, SERVICE_DEFAULT_MAX_CONNECTIONS);
            } catch (std::exception &e) {
                std::lock_guard<std::mutex> lock(instance->errorAccess);
                instance->error.valid = true;
                instance->error.message = e.what();
            }
        });
        auto statusTimestamp = std::chrono::system_clock::now();
        unsigned long long publishedCount = 0;
        while (!instance->closed) {
            if (instance->GetError().valid) {
                instance->closed = true;
            } else {
                bool active = false;
                auto packets = topics.PublishPackets(clients);
                publishedCount += packets.size();
                published.Append(packets);
                for (auto handled : published.Handle(topics, server)) {
                    clients.RemovePacket(handled.first, handled.second);
                    active = true;
                }
                auto now = std::chrono::system_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - statusTimestamp).count() >= SERVICE_STATUS_INTERVAL) {
                    print("Status: [topics:" + std::to_string(topics.Count()) + ", clients:" + std::to_string(clients.Count()) + ", processed:" + std::to_string(publishedCount) + "]");
                    statusTimestamp = now;
                    publishedCount = 0;
                }
                requests.HandleExpired();
                if (packets.empty() && !active) {
                    std::this_thread::sleep_for(std::chrono::microseconds(SERVICE_NOP_DELAY));
                }
            }
        }
        server.Disable();
        serverThread.join();
    }
}
