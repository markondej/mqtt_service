# Light MQTT Service

Light MQTT is light cross-platform MQTT broker, written in C++, designed for specialized use. It is compatible with MQTT 3.1.1 clients.

It may be easily embedded into custom applications, eg:
```
#include "mqtt/service.hpp"

int main(int argc, char** argv)
{
    // Run service on port 1883
    mqtt::Service service("127.0.0.1", 1883);
    // Check if service is enabled
    while (service.IsEnabled()) {
        // Publish 'Hello' message every second on topic 'default'
        service.Publish("default", {'H', 'e', 'l', 'l', 'o'});
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
```

## "Queue" mode
If compiled in "queue" mode, messages won't be broadcasted to all subscribers. Instead, each message will be published to randomly chosen subscriber. All unpublished messages are retained, so "Retain" option is ignored.
To compile service in "queue" mode define "SERVICE_OPERATION_MODE_QUEUE".

## To be done:
* Topic wildcards support
* Permanent client sessions
