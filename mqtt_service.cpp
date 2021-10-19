#include "mqtt/service.hpp"
#ifdef _WIN32
#include "console_window.hpp"
using Console = ConsoleWindow;
#else
#include "console.hpp"
#include <csignal>
#endif
#include <cstring>

#define CONSOLE_NOP_DELAY 1000

std::shared_ptr<mqtt::Service> service;

std::vector<uint8_t> GeneratePayload(const std::string &string) {
    std::vector<uint8_t> payload;
    payload.resize(string.size());
    std::memcpy(payload.data(), string.data(), string.size());
    return payload;
};

#ifndef _WIN32
void signalHandler(int sigNum)
{
    if (service && service->IsEnabled()) {
        service->Disable();
    }
}
#endif

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
#else
int main(int argc, char** argv)
#endif
{
    std::string address = SERVICE_DEFAULT_ADDRESS;
#ifndef SERVICE_OPERATION_MODE_QUEUE
    std::string filename = SERVICE_DEFAULT_TOPICS_FILENAME;
#endif
    uint16_t port = SERVICE_DEFAULT_PORT;

#ifdef _WIN32
    int argc = __argc;
    char** argv = __argv;
#endif

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
#ifndef SERVICE_OPERATION_MODE_QUEUE
    if (argc > 3) { filename = argv[3]; }
#endif

#ifndef _WIN32
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = 0;
#else
    WPARAM result = 1;
#endif

    try {
        Console console;
        service = std::shared_ptr<mqtt::Service>(new mqtt::Service(
            address,
            port,
#ifndef SERVICE_OPERATION_MODE_QUEUE
            filename,
#endif
            nullptr,
            [&](const std::exception &exception) {
#ifndef _WIN32
            console.Print(exception.what());
#else
            MessageBox(NULL, exception.what(), "Error", MB_OK | MB_ICONERROR);
#endif
        }, [&](const std::string &message) {
            console.Print(message);
        }));
#ifndef _WIN32
        while (service->IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(CONSOLE_NOP_DELAY));
        }
#else
        result = Window::HandleMessages(*service);
#endif
    } catch (...) {
#ifndef _WIN32
        return 1;
#endif
    }
    return result;
}
