#include "mqtt/service.hpp"
#ifdef _WIN32
#include "console_window.hpp"
using Console = ConsoleWindow;
#else
#include "console.hpp"
#include <csignal>
#endif

#define CONSOLE_NOP_DELAY 1000

std::shared_ptr<mqtt::Service> service;

#ifndef _WIN32
void sigIntHandler(int sigNum)
{
    if (service && !service->IsClosed()) {
        service->Close();
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
    uint16_t port = SERVICE_DEFAULT_PORT;

#ifdef _WIN32
    int argc = __argc;
    char** argv = __argv;
#endif

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }

#ifndef _WIN32
    std::signal(SIGINT, sigIntHandler);
    std::signal(SIGTSTP, sigIntHandler);

    int result = 0;
#else
    WPARAM result = 1;
#endif

    Console console;
    try {
        service = std::shared_ptr<mqtt::Service>(new mqtt::Service(address, port, [&](const std::exception &exception) {
#ifndef _WIN32
            console.Print(exception.what());
#else
            MessageBox(NULL, exception.what(), "Error", MB_OK | MB_ICONERROR);
#endif
        }, [&](const std::string &message) {
            console.Print(message);
        }));
#ifndef _WIN32
        while (!service->IsClosed()) {
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
