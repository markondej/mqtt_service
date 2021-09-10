#include "window.hpp"
#include <stdexcept>
#include <string>
#include <vector>

#define WINDOW_NOP_INTERVAL 1000

#define WINDOW_CLASS_NAME_LENGTH 128
#define WINDOW_DEFAULT_DPI 96

struct WindowInstance {
    std::string className;
    Window *window;
    GUID guid;
    HWND hWnd;
};

class WindowInstances
{
public:
    enum class OperationResult {
        Failure,
        Success,
        ClassExists
    };

    WindowInstances() = delete;
    WindowInstances(const WindowInstances &) = delete;
    WindowInstances(WindowInstances &&) = delete;
    WindowInstances &operator=(const WindowInstances &) = delete;
    static OperationResult Add(WindowInstance window) {
        bool classExists = false;
        if (Exists(window.className, false)) {
            return OperationResult::Failure;
        }
        if (Exists(window.className)) {
            classExists = true;
        }
        instances.push_back(window);
        return classExists ? OperationResult::ClassExists : OperationResult::Success;
    }
    static OperationResult Remove(GUID guid) {
        for (auto iterator = instances.begin(); iterator != instances.end(); iterator++) {
            if ((*iterator).guid == guid) {
                std::string removedClass = (*iterator).className;
                instances.erase(iterator);
                return (Exists(removedClass) || Exists(removedClass, false)) ? OperationResult::ClassExists : OperationResult::Success;
            }
        }
        return OperationResult::Failure;
    }
    static Window *GetWindow(HWND hWnd, const std::string &className = std::string()) noexcept {
        for (WindowInstance &instance : instances) {
            if ((instance.hWnd == hWnd) && ((hWnd != NULL) || (instance.className == className))) {
                return instance.window;
            }
        }
        return nullptr;
    }
    static OperationResult UpdateHandle(GUID guid, HWND hWnd) {
        for (WindowInstance &instance : instances) {
            if (instance.guid == guid) {
                instance.hWnd = hWnd;
                return OperationResult::Success;
            }
        }
        return OperationResult::Failure;
    }
    static const std::vector<WindowInstance> &GetAll() {
        return instances;
    }
private:
    static bool Exists(const std::string &className, bool isInitialized = true) {
        for (WindowInstance &instance : instances) {
            if ((instance.className == className) && (isInitialized ? (instance.hWnd != NULL) : (instance.hWnd == NULL))) {
                return true;
            }
        }
        return false;
    }
    static std::vector<WindowInstance> instances;
};

std::vector<WindowInstance> WindowInstances::instances;

Window::Window(HWND parent)
    : dpiHorizontal(WINDOW_DEFAULT_DPI), dpiVertical(WINDOW_DEFAULT_DPI), isActive(false), className(NULL), hWnd(NULL), hParent(parent)
{
    hInstance = GetModuleHandle(NULL);
    if (hInstance == NULL) {
        throw std::runtime_error("Cannot obtain module handle");
    }
    if (CoCreateGuid(&guid) != S_OK) {
        throw std::runtime_error("Cannot generate window GUID");
    }

    HDC hScreen = GetDC(0);
    if (hScreen != NULL) {
        dpiHorizontal = GetDeviceCaps(hScreen, LOGPIXELSX);
        dpiVertical = GetDeviceCaps(hScreen, LOGPIXELSY);
        ReleaseDC(0, hScreen);
    }
}

Window::Window(LPCSTR className, LPCSTR windowTitle, DWORD exStyle, DWORD style, LPCSTR icon, unsigned width, unsigned height, HWND parent)
    : Window(parent)
{
    Register(className, icon, CS_DBLCLKS);

    try {
        Create(exStyle, style, windowTitle, GetScaled(width), GetScaled(height, false));
    } catch (...) {
        Unregister();
        throw;
    }
}

Window::~Window()
{
    if (!isActive) {
        Destroy();
        isActive = false;
    }
    if (className != NULL) {
        Unregister();
    }
}

WPARAM Window::HandleMessages(Thread &thread)
{
    MSG msg;
    while (true) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if ((WindowInstances::GetWindow(msg.hwnd) == nullptr) || !IsDialogMessage(msg.hwnd, &msg)) {
                if (msg.message == WM_QUIT) {
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        } else if (thread.IsClosed()) {
            for (auto &instance : WindowInstances::GetAll()) {
                instance.window->Close(TRUE);
            }
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(WINDOW_NOP_INTERVAL));
        }
    }
    thread.Close();
    return msg.wParam;
}

LRESULT CALLBACK Window::WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) noexcept {
    Window *window = WindowInstances::GetWindow(hWnd);
    if (window == nullptr) {
        CHAR windowClass[WINDOW_CLASS_NAME_LENGTH];
        if (GetClassName(hWnd, windowClass, WINDOW_CLASS_NAME_LENGTH) > 0) {
            window = WindowInstances::GetWindow(NULL, windowClass);
        }
    }
    if (window != nullptr) {
        if (msg == WM_DESTROY) {
            window->isActive = false;
        }
        if (window->hWnd == NULL) {
            window->hWnd = hWnd;
        }
        return window->HandleMessage(msg, wParam, lParam);
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

LRESULT Window::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept
{
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

void Window::Register(LPCSTR className, LPCSTR icon, UINT style)
{
    if (this->className != NULL) {
        throw std::runtime_error("Cannot register window class, already registered");
    }

    this->className = new CHAR[strlen(className) + 1];
#ifdef _MSC_VER
    std::strcpy(this->className, className);
#else
    ::strcpy(this->className, className);
#endif

    auto added = WindowInstances::Add({ this->className, this, guid, NULL });
    if (added == WindowInstances::OperationResult::Failure) {
        delete[] this->className;
        this->className = NULL;
        throw std::runtime_error("Cannot register window class");
    }

    if (added != WindowInstances::OperationResult::ClassExists) {
        WNDCLASSEX wndClass;
        wndClass.hInstance = hInstance;
        wndClass.lpszClassName = className;
        wndClass.lpfnWndProc = WindowProc;
        wndClass.style = style;
        wndClass.cbSize = sizeof(WNDCLASSEX);
        wndClass.hIcon = (icon != NULL) ? LoadIcon(hInstance, icon) : NULL;
        wndClass.hIconSm = (icon != NULL) ? static_cast<HICON>(LoadImage(hInstance, icon, IMAGE_ICON, 16, 16, 0)) : NULL;
        wndClass.hCursor = LoadCursor(NULL, IDC_ARROW);
        wndClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW);
        wndClass.lpszMenuName = NULL;
        wndClass.cbClsExtra = 0;
        wndClass.cbWndExtra = 0;

        /* wndClass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        wndClass.hIconSm = LoadIcon(NULL, IDI_APPLICATION); */

        if (!RegisterClassEx(&wndClass)) {
            WindowInstances::Remove(guid);
            delete[] this->className;
            this->className = NULL;
            throw std::runtime_error("Cannot register window class");
        }
    }
}

void Window::Create(DWORD exStyle, DWORD style, LPCSTR title, unsigned width, unsigned height)
{
    if ((className == NULL) || isActive) {
        throw std::runtime_error("Cannot create window");
    }

    hWnd = CreateWindowEx(exStyle, className, title, style, CW_USEDEFAULT, CW_USEDEFAULT, width, height, hParent, NULL, hInstance, NULL);

    if (hWnd == NULL) {
        throw std::runtime_error("Cannot create window");
    }

    if (WindowInstances::UpdateHandle(guid, hWnd) == WindowInstances::OperationResult::Failure) {
        DestroyWindow(hWnd);
         throw std::runtime_error("Cannot update window handle");
    }

    isActive = true;
}

void Window::Unregister()
{
    if (className == NULL) {
        return;
    }

    if (WindowInstances::Remove(guid) == WindowInstances::OperationResult::Success) {
        UnregisterClass(className, hInstance);
    }

    delete[] className;
    className = NULL;
}

void Window::Destroy() const
{
    if (!isActive) {
        return;
    }
    DestroyWindow(hWnd);
}

void Window::Close(LPARAM lParam) const
{
    if (hWnd != NULL) {
        SendMessage(hWnd, WM_CLOSE, 0, lParam);
    }
}

int Window::GetScaled(int size, bool horizontal) const
{
    return size * (horizontal ? dpiHorizontal : dpiVertical) / WINDOW_DEFAULT_DPI;
}
