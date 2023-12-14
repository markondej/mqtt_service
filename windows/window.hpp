#pragma once

#include <functional>
#include <windows.h>

class Window
{
public:
    using StatusHandler = std::function<bool()>;
    explicit Window(HWND parent = NULL);
    Window(LPCSTR className, LPCSTR windowTitle, DWORD exStyle, DWORD style, LPCSTR icon, unsigned width, unsigned height, HWND parent = NULL);
    Window(const Window&) = delete;
    Window(Window&&) = delete;
    Window& operator=(const Window&) = delete;
    virtual ~Window();
    static WPARAM HandleMessages(const StatusHandler &status);
protected:
    static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) noexcept;
    virtual LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept;
    void Register(LPCSTR className, LPCSTR icon, UINT style);
    void Unregister();
    void Create(DWORD exStyle, DWORD style, LPCSTR title, unsigned width, unsigned height);
    void Destroy() const;
    void Close(LPARAM lParam = FALSE) const;
    int GetScaled(int size, bool horizontal = true) const;
    int dpiHorizontal, dpiVertical;
    bool active;
    LPSTR className;
    HINSTANCE hInstance;
    HWND hWnd, hParent;
    GUID guid;
};