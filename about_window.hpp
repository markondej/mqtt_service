#pragma once

#include "windows/window.hpp"
#include "windows/product_info.hpp"

class AboutWindow : public Window
{
public:
    AboutWindow(HWND parent);
    virtual ~AboutWindow();
private:
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept;
    ProductInfo productInfo;
    HBITMAP hLogoBitmap;
    HBRUSH hBackground;
};
