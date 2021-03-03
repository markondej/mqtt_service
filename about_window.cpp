#include "about_window.hpp"
#include "resources/resource.h"
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>

#define ABOUT_NOP_INTERVAL 1000

#define ID_ABOUT_BUTTON_OK 202
#define ID_ABOUT_LABEL_PRODUCT_NAME 203
#define ID_ABOUT_LABEL_COPYRIGHT 204

AboutWindow::AboutWindow(HWND parent)
    : Window(parent), productInfo("040904b0")
{
    Register("AboutWindow", nullptr, CS_OWNDC);

    DWORD exStyle = WS_EX_DLGMODALFRAME;
    DWORD style = WS_CAPTION | WS_SYSMENU;

    RECT clientArea;
    std::memset(&clientArea, 0, sizeof(RECT));
    clientArea.right = GetScaled(350);
    clientArea.bottom = GetScaled(130, false);

    try {
        if (!AdjustWindowRectEx(&clientArea, style, false, exStyle)) {
            Unregister();
            throw std::exception();
        }

        hLogoBitmap = static_cast<HBITMAP>(LoadImage(hInstance, MAKEINTRESOURCE(IDB_ABOUT_LOGO), IMAGE_BITMAP, 0, 0, 0));
        if (hLogoBitmap == NULL) {
            Unregister();
            throw std::exception();
        }

        hBackground = CreateSolidBrush(RGB(0xff, 0xff, 0xff));
        if (hBackground == NULL) {
            DeleteObject(hLogoBitmap);
            Unregister();
            throw std::exception();
        }
    } catch (...) {
        throw std::runtime_error("Cannot create window");
    }

    try {
        Create(exStyle, style, "About", clientArea.right - clientArea.left, clientArea.bottom - clientArea.top);
    } catch (...) {
        DeleteObject(hBackground);
        DeleteObject(hLogoBitmap);
        Unregister();
        throw;
    }

    ShowWindow(hWnd, SW_SHOW);
    EnableWindow(hParent, FALSE);
}

AboutWindow::~AboutWindow()
{
    if (isActive) {
        EnableWindow(hParent, TRUE);
    }
    DeleteObject(hBackground);
    DeleteObject(hLogoBitmap);
}

LRESULT AboutWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept
{
    HDC hDC;
    RECT clientArea;
    PAINTSTRUCT paint;
    DWORD ctrlID;
    HFONT hDefaultFont;
    HWND hProductName, hCopyright, hButton;
    switch (msg) {
    case WM_CREATE:
        if (!GetClientRect(hWnd, &clientArea)) {
            return -1;
        }

        hDefaultFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        hProductName = CreateWindowEx(0, "STATIC", (productInfo.GetName() + ", Version " + productInfo.GetVersion()).c_str(), WS_CHILD | WS_VISIBLE, GetScaled(112), GetScaled(33, false),
            clientArea.right - GetScaled(126), GetScaled(20, false), hWnd, reinterpret_cast<HMENU>(ID_ABOUT_LABEL_PRODUCT_NAME), hInstance, nullptr);
        if (hProductName == NULL) {
            return -1;
        }
        if (hDefaultFont != NULL) {
            SendMessage(hProductName, WM_SETFONT, reinterpret_cast<WPARAM>(hDefaultFont), static_cast<LPARAM>(FALSE));
        }

        hCopyright = CreateWindowEx(0, "STATIC", productInfo.GetLegalCopyright().c_str(), WS_CHILD | WS_VISIBLE, GetScaled(112), GetScaled(53, false),
            clientArea.right - GetScaled(126), GetScaled(20, false), hWnd, reinterpret_cast<HMENU>(ID_ABOUT_LABEL_COPYRIGHT), hInstance, nullptr);
        if (hCopyright == NULL) {
            return -1;
        }
        if (hDefaultFont != NULL) {
            SendMessage(hCopyright, WM_SETFONT, reinterpret_cast<WPARAM>(hDefaultFont), static_cast<LPARAM>(FALSE));
        }

        hButton = CreateWindowEx(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, clientArea.right - GetScaled(88), GetScaled(97, false),
            GetScaled(80), GetScaled(25, false), hWnd, reinterpret_cast<HMENU>(ID_ABOUT_BUTTON_OK), hInstance, nullptr);
        if (hButton == NULL) {
            return -1;
        }
        if (hDefaultFont != NULL) {
            SendMessage(hButton, WM_SETFONT, reinterpret_cast<WPARAM>(hDefaultFont), static_cast<LPARAM>(FALSE));
        }
        break;
    case WM_CLOSE:
        EnableWindow(hParent, TRUE);
        Destroy();
        break;
    case WM_COMMAND:
        if ((LOWORD(wParam) == ID_ABOUT_BUTTON_OK) || (LOWORD(wParam) == IDOK)) {
            Close();
        }
        break;
    case WM_PAINT:
        if (!GetClientRect(hWnd, &clientArea)) {
            break;
        }
        hDC = BeginPaint(hWnd, &paint);
        if (hDC != NULL) {
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(0xff, 0xff, 0xff));
            if (hPen != NULL) {
                HGDIOBJ hOldPen = SelectObject(hDC, hPen);
                HGDIOBJ hOldBrush = SelectObject(hDC, hBackground);
                Rectangle(hDC, clientArea.left, GetScaled(10, false), clientArea.right, GetScaled(90, false));
                SelectObject(hDC, hOldBrush);
                SelectObject(hDC, hOldPen);
                DeleteObject(hPen);
            }

            BITMAP bitmap;
            HDC hCompDC = CreateCompatibleDC(hDC);
            if (hCompDC != NULL) {
                HGDIOBJ hOldBitmap = SelectObject(hCompDC, hLogoBitmap);
                if (GetObject(hLogoBitmap, sizeof(bitmap), &bitmap) != 0) {
                    BitBlt(hDC, GetScaled(16), GetScaled(10, false) + ((GetScaled(80, false) - 80) >> 1), bitmap.bmWidth, bitmap.bmHeight, hCompDC, 0, 0, SRCCOPY);
                }
                SelectObject(hCompDC, hOldBitmap);
                DeleteDC(hCompDC);
            }

            EndPaint(hWnd, &paint);
        }
        break;
    case WM_CTLCOLORSTATIC:
        ctrlID = GetDlgCtrlID(reinterpret_cast<HWND>(lParam));
        if ((ctrlID == ID_ABOUT_LABEL_PRODUCT_NAME) || (ctrlID == ID_ABOUT_LABEL_COPYRIGHT)) {
            hDC = reinterpret_cast<HDC>(wParam);
            SetBkColor(hDC, RGB(0xff, 0xff, 0xff));
            SetTextColor(hDC, RGB(0x00, 0x00, 0x00));
            return reinterpret_cast<INT_PTR>(hBackground);
        }
    default:
        return Window::HandleMessage(msg, wParam, lParam);
    }
    return 0;
}
