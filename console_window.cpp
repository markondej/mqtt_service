#include "console_window.hpp"
#include "resources/resource.h"
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

#define CONSOLE_WINDOW_WIDTH 450
#define CONSOLE_WINDOW_HEIGHT 330
#define CONSOLE_WINDOW_BREAK_LINE "\r\n"
#define CONSOLE_WINDOW_MIN_LINES 450
#define CONSOLE_WINDOW_MAX_LINES 500

#define ID_CONSOLE_EDIT 201

#define IDM_MENU_EXPORT 9001
#define IDM_MENU_CLOSE 9002
#define IDM_MENU_ABOUT 9003

ConsoleWindow::ConsoleWindow()
    : Window("ConsoleWindow", "Console", WS_EX_APPWINDOW, WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX, MAKEINTRESOURCE(IDI_APPLICATION_ICON), CONSOLE_WINDOW_WIDTH, CONSOLE_WINDOW_HEIGHT), about(nullptr)
{
    ProductInfo productInfo("040904b0");
    textLines.push_back(productInfo.GetName() + ", Version " + productInfo.GetVersion());

    HMENU hMenu = CreateMenu();
    if (hMenu == NULL) {
        throw std::runtime_error("Cannot create window menu");
    }
    try {
        HMENU hSubMenu = CreatePopupMenu();
        if (hSubMenu == NULL) {
            throw std::exception();
        }
        if (!AppendMenu(hSubMenu, MF_STRING, IDM_MENU_EXPORT, "&Export") || !AppendMenu(hSubMenu, MF_STRING, IDM_MENU_CLOSE, "&Close") || !AppendMenu(hMenu, MF_STRING | MF_POPUP, reinterpret_cast<UINT_PTR>(hSubMenu), "&File")) {
            DestroyMenu(hSubMenu);
            throw std::exception();
        }
        if (!AppendMenu(hMenu, MF_STRING, IDM_MENU_ABOUT, "&About") || !SetMenu(hWnd, hMenu)) {
            throw std::exception();
        }
    } catch (...) {
        DestroyMenu(hMenu);
        throw std::runtime_error("Cannot create window menu");
    }

    try {
        RECT clientArea;
        if (!GetClientRect(hWnd, &clientArea)) {
            throw std::exception();
        }
        HWND hEdit = CreateWindowEx(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY, 0, 0,
            clientArea.right, clientArea.bottom, hWnd, reinterpret_cast<HMENU>(ID_CONSOLE_EDIT), hInstance, nullptr);
        if (hEdit == NULL) {
            throw std::exception();
        }
        HFONT hDefaultFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        if (hDefaultFont != NULL) {
            SendMessage(hEdit, WM_SETFONT, reinterpret_cast<WPARAM>(hDefaultFont), static_cast<LPARAM>(FALSE));
        }
        SendMessage(hEdit, EM_SETMARGINS, EC_LEFTMARGIN, static_cast<LPARAM>(GetScaled(2)));
        SendMessage(hEdit, EM_SETMARGINS, EC_RIGHTMARGIN, static_cast<LPARAM>(GetScaled(2)));
    } catch (...) {
        throw std::runtime_error("Cannot create window");
    }

    ShowWindow(hWnd, SW_SHOW);
}

ConsoleWindow::~ConsoleWindow()
{
    if (about != nullptr) {
        delete about;
    }
}

void ConsoleWindow::Print(const std::string& text, bool appendTs)
{
    auto t = std::time(nullptr);
    std::stringstream tsText;
    tsText << "[" << std::put_time(std::localtime(&t), "%H:%M:%S") << "] " << text;
    {
        std::lock_guard<std::mutex> lock(access);
        textQueue.push(appendTs ? tsText.str() : text);
    }
    PostMessage(hWnd, WM_NULL, 0, 0);
}

void ConsoleWindow::AddText(const std::string& text)
{
    std::size_t erase = 0;
    textLines.push_back(text);
    if (textLines.size() > CONSOLE_WINDOW_MAX_LINES) {
        for (std::size_t i = 0; i < textLines.size() - CONSOLE_WINDOW_MIN_LINES; i++) {
            erase += textLines[i].size() + std::string(CONSOLE_WINDOW_BREAK_LINE).size();
        }
        textLines.erase(textLines.begin(), textLines.begin() + textLines.size() - CONSOLE_WINDOW_MIN_LINES);
    }
    HWND hEdit = GetDlgItem(hWnd, ID_CONSOLE_EDIT);
    if (hEdit != NULL) {
        /* SetWindowText(hEdit, GetText().c_str()); */
        if (erase) {
            SendMessage(hEdit, EM_SETSEL, 0, static_cast<LPARAM>(erase));
            SendMessage(hEdit, EM_REPLACESEL, 0, reinterpret_cast<LPARAM>(""));
        }
        int length = GetWindowTextLength(hEdit);
        SendMessage(hEdit, EM_SETSEL, static_cast<WPARAM>(length), static_cast<LPARAM>(length));
        SendMessage(hEdit, EM_REPLACESEL, 0, reinterpret_cast<LPARAM>((text + CONSOLE_WINDOW_BREAK_LINE).c_str()));
    }
}

void ConsoleWindow::Save(const std::string& filename)
{
    std::ofstream file;
    file.open(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to log file");
    }
    for (std::string& line : textLines) {
        file << line << std::endl;
    }
    file.close();
}

void ConsoleWindow::AppendText()
{
    std::lock_guard<std::mutex> lock(access);
    while (!textQueue.empty()) {
        AddText(textQueue.front());
        textQueue.pop();
    }
}

LRESULT ConsoleWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept
{
    HWND hEdit;
    RECT clientArea;
    CHAR filename[MAX_PATH] = "export.log";
    LPMINMAXINFO minMaxInfo;
    switch (msg) {
    case WM_NULL:
        AppendText();
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CLOSE:
        if ((lParam == TRUE) || (MessageBox(hWnd, "Service will be terminated, are you sure?", "Console", MB_YESNO | MB_ICONQUESTION) == IDYES)) {
            Destroy();
        }
        break;
    case WM_GETMINMAXINFO:
        minMaxInfo = reinterpret_cast<LPMINMAXINFO>(lParam);
        minMaxInfo->ptMinTrackSize.x = GetScaled(CONSOLE_WINDOW_WIDTH >> 1);
        minMaxInfo->ptMinTrackSize.y = GetScaled(CONSOLE_WINDOW_HEIGHT >> 1);
        break;
    case WM_SIZE:
        GetClientRect(hWnd, &clientArea);
        hEdit = GetDlgItem(hWnd, ID_CONSOLE_EDIT);
        if (hEdit != NULL) {
            SetWindowPos(hEdit, NULL, 0, 0, clientArea.right, clientArea.bottom, SWP_NOZORDER);
        }
        break;
    case WM_SHOWWINDOW:
        hEdit = GetDlgItem(hWnd, ID_CONSOLE_EDIT);
        if (hEdit != NULL) {
            SetWindowText(hEdit, GetText().c_str());
            /* for (std::string& line : lines) {
                int length = GetWindowTextLength(hEdit);
                SendMessage(hEdit, EM_SETSEL, static_cast<WPARAM>(length), static_cast<LPARAM>(length));
                SendMessage(hEdit, EM_REPLACESEL, 0, reinterpret_cast<LPARAM>((line + CONSOLE_WINDOW_BREAK_LINE).c_str()));
            } */
        }
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_MENU_EXPORT:
            OPENFILENAME openFilename;
            ZeroMemory(&openFilename, sizeof(OPENFILENAME));
            openFilename.lStructSize = sizeof(OPENFILENAME);
            openFilename.hwndOwner = hWnd;
            openFilename.lpstrFilter = "Exported log file (*.log)\0*.log\0";
            openFilename.lpstrFile = filename;
            openFilename.nMaxFile = MAX_PATH;
            openFilename.Flags = OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
            if (GetSaveFileName(&openFilename)) {
                try {
                    Save(filename);
                    AddText(std::string("Log exported to: ") + filename);
                } catch (std::exception &catched) {
                    MessageBox(hWnd, catched.what(), "Console", MB_OK | MB_ICONERROR);
                }
            }
            break;
        case IDM_MENU_CLOSE:
            Close();
            break;
        case IDM_MENU_ABOUT:
            try {
                if (about != nullptr) {
                    delete about;
                }
                about = new AboutWindow(hWnd);
            } catch (std::exception &catched) {
                MessageBox(hWnd, catched.what(), "Console", MB_OK | MB_ICONERROR);
            }
            break;
        }
        break;
    default:
        return Window::HandleMessage(msg, wParam, lParam);
    }
    return 0;
}

std::string ConsoleWindow::GetText() const
{
    std::string text;
    for (const std::string &line : textLines) {
        text += line + CONSOLE_WINDOW_BREAK_LINE;
    }
    return text;
}
