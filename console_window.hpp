#pragma once

#include "about_window.hpp"
#include <string>
#include <vector>
#include <queue>
#include <mutex>

class ConsoleWindow : protected Window
{
public:
    ConsoleWindow();
    virtual ~ConsoleWindow();
    void Print(const std::string &text, bool appendTs = true);
private:
    void AddText(const std::string &text);
    void Save(const std::string &filename);
    void AppendText();
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept;
    std::string GetText() const;
    std::vector<std::string> textLines;
    std::queue<std::string> textQueue;
    std::mutex access;
    AboutWindow *about;
};
