#include "product_info.hpp"
#include <stdexcept>
#include <windows.h>

ProductInfo::ProductInfo(const std::string &language)
{
    try {
        CHAR filename[MAX_PATH + 1] = { 0 };
        if (GetModuleFileName(NULL, filename, MAX_PATH) == 0) {
            throw std::exception();
        }

        DWORD temp;
        DWORD size = GetFileVersionInfoSize(filename, &temp);
        if (size == 0) {
            throw std::exception();
        }

        BYTE *data = new BYTE[size];
        if (!GetFileVersionInfo(filename, NULL, size, data)) {
            delete[] data;
            throw std::exception();
        }

        LPVOID string = nullptr;
        unsigned length = 0;

        name = (!VerQueryValue(data, ("\\StringFileInfo\\" + language + "\\ProductName\\").c_str(), &string, &length)) ? "Unknown Product" : std::string(static_cast<LPCSTR>(string), length - 1);
        version = (!VerQueryValue(data, ("\\StringFileInfo\\" + language + "\\ProductVersion\\").c_str(), &string, &length)) ? "Unknown" : std::string(static_cast<LPCSTR>(string), length - 1);
        companyName = (!VerQueryValue(data, ("\\StringFileInfo\\" + language + "\\CompanyName\\").c_str(), &string, &length)) ? "Unknown Company" : std::string(static_cast<LPCSTR>(string), length - 1);
        legalCopyright = (!VerQueryValue(data, ("\\StringFileInfo\\" + language + "\\LegalCopyright\\").c_str(), &string, &length)) ? "Copyright (c) 2019" : std::string(static_cast<LPCSTR>(string), length - 1);

        delete[] data;
    } catch (...) {
        throw std::runtime_error("Cannot load product version info");
    }
}

const std::string &ProductInfo::GetName() const
{
    return name;
}

const std::string &ProductInfo::GetVersion() const
{
    return version;
}

const std::string &ProductInfo::GetCompanyName() const
{
    return companyName;
}

const std::string &ProductInfo::GetLegalCopyright() const
{
    return legalCopyright;
}
