#pragma once

#include <string>

class ProductInfo
{
public:
    ProductInfo(const std::string& language);
    const std::string &GetName() const;
    const std::string &GetVersion() const;
    const std::string &GetCompanyName() const;
    const std::string &GetLegalCopyright() const;
protected:
    std::string name, version, companyName, legalCopyright;
};
