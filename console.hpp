#pragma once

#include <iostream>

#ifndef SERVICE_PRODUCT_NAME
#define SERVICE_PRODUCT_NAME "Unknown"
#endif

#ifndef SERVICE_PRODUCT_VERSION
#define SERVICE_PRODUCT_VERSION "0.0.0.0"
#endif

class Console {
public:
    Console() {
        std::cout << SERVICE_PRODUCT_NAME << ", Version " << SERVICE_PRODUCT_VERSION << std::endl;
    }
    void Print(const std::string &text) {
        std::cout << text << std::endl;
    }
};
