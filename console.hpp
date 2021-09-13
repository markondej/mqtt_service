#pragma once

#include <iostream>

#ifndef PRODUCT_NAME
#define PRODUCT_NAME "Unknown"
#endif

#ifndef PRODUCT_VERSION
#define PRODUCT_VERSION "1.0.0.0"
#endif

class Console {
public:
    Console() {
        std::cout << PRODUCT_NAME << ", Version " << PRODUCT_VERSION << std::endl;
    }
    void Print(const std::string &text) {
        std::cout << text << std::endl;
    }
};
