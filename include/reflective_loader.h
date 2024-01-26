#pragma once
#include <iostream>
#include <vector>
#include <Windows.h>

class ReflectiveLoader {

    std::vector<char> PE;

    HANDLE native_reflective_execution();
public:

    bool load_PE(const char* path);

    bool execute_PE();

    ReflectiveLoader() = default;
    ~ReflectiveLoader();
};