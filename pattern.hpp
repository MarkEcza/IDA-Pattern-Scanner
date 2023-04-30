#pragma once

#include <cstdint>   
#include <string>   
#include <windows.h> 

namespace scanner
{
    class handle {
    public:
        handle() = default;
        explicit handle(std::uintptr_t address) : m_address(address) {}

        template <typename T>
        T as() const {
            return reinterpret_cast<T>(m_address);
        }

        handle add(std::uintptr_t offset) const {
            return handle(m_address + offset);
        }

        handle sub(std::uintptr_t offset) const {
            return handle(m_address - offset);
        }

        handle rip() const {
            return add(*reinterpret_cast<const int32_t*>(as<const char*>())).add(4);
        }

    private:
        std::uintptr_t m_address = 0;
    };

    class pattern {
    public:
        explicit pattern(const std::string& module = nullptr);
        ~pattern() noexcept;

        pattern& scan(const char* sig_name, std::string ida_sig);

        handle get_result();

    private:
        std::string m_module_name;
        HMODULE m_module_base;
        size_t m_module_size;
        handle m_result;
    };
}