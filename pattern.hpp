#pragma once

#include <cstdint>   
#include <string>   
#include <windows.h> 

namespace scanner
{
    class handle {
    public:
        handle() = default;
        explicit handle(uintptr_t address) : m_address(address) {}

        template <typename T>
        T as() const {
            return reinterpret_cast<T>(m_address);
        }

        handle add(uintptr_t offset) const {
            if (m_address != 0)
            {
                return handle(m_address + offset);
            }

            return *this;
        }

        handle sub(uintptr_t offset) const {
            if (m_address != 0)
            {
                return handle(m_address - offset);
            }

            return *this;
        }

        handle rip() const {
            if (m_address != 0)
            {
                auto offset = *as<int32_t*>();
                return add(offset + sizeof(int32_t));
            }

            return *this;
        }

    private:
        uintptr_t m_address = 0;
    };


    class _module {
    public:
        _module(const char* module) : m_module(module)
        {
            m_module_handle = GetModuleHandleA(m_module);
        }

        handle get_export(const char* func)
        {
            return handle((std::uintptr_t)GetProcAddress(m_module_handle, func));
        }

        HMODULE get_handle()
        {
            return m_module_handle;
        }

    private:
        const char* m_module;
        HMODULE m_module_handle;
    };

    class pattern {
    public:
        explicit pattern(_module module);
        ~pattern() noexcept;

        pattern& scan_now(const char* sig_name, const char* ida_sig);

        handle get_result();

    private:
        std::string m_module_name;
        _module m_module;
        size_t m_module_size;
        HMODULE m_module_handle;
        handle m_result;
    };
}