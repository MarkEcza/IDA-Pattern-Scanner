#include "pattern.hpp"

namespace scanner
{
    std::vector<uint8_t> parse_ida_signature(const std::string& sig) {
        std::vector<uint8_t> bytes;
        std::stringstream ss(sig);

        while (!ss.eof()) {
            std::string byte_str;
            ss >> byte_str;

            if (byte_str == "?" || byte_str == "??") {
                bytes.push_back(0);
                continue;
            }

            if (byte_str.length() != 2) {
                throw std::runtime_error("Invalid byte in IDA signature: " + byte_str);
            }

            char* end;
            long value = strtol(byte_str.c_str(), &end, 16);

            if (*end != '\0') {
                throw std::runtime_error("Invalid byte in IDA signature: " + byte_str);
            }

            bytes.push_back(static_cast<uint8_t>(value));
        }

        return bytes;
    }


    pattern::pattern(const std::string& module) :
        m_module_name(module), m_result(0)
    {
        m_module_base = GetModuleHandleA(m_module_name.c_str());

        if (m_module_base == nullptr) {
            throw std::runtime_error("Could not find module: " + m_module_name);
        }

        MODULEINFO mi = { 0 };

        if (!GetModuleInformation(GetCurrentProcess(), m_module_base, &mi, sizeof(mi))) {
            throw std::runtime_error("Could not get module information");
        }
        m_module_size = mi.SizeOfImage;
    }

    pattern::~pattern() {}

    pattern& pattern::scan(const char* sig_name, std::string ida_sig)
    {
        std::vector<uint8_t> signature = parse_ida_signature(ida_sig);
        std::uintptr_t base_address = reinterpret_cast<std::uintptr_t>(m_module_base);
        std::uintptr_t end_address = base_address + m_module_size - signature.size();


        std::array<int, 256> bad_char;
        for (int i = 0; i < 256; ++i) {
            bad_char[i] = signature.size();
        }
        for (int i = 0; i < signature.size() - 1; ++i) {
            bad_char[signature[i]] = signature.size() - i - 1;
        }

        std::uintptr_t i = base_address + signature.size() - 1;
        while (i < end_address) {
            int j = signature.size() - 1;
            while (j >= 0 && *reinterpret_cast<uint8_t*>(i - signature.size() + j + 1) == signature[j]) {
                --j;
            }
            if (j < 0) {
                m_result = handle(i - signature.size() + 1);
                return *this;
            }
            i += bad_char[*reinterpret_cast<uint8_t*>(i)];
        }
        return *this;
    }


    handle pattern::get_result()
    {
        return m_result;
    }
}