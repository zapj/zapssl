#include "cacert_resource.h"

namespace resources {

namespace {
// CA 证书数据
const unsigned char CACERT_DATA[] = {
    0x43,0x41,0x43,0x45,0x52,0x54,0x5f,0x43,0x4f,0x4e,0x54,0x45,0x4e,0x54,
    
};

const size_t CACERT_SIZE = sizeof(CACERT_DATA);
} // anonymous namespace

std::string_view get_cacert_pem() {
    return std::string_view(reinterpret_cast<const char*>(CACERT_DATA), CACERT_SIZE);
}

} // namespace resources
