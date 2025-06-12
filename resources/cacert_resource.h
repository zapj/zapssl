#ifndef ZAPSSL_CACERT_RESOURCE_H
#define ZAPSSL_CACERT_RESOURCE_H

#include <string_view>

namespace resources {

// 获取 CA 证书内容
std::string_view get_cacert_pem();

} // namespace resources

#endif // ZAPSSL_CACERT_RESOURCE_H
