#include <curl/curl.h>

void bad(CURL *handle) {
    // ruleid: cra-cpp-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    // ruleid: cra-cpp-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
}

void good(CURL *handle) {
    // ok: cra-cpp-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    // ok: cra-cpp-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
}
