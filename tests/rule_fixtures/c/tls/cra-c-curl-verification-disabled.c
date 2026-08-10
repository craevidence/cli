#include <curl/curl.h>

void bad(CURL *handle) {
    // ruleid: cra-c-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    // ruleid: cra-c-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
}

void good(CURL *handle) {
    // ok: cra-c-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    // ok: cra-c-curl-verification-disabled
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
}
