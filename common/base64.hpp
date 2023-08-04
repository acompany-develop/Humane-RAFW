#pragma once

template<typename T, typename U>
T* base64_encode(U *message, size_t sz);

template<typename T, typename U>
T* base64_decode(U *message, size_t &sz);