#pragma once

// ===== C ABI exports for shared library mode (argv + len) =====
#include <cstdint>

#if defined(_WIN32)
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#endif

// Запуск клиента в отдельном потоке.
// Ожидается, что argv/len — это ТОЛЬКО аргументы (без argv[0]).
EXPORT int32_t Start(char **argv, int32_t len);

// Мягкая остановка: сигналим рабочему коду и НЕ блокируем вызывающего.
EXPORT int32_t Stop(void);

// Статус работы: 1 — запущен, 0 — остановлен
EXPORT int32_t IsRunning(void);
