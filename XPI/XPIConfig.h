#ifndef CONFIG_MANAGER_H_
#define CONFIG_MANAGER_H_

#include <windows.h>

BOOL LoadXPIConfig(__in_z LPCWSTR lpcwszFile);
BOOL SaveXPIConfig(__in_z LPCWSTR lpcwszFile);

#endif // CONFIG_MANAGER_H_