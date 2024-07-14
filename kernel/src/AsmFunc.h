#pragma once
#include "ntddk.h"
extern void* GetHookFunctionAddress();
extern ULONG_PTR GetHookFunAsmSize();
extern ULONG_PTR GetHookFunctionJmpDataOffset();