#pragma once
/*
    MiniJumper - Custom Hooking Minimalistic Engine
    by NtKernelMC a.k.a �ed�uM
    Platform x32-x86
*/
#include <Windows.h>
#include <stdio.h>
namespace MiniJumper
{
    PVOID Trampoline = nullptr;
    class CustomHooks
    {
    public:
        static DWORD MakeJump(DWORD jmp_address, DWORD hookAddr, BYTE* prologue, size_t prologue_size)
        {
            DWORD old_prot = 0x0; if (prologue == nullptr) return 0x0;
            VirtualProtect((void*)jmp_address, prologue_size, PAGE_EXECUTE_READWRITE, &old_prot);
            memcpy(prologue, (void*)jmp_address, prologue_size);
            BYTE addrToBYTEs[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
            DWORD JMPBYTEs = (hookAddr - jmp_address - 5);
            memcpy(&addrToBYTEs[1], &JMPBYTEs, 4);
            memcpy((void*)jmp_address, addrToBYTEs, 5);
            Trampoline = VirtualAlloc(0, (5 + (prologue_size - 5)), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            BYTE TrampolineBYTEs[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
            if (prologue_size > 5)
            {
                BYTE nop[] = { 0x90 };
                for (BYTE x = 0; x < (prologue_size - 5); x++) memcpy((void*)(jmp_address + 0x5 + x), nop, 1);
                memcpy(Trampoline, &prologue[3], (prologue_size - 3));
                DWORD Delta = (jmp_address + prologue_size) - (((DWORD)Trampoline + (prologue_size - 3)) + 5);
                memcpy(&TrampolineBYTEs[1], &Delta, 4);
                memcpy((void*)((DWORD)Trampoline + (prologue_size - 3)), TrampolineBYTEs, 5);
            }
            else
            {
                DWORD Delta = (jmp_address + prologue_size) - ((DWORD)Trampoline + 5);
                memcpy(&TrampolineBYTEs[1], &Delta, 4);
                memcpy((void*)Trampoline, TrampolineBYTEs, 5);
            }
            VirtualProtect((void*)jmp_address, prologue_size, old_prot, &old_prot);
            return (DWORD)Trampoline;
        }
        static bool RestorePrologue(DWORD addr, BYTE* prologue, size_t prologue_size)
        {
            if (addr == NULL || prologue == nullptr || prologue_size == NULL) return false;
            DWORD old_prot = 0;
            VirtualProtect((void*)addr, prologue_size, PAGE_EXECUTE_READWRITE, &old_prot);
            memcpy((void*)addr, prologue, prologue_size);
            VirtualProtect((void*)addr, prologue_size, old_prot, &old_prot);
            if (Trampoline) VirtualFree(Trampoline, 0, MEM_RELEASE);
            return true;
        }
    };
}