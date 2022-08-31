#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <name.hpp>
#include <ua.hpp>
#include "../../Headers/value_calculate/common_library.h"
#include "../../Headers/value_calculate/ARM_mylibrary.h"
extern int ARM_BIT;
int ARM_subfindupdate(ea_t ea, func_t* func, std::string operand0, std::string operand1, std::string operand2, int mode);
void ARM_propagate_insn_value(ea_t ea, func_t* func);
void ARM_no_execute_update_insn(ARM_my_instruction* instrction, int op0_type, std::string operand0, ea_t ea, func_t* func,int num);