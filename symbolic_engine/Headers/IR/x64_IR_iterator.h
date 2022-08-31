#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include "../value_calculate/x64_mylibrary.h"
#include "x64_IR.h"
bool x64_contain_iterators(ea_t ea);
void x64_iterator_handler(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type);
bool is_iterator_source_insn(ea_t ea);
std::string extract_iterator_var(ea_t ea, int operand_num);
bool right_op_is_iterator(ea_t ea);
bool left_op_is_iterator(ea_t ea);
bool left_op_contain_iterator(ea_t ea);
bool right_op_contain_iterator(ea_t ea);
bool x64_contain_iterators_v1(ea_t ea);
void x64_iterator_handler_v1(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type);