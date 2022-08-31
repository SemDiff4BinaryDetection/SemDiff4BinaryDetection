#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include "../value_calculate/ARM_mylibrary.h"
#include "ARM_IR.h"
bool ARM_contain_iterators(ea_t ea);
void ARM_iterator_handler(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type);
bool first_op_contain_iterator(ea_t ea);
bool second_op_contain_iterator(ea_t ea);
bool third_op_contain_iterator(ea_t ea);
bool fourth_op_contain_iterator(ea_t ea);
std::string ARM_translate_bracket(std::string operand);
bool ARM_contain_shifter(std::string operand);
bool ARM_contain_iterators_v1(ea_t ea);
void ARM_iterator_handler_v1(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type);