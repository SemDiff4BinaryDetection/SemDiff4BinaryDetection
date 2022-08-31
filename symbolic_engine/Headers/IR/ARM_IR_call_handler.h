#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../../Headers/value_calculate/common_library.h"
#include "../../Headers/value_calculate/ARM_mylibrary.h"
#include "ARM_IR.h"
void ARM_translate_return_value(ea_t ea, func_t* func);
std::vector <std::string>  ARM_look_for_parameters(ea_t ea, func_t* func);
std::string ARM_look_for_parameter_define(std::string reg, ea_t ea, func_t* func);
std::vector <std::string> ARM_look_for_stack_parameters(ea_t ea, func_t* func);
bool ARM_is_stack_parameter(std::string operand);
std::vector <std::string> ARM_sort_stack_parameters(std::vector <std::string> stack_parameters);
int ARM_extract_stack_offset(std::string stack_expression);
void ARM_calculate_stack_value(std::string* stack_operand);
int ARM_iterate_calculate(std::string stack_operand);
bool ARM_not_jump_insn(ea_t ea);
bool arm_is_joint_node(ea_t ea);