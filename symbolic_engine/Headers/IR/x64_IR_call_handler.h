#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../value_calculate/x64_mylibrary.h"
#include "x64_IR.h"
void init_x64_my_insn_IR(func_t* func);
std::vector <std::string>  x64_windows_look_for_parameters(ea_t ea, func_t* func);
std::vector <std::string>  x64_linux_look_for_parameters(ea_t ea, func_t* func);
std::vector  <std::string> x64_look_for_parameters(ea_t ea, func_t* func);
std::string x64_look_for_parameter_define(std::string reg, ea_t ea, func_t* func);
std::vector <std::string> x64_look_for_stack_parameters(ea_t ea, func_t* func);
bool x64_is_stack_parameter(std::string operand0);
std::vector <std::string> x64_sort_stack_parameters(std::vector <std::string> stack_parameters);
int x64_extract_stack_offset(std::string stack_expression);
void x64_calculate_stack_value(std::string* stack_operand);
int x64_iterate_calculate(std::string stack_operand);
void x64_translate_return_value(ea_t ea,func_t* func);
bool x64_not_jump_insn(ea_t ea);
bool x64_is_joint_node(ea_t ea);
std::string x64_windows_look_for_parameter_n(int param_n, ea_t ea, func_t* func);
std::string x64_linux_look_for_parameter_n(int param_n, ea_t ea, func_t* func);