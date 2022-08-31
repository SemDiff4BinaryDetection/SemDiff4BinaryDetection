#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <ua.hpp>
#include <name.hpp>
#pragma once
std::string x64_extractBase(std::string operand);
void x64_define_base(ea_t ea, int operand_num, std::string value);
std::string x64_lookForDefine(std::string operand, ea_t ea, func_t* func);
void x64_redefine(ea_t ea, std::string defined_value, std::string new_value);
void x64_replace_element(ea_t ea, int operand_num, std::string resolvable, std::string result, int* index);
std::string x64_resolve(ea_t ea, std::string resolvable, func_t* func);
std::string x64_extract_value_from_insn(ea_t ea, int i, func_t* func);
std::string x64_extract_parameter_value_from_insn(ea_t ea, int i, func_t* func, std::string operand);
void x64_look_for_same_displ(int operand_num, ea_t ea,func_t * func);
bool is_in_loop(ea_t ea, int num);
//void x64_recover_renamed_register(ea_t ea,std::string* operand0, std::string* operand1, std::string* operand2, int op0_type, int op1_type, int op2_type, int ea_operand_num);
bool x64_is_not_calculatable(ea_t ea);
bool x64_Mnem_not_support(ea_t ea);
bool x64_is_symbolic_value_explosion(ea_t ea);
bool x64_is_switch_jump(ea_t ea);
bool x64_is_number(std::string* operand);
std::string x64_look_for_define_in_argument(std::string operand);
std::string check_define_in_argument(int index, std::string operand, func_t* func,std::string return_val);