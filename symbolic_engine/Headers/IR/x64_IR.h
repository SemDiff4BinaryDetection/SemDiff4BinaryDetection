#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../value_calculate/x64_mylibrary.h"
#include <iostream>
#include "x64_IR_call_handler.h"
#include "x64_IR_mov_handler.h"
#include "../value_calculate/x64_mylibrary_operator.h"
#include <fpro.h>
#include "x64_IR_iterator.h"
//#include <fstream>
extern std::vector <std::string> x64_my_insn_IR;
extern std::string calling_convection[4][2];
extern std::vector <std::string> IR_reserve_insns;
extern int x64_file_num;
void x64_translate_all_insn(func_t* func);
void x64_sub_IR(int num, ea_t ea, func_t* func);
void x64_display_translate_result(func_t* func);
void x64_print_to_file(ea_t ea,std::string working_path, func_t* func);
void x64_print_IR_file(std::string working_path,func_t* func);
void x64_clear_each_random_run();
void x64_translate_one_insn(ea_t ea, func_t* func);
ea_t x64_find_forward4key_IR(ea_t ea, func_t* func);
ea_t x64_find_backward4cmp(ea_t ea, func_t* func);
std::string x64_further_investigate_this_branch(ea_t ea, func_t* func);
bool x64_look_backward_4_conditional(ea_t ea, func_t* func,bool ea_is_last_cmp);
std::vector<std::string> x64_get_operands_list(ea_t ea);
ea_t x64_find_backward4define(std::string operand, ea_t ea,func_t * func);
std::string x64_translate_branching_insn(ea_t ea, func_t* func,bool ea_is_last_cmp);
std::string  x64_explain_set(ea_t ea, func_t* func,bool ea_is_last_cmp);
std::string  x64_explain_cmov(ea_t ea, func_t* func,bool ea_is_last_cmp);
//ea_t x64_operand_from_and_or_insn(int index, ea_t ea, func_t* func);
std::string x64_check_for_last_last_and_or(ea_t last_insn, std::string Mnem, func_t* func);
std::vector<std::string> x64_get_original_operands(ea_t ea);
bool x64_is_movs(ea_t ea, std::string Mnem);
void x64_add_while_before_IR(ea_t ea);

