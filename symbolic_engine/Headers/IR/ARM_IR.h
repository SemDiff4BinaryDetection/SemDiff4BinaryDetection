#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include <vector>
#include "../value_calculate/common_library.h"
#include "../value_calculate/ARM_mylibrary.h"
#include "ARM_IR_call_handler.h"
#include "ARM_IR_iterator.h"
extern int ARM_file_num;
extern std::vector <std::string> ARM_my_insn_IR;
void init_ARM_my_insn_IR(func_t* func);

void ARM_translate_each_insn(func_t* func);
void ARM_print_to_file(ea_t ea, std::string working_path,func_t* func);
void ARM_sub_IR(int num, ea_t ea, func_t* func);
void ARM_print_IR_file(std::string working_path,func_t* func);
void ARM_clear_each_random_run();
void ARM_delete_all_hash_tag(func_t* func);
void ARM_display_translate_result(func_t* func);
void ARM_translate_one_insn(ea_t ea, func_t* func);
bool ARM_contains_conditional_compare(ea_t ea);
bool ARM_is_conditional_insn(ea_t ea);
ea_t ARM_find_forward4key_IR(ea_t ea, func_t* func);
ea_t ARM_find_backward4cmp(ea_t ea, func_t* func);
std::vector <std::string> ARM_get_two_operands_original_value(ea_t ea, func_t *func);
std::string ARM_further_investigate_this_branch(ea_t ea, func_t* func);
std::string ARM_check_for_last_last_and_or(ea_t last_insn, std::string Mnem, func_t* func);
std::string ARM_explain_cc(ea_t ea, func_t* func,bool ea_is_last_cmp);
ea_t ARM_find_backward4define(std::string operand, ea_t ea, func_t* func);
//ea_t ARM_operand_from_and_or_insn(int index, ea_t ea, func_t* func);
std::vector<std::string> ARM_get_operands_list(ea_t ea);
bool ARM_look_backward_4_conditional(ea_t ea, func_t* func,bool ea_is_last_cmp_insn);
std::string ARM_translate_branching_insn(ea_t ea, func_t* func,bool ea_is_last_cmp,std::string operand);
bool ARM_is_add_pc_insn(ea_t ea);
bool ARM_is_common_Mnem(std::string root);