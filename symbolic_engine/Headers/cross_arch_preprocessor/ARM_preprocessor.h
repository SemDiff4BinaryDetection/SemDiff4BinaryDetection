#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../../Headers/value_calculate/ARM_mylibrary.h"
#include "../../Headers/IR/ARM_IR.h"
#include "../value_calculate/ARM_update.h"
#include "../../Headers/value_calculate/common_library.h"
#include "../../Headers/value_calculate/ARM_while_handler.h"
int ARM_findUpdate(ea_t ea, func_t* func);
void ARM_random_infer_this_insn_propagate_next(func_t* func, ea_t ea);
void ARM_infer_conditional_block(ea_t ea,func_t *func);
ea_t ARM_find_conditional_block_end(ea_t ea,func_t * func);
std::vector<char> ARM_extract_flags_used_in_block(ea_t block_start, ea_t block_end);
std::vector <std::map <char, int>> ARM_combine_flags(std::vector<char> flags_set);
void ARM_infer_conditional_block_with_one_possibility(ea_t block_start, ea_t block_end, std::map <char, int> flag_combination,func_t * func);
bool ARM_flag_satisfy_condition(std::map <char, int> flag_combination, std::string Mnem);
void ARM_iterate_clean_ARM_my_insn(ea_t ea, func_t* func);
void ARM_analyze_conditional_jump(func_t* func);
void ARM_generate_conditional_jump_map(ea_t ea, ea_t next_ea, ea_t far_ea, std::string Mnem);
void ARM_generate_conditional_jump_map4between_insns(ea_t last_cmp, ea_t jump_ea,ea_t next_IR, ea_t far_IR, std::string Mnem);