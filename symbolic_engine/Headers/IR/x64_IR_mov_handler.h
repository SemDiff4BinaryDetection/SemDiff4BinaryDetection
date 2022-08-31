#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../value_calculate/x64_mylibrary.h"
#include <iostream>
void explain_displ(ea_t ea);
bool is_multi_level_stru(std::string operand0);
std::string transform_to_c_stru(std::string operand0);
std::string extract_offset(int inner_most_right_bracket, std::string operand0);
int last_left_bracket(int inner_most_left_bracket, std::string operand0);
int next_right_bracket(int inner_most_right_bracket, std::string operand0);
//void reserve_loop(ea_t ea, ea_t next_ea, func_t * func);
void init_IR_reserve_insns(func_t* func);
ea_t find_last_compare(ea_t ea, ea_t next_ea, func_t* func);
//void translate_decide_insn(ea_t last_compare_insn);
//void reserve_insn(ea_t index, int operand_index, std::string iterator_variable);


//void translate_loop_insns(ea_t ea, func_t* func);
