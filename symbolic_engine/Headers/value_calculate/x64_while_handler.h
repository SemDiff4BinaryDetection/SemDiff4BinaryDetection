#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "x64_mylibrary.h"
#include "x64_update.h"
#include "x64_iterator_propagate_handler.h"
#include "../../Headers/cross_arch_preprocessor/x64_preprocessor.h"

extern int x64_iterator_variable;
extern std::vector <ea_t> tmp_x64_insn_record;
extern std::vector <x64_my_instruction> tmp_x64_my_insn;
void x64_init_iterator_var();
std::string x64_allocate_iterator_var();
void x64_recalculate_for_while(ea_t ea, ea_t next_ea, func_t* func);
//void x64_init_tmp_insn_record(ea_t ea, ea_t next_ea);
void x64_init_tmp_x64_my_insn(ea_t ea, ea_t next_ea);
std::string x64_is_iter_source(int loop_block_insn_num);
void x64_replace_element_with_iterator(ea_t ea, std::string diff);
//bool x64_contain_iterators();
void x64_reserve_IR(ea_t ea);
void x64_clean_tmp();
void x64_tmp_copy_to_my_insn(ea_t start, ea_t end,int loop_block_insn_num);
/*ea_t find_last_compare(ea_t ea, ea_t next_ea, func_t* func);
void identify_iterator(ea_t last_compare_insn, ea_t next_ea, std::map<std::string, std::string>& map);
bool contain_iterator(ea_t ea, std::map<std::string, std::string> &map);
void x64_recalculate_each_insn(ea_t ea, std::map<std::string, std::string>& var_map, std::map<std::string, std::pair<ea_t, int>>line_map, func_t * func);
void find_iterator_first_occur(std::map<ea_t,ea_t>::iterator, ea_t end, std::map<std::string, std::pair<ea_t,int>> &line_map,std::vector <std::string> vector);
void clear_x64_my_insn(std::map <ea_t,ea_t>::iterator it, ea_t end);
bool is_iterator(ea_t ea, ea_t next_ea, int op_index);*/
void x64_init_tmp_x64_insn_record(ea_t ea, ea_t next_ea);
void x64_process_loop(ea_t ea, ea_t next_ea, func_t* func);
void x64_change_operand_if_modified(ea_t ea);
void x64_iteralize_operands(ea_t ea, ea_t next_ea, func_t* func);
void x64_mark_redundant_insns(ea_t ea, ea_t next_ea, func_t* func);
void x64_go_back_mark_if_cite(std::string Mnem, ea_t start_index, ea_t end_index, ea_t current_index);
std::vector<std::string> x64_operand_to_check(std::string Mnem, ea_t current_index);
void x64_mark_if_cite(std::vector<std::string> operand_to_check, ea_t ea);
void x64_recalculate_loop(ea_t ea, ea_t next_ea, func_t* func);
void x64_recalculate_for_while_v1(ea_t ea, ea_t next_ea, func_t* func);
int x64_loop_updated(int loop_block_insn_num);