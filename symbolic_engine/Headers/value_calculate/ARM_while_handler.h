#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "ARM_mylibrary.h"
#include "ARM_update.h"
#include "ARM_iterator_propagate_handler.h"
#include "../../Headers/cross_arch_preprocessor/ARM_preprocessor.h"
extern std::vector <ea_t> tmp_ARM_insn_record;
extern std::vector <ARM_my_instruction> tmp_ARM_my_insn;
extern std::vector<std::string> debug_iter_sinsn;
extern int ARM_iterator_variable;
void ARM_recalculate_for_while(ea_t ea, ea_t next_ea, func_t* func);
void ARM_init_tmp_ARM_insn_record(ea_t ea, ea_t next_ea);
void ARM_init_tmp_ARM_my_insn(ea_t ea, ea_t next_ea);
void ARM_is_iter_source(ea_t ea,int loop_block_insn_num);
void ARM_replace_element_with_iterator(ea_t ea, std::string diff);
std::string ARM_allocate_iterator_var();
void ARM_tmp_copy_to_my_insn(ea_t start, ea_t end, int loop_block_insn_num);
void ARM_clean_tmp();
void ARM_init_iterator_var();
int find_bracket_level(std::string after);
void ARM_process_loop(ea_t ea, ea_t next_ea, func_t* func);
void ARM_change_operand_if_modified(ea_t ea);
void ARM_recalculate_loop(ea_t ea, ea_t next_ea, func_t* func);
int ARM_loop_updated(int loop_block_insn_num);
void ARM_recalculate_for_while_v1(ea_t ea, ea_t next_ea, func_t* func);