#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../value_calculate/x64_update.h"
#include "../value_calculate/x64_mylibrary.h"
#include "../IR/x64_IR.h"
#include "../../Headers/value_calculate/common_library.h"
#include "../../Headers/value_calculate/x64_while_handler.h"
extern std::map <std::string, int> x64_Mnem2index;
int x64_findUpdate(ea_t ea, func_t* func);
//int ARM_findUpdate(ea_t ea, func_t* func);
//int MIPS_findUpdate(ea_t ea, func_t* func);
//void x64_infer_this_insn_propagate_next(func_t* func, ea_t ea);
//void ARM_infer_this_insn_propagate_next(func_t* func, ea_t ea);
//void MIPS_infer_this_insn_propagate_next(func_t* func, ea_t ea);
void x64_random_infer_this_insn_propagate_next(func_t* func, ea_t ea);
void x64_random_infer_cinditional_insn(func_t* func, ea_t ea);
void x64_findUpdate_cmov(std::string thread_num, ea_t ea, func_t* func);
void x64_iterate_clean_x64_my_insn(ea_t ea, func_t* func);
void init_recalculated_yet_map();
void x64_analyze_conditional_jump(func_t* func);
void x64_generate_conditional_jump_map(ea_t ea, ea_t next_ea, ea_t far_ea, std::string Mnem);
void x64_generate_conditional_jump_map4between_insns(ea_t last_cmp, ea_t jump_ea, ea_t next_IR, ea_t far_IR, std::string Mnem);