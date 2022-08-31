#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include <vector>
#include "ARM_my_library_operator.h"
#include "ARM_mylibrary_wheel.h"
//#include "../cross_arch_preprocessor/ARM_preprocessor.h"
//#include "../../Headers/value_calculate/ARM_while_handler.h"

extern int DWORD_LEN;
extern struct ARM_my_instruction {
	std::string operand0;
	std::string operand1;
	std::string operand2;
	std::string operand3;
	std::map<std::string, std::string> parameters0;
	std::map<std::string, std::string> parameters1;
	std::map<std::string, std::string> parameters2;
	std::map<std::string, std::string> parameters3;
};

extern std::vector <ARM_my_instruction> ARM_my_insn;
extern std::map<int, int> ea2ARM_my_insn;
extern std::vector<char> ARM_iterate_mark;

void ARM_init_ARM_my_instruction(func_t* func);
//void ARM_infer_this_insn_propagate_next(func_t* func, ea_t ea);
std::string ARM_process_shift_operand(std::string operand, int index, ea_t ea, func_t* func);
void ARM_arithmatic_propagate_reg_reg_reg(std::string operand1, std::string operand2, ea_t ea, func_t* func, std::string Mnem);
void ARM_arithmatic_propagate_reg_reg_num(std::string operand1, std::string operand2, ea_t ea, func_t* func, std::string Mnem);
void ARM_arithmatic_propagate_reg_reg_shift(std::string operand1, std::string operand2, ea_t ea, func_t* func, std::string Mnem);
void ARM_arithmatic_propagate_reg_reg(std::string operand0, std::string operand1, ea_t ea, func_t* func, std::string Mnem);
void ARM_arithmatic_propagate_reg_shift(std::string operand0, std::string operand1, ea_t ea, func_t* func, std::string Mnem);
void ARM_arithmatic_propagate_reg_num(std::string operand0, std::string operand1, ea_t ea, func_t* func, std::string Mnem);
void ARM_clear_ARM_my_insn(ea_t ea);
void ARM_init_ARM_my_instruction(func_t* func);
std::string ARM_translate_type4_bracket(std::string operand);
void ARM_LDR_type4_register_offset(std::string operand1, ea_t ea, func_t* func);
void ARM_LDR_type4_pre_indexed(std::string operand1, ea_t ea, func_t* func);
void ARM_LDR_type4_post_indexed(std::string operand1, ea_t ea, func_t* func);
void ARM_LDR_type3_register_offset(std::string operand1, ea_t ea, func_t * func);
void ARM_LDR_type3_pre_indexed(std::string operand1, ea_t ea, func_t* func);
void ARM_LDR_type3_post_indexed(std::string operand1, ea_t ea, func_t* func);
void ARM_process_switch_case(ea_t ea, func_t* func, std::string operand0, std::string operand1, std::string operand2);

void ARM_STR_type3_register_offset(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_STR_type3_pre_indexed(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_STR_type3_post_indexed(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_STR_type4_register_offset(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_STR_type4_pre_indexed(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_STR_type4_post_indexed(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_process_LDM(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_process_STM(std::string operand0, std::string operand1, ea_t ea, func_t* func);
void ARM_LDRD_type4_register_offset(std::string operand2, ea_t ea, func_t* func);
void ARM_LDRD_type4_pre_indexed(std::string operand2, ea_t ea, func_t* func);
void ARM_LDRD_type4_post_indexed(std::string operand2, ea_t ea, func_t* func);
void ARM_STRD_type4_register_offset(std::string operand0, std::string operand1,std::string operand2, ea_t ea, func_t* func);
void ARM_STRD_type4_pre_indexed(std::string operand0, std::string operand1, std::string operand2, ea_t ea, func_t* func);
void ARM_STRD_type4_post_indexed(std::string operand0, std::string operand1, std::string operand2, ea_t ea, func_t* func);
std::string ARM_get_label_value(std::string operand, func_t* func);
std::string ARM_numerize_offset(std::string operand);
bool ARM_is_code_ea(ea_t ea);
void arm_convert_operand2offset_type(ea_t ea);