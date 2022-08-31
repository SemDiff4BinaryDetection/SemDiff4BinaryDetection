#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "ARM_while_handler.h"
void ARM_re_update_each_insn(ea_t ea, func_t* func);
int ARM_sub_iter_handler(std::string Mnem, std::string operand0, std::string operand1, std::string operand2, std::string operand3, int mode);
void ARM_create_new_tmp_ARM_my_instruction(std::string operand, std::string operand1);
void ARM_iter_propagate_to_operand(std::string defined_value, int index);
void ARM_create_new_tmp_x64_my_instruction(std::string operand, std::string operand1);
void ARM_iter_LDR_type4_register_offset(std::string operand1);//LDR, reg, [reg {,num}] 
void ARM_iter_LDR_type4_pre_indexed(std::string operand1);// LDR, reg, [reg {,num}]! 
void ARM_iter_LDR_type4_post_indexed(std::string operand1);//LDR, reg, [reg], num  
void ARM_iter_LDR_type3_register_offset(std::string operand1);
void ARM_iter_LDR_type3_pre_indexed(std::string operand1);
void ARM_iter_LDR_type3_post_indexed(std::string operand1);
void ARM_iter_STR_type4_post_indexed(std::string operand0, std::string operand1);
void ARM_iter_STR_type4_pre_indexed(std::string operand0, std::string operand1);
void ARM_iter_STR_type4_register_offset(std::string operand0, std::string operand1);
void ARM_iter_STR_type3_post_indexed(std::string operand0, std::string operand1);
void ARM_iter_STR_type3_pre_indexed(std::string operand0, std::string operand1);
void ARM_iter_STR_type3_register_offset(std::string operand0, std::string operand1);
void ARM_iter_process_LDM(std::string operand0, std::string operand1);
void ARM_iter_process_STM(std::string operand0, std::string operand1);
void ARM_iter_arithmatic_propagate_reg_reg_reg(std::string operand1, std::string operand2, std::string Mnem);
void ARM_iter_arithmatic_propagate_reg_reg_shift(std::string operand1, std::string operand2, std::string Mnem);
void ARM_iter_arithmatic_propagate_reg_reg_num(std::string operand1, std::string operand2, std::string Mnem);
void ARM_iter_arithmatic_propagate_reg_reg(std::string operand0, std::string operand1, std::string Mnem);
void ARM_iter_arithmatic_propagate_reg_shift(std::string operand0, std::string operand1, std::string Mnem);
void ARM_iter_arithmatic_propagate_reg_num(std::string operand0, std::string operand1, std::string Mnem);
std::string ARM_iter_lookForDefine(std::string operand);
std::string ARM_iter_process_shift_operand(std::string operand, int index);
std::string ARM_iter_translate_type3_register_offset(std::string operand, std::string defined_value1, std::string defined_value2);
void ARM_iter_look_for_displ(int operand_num);
void ARM_iter_LDRD_type4_post_indexed(std::string operand1);
void ARM_iter_LDRD_type4_pre_indexed(std::string operand1);
void ARM_iter_LDRD_type4_register_offset(std::string operand1);
void ARM_iter_STRD_type4_register_offset(std::string operand0, std::string operand1, std::string operand2);
void ARM_iter_STRD_type4_pre_indexed(std::string operand0, std::string operand1, std::string operand2);
void ARM_iter_STRD_type4_post_indexed(std::string operand0, std::string operand1, std::string operand2);