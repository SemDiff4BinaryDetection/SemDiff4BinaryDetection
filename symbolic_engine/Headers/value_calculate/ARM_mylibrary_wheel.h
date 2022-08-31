#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "common_library.h"
#include "ARM_my_library_operator.h"
#include "ARM_mylibrary.h"
#include <frame.hpp>
std::string ARM_lookForDefine(std::string operand, ea_t ea, func_t* func);
std::string ARM_check_each_operand(ea_t index, std::string operand, bool & found_reg_occur);
bool ARM_is_below_16_bit_const(std::string tmp);
std::string ARM_extract_value_from_insn(ea_t ea, int i);
std::string ARM_extract_parameter_value_from_insn(ea_t ea, int i,std::string operand);
std::string ARM_extract_shift_mnem(std::string operand);
std::string ARM_extract_shift_base(std::string operand, std::string shift_mnem);
std::string ARM_extract_shift_offset(std::string operand, std::string shift_mnem);
bool is_ARM_register(std::string operand);
void ARM_convert_to_code(ea_t ea);
bool ARM_is_data_segment(ea_t ea);
bool ARM_not_junping_insn(ea_t ea);
bool ARM_is_regiter_offset(std::string operand);
bool ARM_is_pre_indexed(std::string operand);
bool ARM_is_post_indexed(std::string operand);
std::string ARM_replace_comma_with_plus(std::string operand);
bool ARM_is_pop_insn(ea_t ea);
std::string ARM_translate_shift(std::string operand1);
void ARM_propagate_to_operand(ea_t ea, std::string defined_value, int index);
std::string ARM_extract_bracket_base(std::string operand);
std::string ARM_translate_type4_register_offset(std::string operand, std::string defined_value);
std::string ARM_extract_bracket_second_register(std::string operand, bool & minus);
std::string ARM_translate_type3_register_offset(std::string operand, std::string defined_value1, std::string defined_value2,ea_t ea, func_t* func);
std::vector<std::string> ARM_get_reg_list(std::string operand);
std::vector<std::string> ARM_get_regs_from_range(std::string reg_range);
std::string ARM_find_last_compare_const(std::string operand, ea_t ea, func_t* func);
void ARM_look_for_displ(ea_t ea, func_t* func,int target_operand_num);
void ARM_look_for_same_displ(int operand_num, ea_t ea, func_t* func);
bool ARM_contain_register(std::string long_string, std::string reg);
//std::string get_STRD_value_if_defined(std::string operand, ea_t ea);
bool ARM_is_symbolic_value_explosion(ea_t ea);
bool ARM_is_not_calculatable(ea_t ea);
bool ARM_Mnem_not_support(ea_t ea);
std::string ARM_translate_LDRD_STRD_second_op(std::string ea);
std::string ARM_clear_num_string(std::string string);
void ARM_unname_all_regs(func_t* func);