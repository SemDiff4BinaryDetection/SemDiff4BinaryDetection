#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "x64_while_handler.h"
void x64_re_update_each_insn(ea_t ea, func_t* func);
int x64_sub_iter_handler(std::string operand0, std::string operand1, std::string operand2, int mode,ea_t ea);
int x64_sub_iter_handler(std::string operand0, std::string operand1, std::string operand2, int mode, std::string Mnem);
void x64_create_new_tmp_x64_my_instruction(int index, std::string operand);
void x64_create_new_tmp_x64_my_instruction(std::string operand, std::string operand1);
std::string x64_iter_lookForDefine(std::string operand);
void x64_iter_only_Rbase_is_defined_propagate(std::string operand_to_decide, std::string defined_value, std::string defined_value1, std::string Mnem);
void x64_iter_lea_explain_member_propagate();
void x64_iter_lea_extract_string_content_propagate(std::string operand0,std::string operand1);
void x64_iter_define_base(int index, std::string defined_value);
void x64_iter_further_explain_displace(int operand_num, int index);
void x64_iter_replace_element(int operand_num, std::string resolvable, std::string result, int* index);
std::string x64_iter_resolve(std::string to_resolve, int tmp_insn_index);
void x64_iter_get_reg_val(std::string operand, std::string& defined_value);
void x64_iter_get_disp_val(int index, std::string operand);void x64_iter_arithmatic_propagate_reg_reg(std::string operand_to_decide,std::string defined_value, std::string defined_value1, std::string Mnem);
void x64_iter_arithmatic_propagate_reg_displ(std::string operand_to_decide,std::string defined_value, std::string Mnem);
void x64_iter_arithmatic_propagate_reg_num(std::string operand_to_decide,std::string defined_value, std::string num, std::string Mnem);
void x64_iter_arithmatic_propagate_displ_reg(std::string operand_to_decide,std::string defined_value, std::string Mnem);
void x64_iter_arithmatic_propagate_displ_num(ea_t ea,std::string num, std::string Mnem);
void x64_iter_arithmatic_propagate_reg_reg_num(std::string operand_to_decide,std::string defined_value,std::string defined_value1, std::string num, std::string Mnem);
void x64_iter_arithmatic_propagate_reg_disp_num(ea_t ea,std::string defined_value,std::string num, std::string Mnem);
void x64_iter_div_propagate_reg(std::string operand_to_decide,std::string defined_value, std::string Mnem);
void x64_iter_div_propagate_disp(ea_t ea,std::string Mnem);
void x64_iter_Ldefined_base_propagate(std::string defined_value, std::string value,ea_t ea);
void x64_iter_look_for_same_displ(int operand_num);
/*std::string replace_all_iter_var(std::string insn_string, std::string reg, std::string iterator_var);
void iter_get_displ_reg_val(ea_t ea, func_t* func, std::string& defined_value, std::string& defined_value1, int operand_index, std::string reg, std::string iterator_var, std::string operand0, std::string operand1);
void iter_get_left_displ_val(ea_t ea, func_t* func, std::string& defined_value, std::string reg, std::string iterator_var, std::string operand0);
void iter_get_right_displ_val(ea_t ea, func_t* func, std::string& defined_value, std::string reg, std::string iterator_var, std::string operand1);*/
void x64_iter_mul_single_propagate_reg(std::string operand_to_decide, std::string defined_value, ea_t ea, std::string Mnem);
void x64_iter_mul_single_propagate_disp(ea_t ea, std::string Mnem);
void x64_iter_arithmatic_propagate_reg_label(std::string operand_to_decide, std::string defined_value, std::string operand1, std::string Mnem);
void x64_iter_arithmatic_propagate_displ_label(ea_t ea, std::string operand1, std::string Mnem);
void x64_iter_stos(ea_t ea, std::string operand0);
void x64_iter_scas(ea_t ea, std::string operand0);
void x64_iter_movs(ea_t ea, std::string operand0, std::string operand1);
void x64_iter_div_propagate_label(std::string label_operand, std::string Mnem);