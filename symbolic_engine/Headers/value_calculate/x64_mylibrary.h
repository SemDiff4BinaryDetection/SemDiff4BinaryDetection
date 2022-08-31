#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include <vector>
#include <bytes.hpp>
#include "x64_mylibrary_wheel.h"
#include "x64_mylibrary_operator.h"
//#include "x64_while_handler.h"
#include <algorithm>



extern struct x64_my_instruction {
	std::string operand0;
	std::string operand1;
	std::map<std::string, std::string> parameters0;
	std::map<std::string, std::string> parameters1;
};
extern std::vector <x64_my_instruction> x64_my_insn; 
extern std::map<int, int> ea2x64_my_insn;
extern std::vector<char> x64_iterate_mark;

 void init_x64_my_instruction(func_t* func);

 void x64_propagate_to_right_operand(ea_t ea, std::string value);

 void x64_propagate_to_right_left_operand(ea_t ea, std::string defined_value);

 void x64_only_Rbase_is_defined_propagate(ea_t ea, std::string operand0,std::string defined_value,std::string defined_value1, func_t* func);


 void x64_even_Rbase_is_not_defined_propagate(ea_t ea, func_t* func,std::string operand0,std::string left_op,std::string operand1);


 void x64_Ldefined_base_propagate(ea_t ea, std::string defined_value,std::string value, func_t* func);

 void x64_even_Lundefined_base_propagate(ea_t ea,std::string value, func_t* func,std::string operand0);

 
 void x64_even_Rbase_is_not_defined_sub_update(ea_t ea, func_t * func, std::string defined_value);
 std::string x64_extract_value_from_insn(ea_t ea, int i, func_t* func);
 void x64_further_explain_displace(ea_t ea, int operand_num, func_t* func,int index);
 void x64_display_results(func_t* func);
 void x64_lea_explain_member_propagate(ea_t ea, func_t* func);
 void x64_lea_extract_string_content_propagate(ea_t ea, func_t* func,std::string operand0,std::string operand1);
 void x64_arithmatic_propagate_reg_label(std::string operand_to_decide, std::string defined_value, ea_t ea, std::string Mnem);

 void x64_propagate_to_left_operand(ea_t ea, std::string defined_value);
 void x64_get_reg_val(ea_t ea, std::string operand, func_t* func, std::string& defined_value);
 
 void x64_arithmatic_propagate_reg_reg(std::string operand_to_decide, std::string defined_value, std::string defined_value1, ea_t ea, std::string Mnem);

 void x64_arithmatic_propagate_reg_displ(std::string operand_to_decide,std::string defined_value, ea_t ea, std::string Mnem);

 void x64_arithmatic_propagate_reg_num(std::string operand_to_decide,std::string defined_value, ea_t ea, std::string Mnem);

 void x64_arithmatic_propagate_displ_reg(std::string operand_to_decide,std::string defined_value, ea_t ea, std::string Mnem);

 void x64_arithmatic_propagate_displ_num(ea_t ea, std::string Mnem);
 void x64_arithmatic_propagate_reg_reg_num(std::string operand_to_decide, std::string defined_value, std::string defined_value1, std::string num, ea_t ea, std::string Mnem);
 void x64_arithmatic_propagate_reg_disp_num(std::string operand_to_decide,ea_t ea, std::string Mnem,std::string defined_value1);

void x64_div_propagate_reg(std::string operand_to_decide, std::string defined_value, ea_t ea, func_t *func, std::string Mnem);
void x64_div_propagate_disp(ea_t ea, func_t* func, std::string Mnem);
bool x64_is_pop_insn(ea_t ea);

void x64_print_path(ea_t ea,func_t * func);

void x64_get_disp_val(ea_t ea, int index, std::string operand, func_t* func);
//void x64_clear_all();

std::string sub_shift(std::string defined_value, std::string operand0, std::string operand1, std::string shift);
std::string x64_get_right_sub_reg(std::string operand_to_decide,std::string left_op,std::string right_op);
void x64_mul_single_propagate_reg(std::string operand_to_decide, std::string defined_value, ea_t ea, func_t *func, std::string Mnem);
void x64_mul_single_propagate_disp(ea_t ea, func_t * func, std::string Mnem);
std::vector<std::string> split_expression(std::string expression);
bool x64_is_within_size(std::string operand, long long int size);
std::string x64_rotate_shift_reg(std::string operand_to_decide, std::string operand0, std::string operand1, std::string Mnem);
std::string x64_rotate_shift_disp(std::string instruction, std::string operand0, std::string operand1, std::string Mnem);
bool x64_is_conditional_insn(ea_t ea);
std::string x64_arithmatic_result_basedon_size(std::string left, std::string right, std::string operand_size, std::string Mnem);
std::string x64_punpck(std::string operand_to_decide, std::string defined_value, std::string defined_value1, std::string Mnem);
void x64_convert_operand2offset_type(ea_t ea);
void x64_arithmatic_propagate_displ_label(ea_t ea, std::string Mnem);
std::string x64_get_root(std::string Mnem);
void x64_stos(ea_t ea,std::string operand0, func_t* func);
void x64_scas(ea_t ea, std::string operand0, func_t* func);
std::string x64_rectify_specific_Mnem(std::string Mnem, std::string keyword, ea_t ea, int op1_type);
void x64_movs(ea_t ea, func_t* func, std::string operand0, std::string operand1);
std::string x64_movd(std::string operand0, std::string defined_value, std::string defined_value1);
std::string x64_movq(std::string operand0, std::string operand1, std::string defined_value, std::string defined_value1);
void check_windows_or_linux();
void x64_div_propagate_label(std::string label_operand, ea_t ea, func_t* func, std::string Mnem);