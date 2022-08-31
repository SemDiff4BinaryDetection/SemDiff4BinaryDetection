#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <regex>
#include<name.hpp>
extern int variable_number;
extern std::map <ea_t, ea_t> insn_last_insn;
extern std::vector <ea_t> iter_source;
extern std::vector<std::string> uncalculatable_function_names;
int count_ea_operands(ea_t ea);
extern std::map <ea_t, int> recalculated_yet_map;
extern std::map <std::string, std::string> conditional_jump_map;
extern std::string file_type;
std::string trim_begin_end_space(std::string string1);

std::string remove_comment(std::string string1);

//remove "ptr word" in "ptr word [eax+5]"
std::string remove_adjective(std::string string1);
std::string groom_string(std::string string1);
int get_optype(ea_t ea, int index);
void initialize_global_variable();


bool is_in_loop(ea_t ea, ea_t next_ea, func_t* func);

std::string dec2hex(int i);
bool not_resolvable(std::string to_resolve);
std::string get_next_element(std::string operand, int* index);
//void reset_iter_source();
void random_swap(ea_t& next_ea, ea_t& next_ea1);
bool insn_has_not_been_touched(ea_t ea, func_t* func);
void put_loop_first(ea_t & next_ea, ea_t & next_ea1,ea_t ea, func_t * func);
std::string arm_allocate_new_variable(std::string);
std::vector <ea_t> find_first_child_of(ea_t ea);
bool insn_not_recalculate_yet(ea_t ea);
void init_conditional_jump_map();
void print_conditional_jump(std::string working_path);
bool is_loop_update(std::string before, std::string after);
std::string clean_number(std::string num_string);
int get_next_none_Mnem(int index, std::string operand);
bool is_calculatable_stack(std::string operand);
bool is_hex_string(std::string operand);
void print_to_time_out_functions(std::string timeout_report, std::string time_out_functions);
std::string strip_disp(std::string disp);
void print_uncalcuulateble_functions(std::string this_binary_path);
std::string filter_specific_string(std::string label_string);
//std::string get_reg_name(ea_t ea, int index);
void add_uncalculatable_function(ea_t ea);
std::string get_label_value(std::string label);
std::string lldec2hex(long long int i);
std::string ldec2hex(long int i);
std::string x64_windows_allocate_new_variable(std::string operand);
std::string x64_linux_allocate_new_variable(std::string operand);
std::string x64_allocate_new_variable(std::string operand);
bool is_number(std::string* string1);
std::vector <std::string>  translate_address_parameter_to_string_or_value(std::vector <std::string>  result_parameters);