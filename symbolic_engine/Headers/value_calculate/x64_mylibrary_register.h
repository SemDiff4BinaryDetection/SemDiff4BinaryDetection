#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include <vector>
#include <frame.hpp>
#pragma once
extern std::string registers[32][5];
extern int register_dimention1;
extern int register_dimentsion2;
int x64_is_equal_register(std::string reg1, std::string reg2);
std::vector<std::string> x64_get_equivalent_registers(std::string reg);
std::string x64_contain_equal_register(std::string reg1, std::string reg2);
std::string which_operand_size(std::string operand);
bool has_this_register(std::vector<std::string> expression_list,std::string reg);
std::string which_operand_size(ea_t ea);
bool x64_is_register(std::string string);
bool x64_contain_register(std::string long_string, std::string reg);
void x64_unname_all_regs(func_t* func);