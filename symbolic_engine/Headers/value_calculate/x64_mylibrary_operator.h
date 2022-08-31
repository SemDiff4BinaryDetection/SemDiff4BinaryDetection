#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "x64_mylibrary_register.h"
#include "../../Headers/value_calculate/common_library.h"
#pragma once
std::string x64_get_operand(ea_t ea, int index);

int x64_is_use_stmt(qstring Mnem,ea_t ea, int which_op);
int x64_count_comma(std::string disasm);

int x64_count_comma_ea(ea_t ea);
bool has_single_operand(ea_t ea);