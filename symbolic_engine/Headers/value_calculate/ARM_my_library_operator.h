#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
#include "../../Headers/value_calculate/common_library.h"
int ARM_count_comma(std::string disasm);
int ARM_last_real_comma(std::string string1);
int ARM_first_real_comma(std::string string1);
bool ARM_comma_not_in_offset(std::string disasm, int i);
std::string ARM_get_operand(ea_t ea, int index);
bool ARM_is_below_16_bit_const(std::string tmp);
std::string ARM_contain_equal_register(std::string reg1, std::string reg2);
int ARM_is_use_stmt(qstring Mnem, ea_t ea, int which_op);