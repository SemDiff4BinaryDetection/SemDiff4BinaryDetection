#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <ua.hpp>
//#include "../../Headers/value_calculate/mylibrary.h"
//#include "../../Headers/IR/IR.h"
int MIPS_findUpdate(ea_t ea, func_t* func);
void MIPS_infer_this_insn_propagate_next(func_t* func, ea_t ea);
