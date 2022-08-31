#include "../../Headers/cross_arch_preprocessor/MIPS_proprecessor.h"

int MIPS_findUpdate(ea_t ea, func_t* func)
{
	return 0;
}
void MIPS_infer_this_insn_propagate_next(func_t* func, ea_t ea)
{
	if (is_pop_insn(ea))
	{
		init_IR_reserve_insns(func);
		//translate_loop_insns(ea,func); 
		init_x64_my_insn_IR(func);
		translate_return_value(ea, func);
		translate_each_insn(func);
		print_to_file(ea, func);
		//print_path(ea,func);
		return;
	}

	x64_my_insn[ea2x64_my_insn[ea]].operand0 = "";
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.clear();
	x64_my_insn[ea2x64_my_insn[ea]].operand1 = "";
	x64_my_insn[ea2x64_my_insn[ea]].parameters1.clear();
	ea_t next_ea, next_ea1;
	MIPS_findUpdate(ea, func);
	next_ea = get_first_cref_from(ea);
	next_ea1 = get_next_cref_from(ea, next_ea);

	if (next_ea != -1 && is_in_loop(ea, next_ea, func))
	{


		recalculate_for_while(ea, next_ea, func);
		next_ea = -1;
	}

	if (next_ea1 != -1 && is_in_loop(ea, next_ea1, func))
	{


		recalculate_for_while(ea, next_ea1, func);
		next_ea1 = -1;

	}


	if (next_ea != -1 && next_ea != BADADDR && next_ea >= func->start_ea && next_ea <= func->end_ea)
	{

		insn_last_insn[next_ea] = ea;
		MIPS_infer_this_insn_propagate_next(func, next_ea);


		if (next_ea1 != -1 && next_ea1 >= func->start_ea && next_ea1 <= func->end_ea)
		{

			insn_last_insn[next_ea1] = ea;
			MIPS_infer_this_insn_propagate_next(func, next_ea1);

		}
	}


}