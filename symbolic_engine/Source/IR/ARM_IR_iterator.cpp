#include "../../Headers/IR/ARM_IR_iterator.h"

bool ARM_contain_iterators(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand0.find("ITERATOR") != -1)
		return true;
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("ITERATOR") != -1)
		return true;
	return false;
}

bool ARM_contain_iterators_v1(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.find("loop_origin") != ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.end())
		return true;
	return false;
}

void ARM_iterator_handler(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type)
{
	std::string tmp;

	if ((Mnem.find("MOV") != -1||Mnem.find("MVN")!=-1||Mnem.find("MVT")!=-1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
	{
		if (ARM_contain_shifter(ARM_get_operand(ea, 1)))
			tmp = ARM_translate_shift(ARM_get_operand(ea, 1));
		else
			tmp = ARM_get_operand(ea, 1);
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + tmp;
		
			
	}
	
	else if ((Mnem.find("LDR") != -1||Mnem.find("ADR")!=-1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
	{
		if (ea == 0x954)
			int bp = 0;
		if (ARM_contain_shifter(ARM_get_operand(ea, 1)))
			tmp = ARM_translate_shift(ARM_get_operand(ea, 1));
		else
			tmp = ARM_get_operand(ea, 1);
		if(ARM_is_regiter_offset(tmp))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) +"="+ ARM_translate_bracket(tmp);
		else if (ARM_is_pre_indexed(tmp))
		{
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_translate_bracket(tmp);
			if (op1_type == 3)
			{
				bool minus;
				func_t * func;
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] += "; " + ARM_extract_bracket_base(tmp) + "="\
					+ ARM_translate_type3_register_offset(tmp, ARM_extract_bracket_base(tmp),\
						ARM_extract_bracket_second_register(tmp, minus), ea, func);
			}
			else if (op1_type == 4)
			{
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] += "; " + ARM_extract_bracket_base(tmp) + "="\
					+ ARM_translate_type4_register_offset(tmp, ARM_extract_bracket_base(tmp));
			}

		}
		else if (ARM_is_post_indexed(tmp))
		{
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_translate_bracket(tmp);
			if (op1_type == 3)
			{
				bool minus;
				func_t* func;
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] += "; " + ARM_extract_bracket_base(tmp) + "="\
					+ ARM_translate_type3_register_offset(tmp, ARM_extract_bracket_base(tmp), \
						ARM_extract_bracket_second_register(tmp, minus), ea, func);
			}
			else if (op1_type == 4)
			{
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] += "; " + ARM_extract_bracket_base(tmp) + "="\
					+ ARM_translate_type4_register_offset(tmp, ARM_extract_bracket_base(tmp));
			}
		}
	}
	else if (Mnem.find("STR") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
	{
		if (ARM_contain_shifter(ARM_get_operand(ea, 1)))
			tmp = ARM_translate_shift(ARM_get_operand(ea, 1));
		else
			tmp = ARM_get_operand(ea, 1);
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_translate_bracket(tmp)+"="+ ARM_get_operand(ea, 0);
	}
	else if (Mnem.find("LDM") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
	{
		if (ARM_contain_shifter(ARM_get_operand(ea, 1)))
			tmp = ARM_translate_shift(ARM_get_operand(ea, 1));
		else
			tmp = ARM_get_operand(ea, 1);
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = tmp + "=" + ARM_get_operand(ea, 0);
	}
	else if (Mnem.find("SWP") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 2)+"; "+ ARM_get_operand(ea, 2)+"="+ARM_get_operand(ea, 1);
	}
	else if (Mnem.find("TST") != -1||Mnem.find("CMP")!=-1||Mnem.find("TEQ")!=-1||Mnem.find("CMN")!=-1)
	{
		if (ARM_contain_shifter(ARM_get_operand(ea, 1)))
			tmp = ARM_translate_shift(ARM_get_operand(ea, 1));
		else
			tmp = ARM_get_operand(ea, 1);
		if (!second_op_contain_iterator(ea) && first_op_contain_iterator(ea))
		{
			if(ARM_my_insn[ea2ARM_my_insn[ea]].operand1!="")
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] = "if " + ARM_get_operand(ea, 0) + "==" + ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
			else
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] = "if " + ARM_get_operand(ea, 0) + "==" + tmp;
		}
		else if (!first_op_contain_iterator(ea) && second_op_contain_iterator(ea))
		{
			if(ARM_my_insn[ea2ARM_my_insn[ea]].operand0!="")
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] = "if " + ARM_my_insn[ea2ARM_my_insn[ea]].operand0 + "==" + tmp;
			else
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] = "if " + ARM_get_operand(ea,0) + "==" + tmp;
		}
		else if (first_op_contain_iterator(ea) && second_op_contain_iterator(ea))
		{
			if (ARM_get_operand(ea, 0) == ARM_get_operand(ea, 1))
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] = "if " + ARM_get_operand(ea, 0) + "== 0";
			else ARM_my_insn_IR[ea2ARM_my_insn[ea]] = "if " + ARM_get_operand(ea, 0) + "==" + tmp;
		}
	}

	/*else if (Mnem.find("xor") != -1 && second_op_contain_iterator(ea))
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 1) + "=0";
	}*/

	else if ((Mnem.find("ADD") != -1||Mnem.find("ADC")!=-1))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
		if(op0_type!=0&&op1_type!=0&&op2_type!=0&& (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "+" + tmp;
		else if (op0_type != 0 && op1_type != 0 && op2_type == 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1);
	}

	else if ((Mnem.find("SUB") != -1||Mnem.find("SBC")!=-1))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
		if (op0_type != 0 && op1_type != 0 && op2_type != 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "-" + tmp;
		else if (op0_type != 0 && op1_type != 0 && op2_type == 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 0) + "-" + tmp;
	}
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
		if (op0_type != 0 && op1_type != 0 && op2_type != 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" +tmp + "-" + ARM_get_operand(ea, 1);
		else if (op0_type != 0 && op1_type != 0 && op2_type == 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "-" + ARM_get_operand(ea, 0);
	}

	else if (Mnem.find("MUL") != -1)
	{
		if (op0_type != 0 && op1_type != 0 && op2_type != 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2);
		else if (op0_type != 0 && op1_type != 0 && op2_type == 0 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)))
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 0) + "*" + ARM_get_operand(ea, 1);
	}
	else if (Mnem.find("MLA") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)||fourth_op_contain_iterator(ea)))
	{
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2)+ "+"+ARM_get_operand(ea, 3);
		
	}
	else if (Mnem.find("MLS") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + "-"+ARM_get_operand(ea, 3);

	}
	else if ((Mnem.find("UMULL") != -1||Mnem.find("SMULL")!=-1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 2) + "*" + ARM_get_operand(ea, 3)+"[LO]; "+ ARM_get_operand(ea, 1) + "=" + ARM_get_operand(ea, 2) + "*" + ARM_get_operand(ea, 3)+"[HI]";

	}
	else if ((Mnem.find("UMLAL") != -1 || Mnem.find("SMLAL") != -1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "="+ARM_get_operand(ea, 0)+"+" + ARM_get_operand(ea, 2) + "*" + ARM_get_operand(ea, 3) + "[LO]; " + ARM_get_operand(ea, 1) + "=" + ARM_get_operand(ea, 1) +"+"+ ARM_get_operand(ea, 2) + "*" + ARM_get_operand(ea, 3) + "[HI]";

	}
	else if ((Mnem.find("SMULT") != -1 || Mnem.find("SMULB") != -1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	if (Mnem == "SMULTB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1)+"[HI]" + "*" + ARM_get_operand(ea, 2) + "[LO]";
	else if (Mnem == "SMULTT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[HI]" + "*" + ARM_get_operand(ea, 2) + "[HI]";
	else if (Mnem == "SMULBB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[LO]" + "*" + ARM_get_operand(ea, 2) + "[LO]";
	else if (Mnem == "SMULBT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[LO]" + "*" + ARM_get_operand(ea, 2) + "[HI]";

	}
	else if ((Mnem.find("SMLAT") != -1 || Mnem.find("SMLAB") != -1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)||fourth_op_contain_iterator(ea)))
	{
	if (Mnem == "SMLATB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[HI]" + "*" + ARM_get_operand(ea, 2) + "[LO]"+"+"+ARM_get_operand(ea,3);
	else if (Mnem == "SMLATT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[HI]" + "*" + ARM_get_operand(ea, 2) + "[HI]"+"+"+ARM_get_operand(ea,3);
	else if (Mnem == "SMLABB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[LO]" + "*" + ARM_get_operand(ea, 2) + "[LO]"+"+"+ ARM_get_operand(ea, 3);
	else if (Mnem == "SMLABT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[LO]" + "*" + ARM_get_operand(ea, 2) + "[HI]" + "+" + ARM_get_operand(ea, 3);

	}
	else if (Mnem.find("SMULW") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	if (Mnem == "SMULWT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + "[HI]";
	else if(Mnem=="SMULB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + "[LO]";
	}
	else if (Mnem.find("SMLAW") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)||fourth_op_contain_iterator(ea)))
	{
	if (Mnem == "SMLAWT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + "[HI]"+"+"+ ARM_get_operand(ea, 3);
	else if (Mnem == "SMLAB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + "[LO]" + "+" + ARM_get_operand(ea, 3);
	}
	else if (Mnem.find("SMLAL") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	if (Mnem == "SMLALTB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 2) + "[HI]*" + ARM_get_operand(ea, 3) + "[LO]" + "+" + ARM_get_operand(ea, 0)+"+"+ ARM_get_operand(ea, 1)+"[LO]; "\
		+ ARM_get_operand(ea, 1) + "=" + ARM_get_operand(ea, 2) + "[HI]*" + ARM_get_operand(ea, 3) + "[LO]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[HI]";
	else if (Mnem == "SMLALTT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 2) + "[HI]*" + ARM_get_operand(ea, 3) + "[HI]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[LO]; "\
		+ ARM_get_operand(ea, 1) + "=" + ARM_get_operand(ea, 2) + "[HI]*" + ARM_get_operand(ea, 3) + "[HI]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[HI]";
	else if (Mnem == "SMLALBB")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 2) + "[LO]*" + ARM_get_operand(ea, 3) + "[LO]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[LO]; "\
		+ ARM_get_operand(ea, 1) + "=" + ARM_get_operand(ea, 2) + "[LO]*" + ARM_get_operand(ea, 3) + "[LO]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[HI]";
	else if (Mnem == "SMLALBT")
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 2) + "[LO]*" + ARM_get_operand(ea, 3) + "[HI]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[LO]; "\
		+ ARM_get_operand(ea, 1) + "=" + ARM_get_operand(ea, 2) + "[LO]*" + ARM_get_operand(ea, 3) + "[HI]" + "+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + "[HI]";
	}
	else if (Mnem.find("SMUAD") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[LO]*" + ARM_get_operand(ea, 2) + "[LO]+" + ARM_get_operand(ea, 1) + "[HI]*" + ARM_get_operand(ea, 2) + "[HI]";
	}
	else if (Mnem.find("SMUSD") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[LO]*" + ARM_get_operand(ea, 2) + "[LO]-" + ARM_get_operand(ea, 1) + "[HI]*" + ARM_get_operand(ea, 2) + "[HI]";
	}
	else if (Mnem.find("SMMUL") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=(" + ARM_get_operand(ea, 1)  +"*"+ ARM_get_operand(ea, 2) + ")[HI]";
	}
	else if (Mnem.find("SMMLA") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)||fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=(" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + ")[HI]+"+"+"+ ARM_get_operand(ea, 3);
	}
	else if (Mnem.find("SMMLS") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=(" + ARM_get_operand(ea, 1) + "*" + ARM_get_operand(ea, 2) + ")[HI]+" + "-" + ARM_get_operand(ea, 3);
	}
	else if (Mnem.find("SMLAD") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1)+"[HI]" + "*" + ARM_get_operand(ea, 2) + "[HI]" + "+" + ARM_get_operand(ea, 1) + "[LO]" + "*" \
		+ ARM_get_operand(ea, 2) + "[LO]+"+ ARM_get_operand(ea, 3);
	}
	else if (Mnem.find("SMLSD") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "[HI]" + "*" + ARM_get_operand(ea, 2) + "[HI]" + "-" + ARM_get_operand(ea, 1) + "[LO]" + "*" \
		+ ARM_get_operand(ea, 2) + "[LO]+" + ARM_get_operand(ea, 3);
	}
	else if (Mnem.find("SMLALD") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=(" + ARM_get_operand(ea, 2) + "[HI]" + "*" + ARM_get_operand(ea, 3) + "[HI]" + "+" + ARM_get_operand(ea, 2) + "[LO]" + "*" \
		+ ARM_get_operand(ea, 3) + "[LO]+" + ARM_get_operand(ea, 0)+ ":"+ARM_get_operand(ea, 1)+")[LO]; "+ ARM_get_operand(ea, 1) + "=(" + ARM_get_operand(ea, 2) + "[HI]" + "*" + \
		ARM_get_operand(ea, 3) + "[HI]" + "+" + ARM_get_operand(ea, 2) + "[LO]" + "*" \
		+ ARM_get_operand(ea, 3) + "[LO]+" + ARM_get_operand(ea, 0) + ":" + ARM_get_operand(ea, 1) + ")[HI]";
	}
	else if (Mnem.find("SMLSLD") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=(" + ARM_get_operand(ea, 2) + "[HI]" + "*" + ARM_get_operand(ea, 3) + "[HI]" + "-" + ARM_get_operand(ea, 2) + "[LO]" + "*" \
		+ ARM_get_operand(ea, 3) + "[LO]+" + ARM_get_operand(ea, 0) + ":" + ARM_get_operand(ea, 1) + ")[LO]; " + ARM_get_operand(ea, 1) + "=(" + ARM_get_operand(ea, 2) + "[HI]" + "*" + \
		ARM_get_operand(ea, 3) + "[HI]" + "-" + ARM_get_operand(ea, 2) + "[LO]" + "*" \
		+ ARM_get_operand(ea, 3) + "[LO]+" + ARM_get_operand(ea, 0) + ":" + ARM_get_operand(ea, 1) + ")[HI]";
	}
	else if (Mnem.find("UMAAL") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea) || fourth_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=(" + ARM_get_operand(ea, 2) + "*" + ARM_get_operand(ea, 3)  + "+"+ ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + ")[LO]; "\
		+ ARM_get_operand(ea, 1) + "=(" + ARM_get_operand(ea, 2) + "*" + \
		ARM_get_operand(ea, 3) +"+" + ARM_get_operand(ea, 0) + "+" + ARM_get_operand(ea, 1) + ")[HI]";
	}
	
	else if (Mnem.find("AND") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)||third_op_contain_iterator(ea)))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "&" + tmp;
	}
	
	else if (Mnem.find("ORR") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea)||third_op_contain_iterator(ea)))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "|" + tmp;
	}
	else if (Mnem.find("EOR") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "^" + tmp;
	}
	else if (Mnem.find("BIC") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "&!" + tmp;
	}
	else if (Mnem.find("ORN") != -1 && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	if (ARM_contain_shifter(ARM_get_operand(ea, 2)))
		tmp = ARM_translate_shift(ARM_get_operand(ea, 2));
	else
		tmp = ARM_get_operand(ea, 2);
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "|!" + tmp;
	}
	else if ((Mnem.find("REV") != -1||Mnem.find("RBIT")!=-1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=~" + ARM_get_operand(ea, 1);
	}
	else if ((Mnem.find("ASR") != -1 || Mnem.find("LSR") != -1||Mnem.find("ROR")!=-1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1)+">>"+ ARM_get_operand(ea, 2);
	}
	else if ((Mnem.find("LSL") != -1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + "<<" + ARM_get_operand(ea, 2);
	}
	else if ((Mnem.find("RRX") != -1) && (first_op_contain_iterator(ea) || second_op_contain_iterator(ea) || third_op_contain_iterator(ea)))
	{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_get_operand(ea, 0) + "=" + ARM_get_operand(ea, 1) + ">>>" + ARM_get_operand(ea, 2);
	}
}


bool first_op_contain_iterator(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand0.find("ITERATOR") != -1)
		return true;
	return false;
}

bool second_op_contain_iterator(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("ITERATOR") != -1)
		return true;
	return false;
}

bool third_op_contain_iterator(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("ITERATOR") != -1)
		return true;
	return false;
}

bool fourth_op_contain_iterator(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand3.find("ITERATOR") != -1)
		return true;
	return false;
}

std::string ARM_translate_bracket(std::string operand)
{
	int left_bracket = operand.find('[');
	int right_bracket = operand.find(']');
	if(left_bracket!=-1 && right_bracket!=-1 && right_bracket>left_bracket)
		operand = operand.substr(left_bracket, right_bracket - left_bracket+1);
	while (operand.find(',') != -1)
	{
		operand = operand.replace(operand.find(','), 1, "+");
	}
	while (operand.find('#')!=-1)
	{
		operand = operand.replace(operand.find('#'), 1, "");
	}
	return operand;
}

bool ARM_contain_shifter(std::string operand)
{
	if (operand.find("ASR") != -1 || operand.find("LSR") != -1 || operand.find("ROR") != -1 || operand.find("LSL") != -1\
		|| operand.find("RRX") != -1)
		return true;
	return false;
}

void ARM_iterator_handler_v1(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type)
{
	ARM_my_insn_IR[ea2ARM_my_insn[ea]] = ARM_my_insn[ea2ARM_my_insn[ea]].parameters0["loop_origin"];
}