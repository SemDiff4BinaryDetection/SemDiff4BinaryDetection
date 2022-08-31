#include "../../Headers/value_calculate/ARM_mylibrary_wheel.h"
std::string ARM_lookForDefine(std::string operand, ea_t ea, func_t * func)
{
	    if (ea == 0x3412c)
			int bp = 1;
		bool found_reg_occur;
		ea_t index;
		bool operandIsR0_R1 = false;
		qstring Mnem = "";
		std::string equivilant_operand, return_val;
		int which_op = -1;
		if (operand == "R0" || operand == "R1")
			operandIsR0_R1 = true;
		index = insn_last_insn[ea];
		for (; index >= func->start_ea && index != BADADDR; index = insn_last_insn[index]) {
			found_reg_occur = false;
			print_insn_mnem(&Mnem, index);
			if (Mnem == "PUSH" || Mnem == "POP")
			{
				continue;
			}
			else if (Mnem.find("B")==0 && Mnem!="BIC" && Mnem != "BFC" && Mnem != "BFI")//When the look-up word is r0-r1, this can be potentially looking for return value of calling function
			{
				if (operandIsR0_R1 == true)
				{
					return_val = "RETURN_" + dec2hex(index);
					return return_val;
				}
				continue;
			}
			/*else if (Mnem.find("STRD") != -1)
			{
				return_val = get_STRD_value_if_defined(operand,index);
				if (return_val == "")//Not defined in thie STRD insn
					continue;
				else//Defined in this STRD insn
					return return_val;
			}*/
			return_val= ARM_check_each_operand(index, operand, found_reg_occur);
			if (return_val != "") 
				return return_val;
			else if (return_val == "" && found_reg_occur == true) 
				return return_val;
			 
		} 
		return "";
}

std::string ARM_check_each_operand(ea_t index, std::string operand, bool &found_reg_occur)
{
	std::string result;
	std::string reg;
	int num= count_ea_operands(index);
	int type;
	for (int i = 0;i < num;i++)
	{
		type = get_optype(index, i);
		if (type == 1)//operand is reg type
		{
			reg = ARM_get_operand(index, i);
			if (reg.find('!') == reg.size() - 1)//if the register ends with '!', we trim this '!'
				reg = reg.substr(0, reg.size() - 1);
			if (reg == operand)
			{
				found_reg_occur = true;
				result = ARM_extract_value_from_insn(index, i);
				return result;
			}
		}

		else if (type == 8 || type == 3 || type == 4)//operand is shift type, or disp type
		{
			reg = ARM_get_operand(index, i);
			if (ARM_contain_register(reg,operand))//Check string really contains register, but not like R12 contains R1.
			{
				found_reg_occur = true;
				result = ARM_extract_parameter_value_from_insn(index, i,operand);
				return result;
			}
		}
		else if (type == 9)//type {reg1, reg2...}
		{
			for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[index]].parameters1)//for each key value pair stored in .parameters1
				if (each_pair.first == operand)//if there is some register we are looking for
				{
					found_reg_occur = true;
					result = each_pair.second;
					return result;
				}
		}

	}
	return "";

}

bool ARM_is_below_16_bit_const(std::string tmp)
{
	if (tmp.find("0x") == 0 && tmp.size()<=6)
	{
		return true;
	}
	return false;
}

std::string ARM_extract_value_from_insn(ea_t ea, int i)
{
	if (i == 0)
		return ARM_my_insn[ea2ARM_my_insn[ea]].operand0;
	else if(i==1)
		return ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (i==2)
		return ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (i==3)
		return ARM_my_insn[ea2ARM_my_insn[ea]].operand3;
}


std::string ARM_extract_parameter_value_from_insn(ea_t ea, int i,std::string operand)
{
	if (i == 0)
		return ARM_my_insn[ea2ARM_my_insn[ea]].parameters0[operand];
	else if (i==1)
		return ARM_my_insn[ea2ARM_my_insn[ea]].parameters1[operand];
	else if (i==2)
		return ARM_my_insn[ea2ARM_my_insn[ea]].parameters2[operand];
	else if(i==3)
		return ARM_my_insn[ea2ARM_my_insn[ea]].parameters3[operand];
}

std::string ARM_extract_shift_mnem(std::string operand)
{
	if (operand.find(">>") != -1)
		return ">>";
	else if (operand.find("<<") != -1)
		return "<<";
	else if (operand.find(">") != -1)
		return ">";
}

std::string ARM_extract_shift_base(std::string operand, std::string shift_mnem)
{
	int index = operand.find(shift_mnem);
	return operand.substr(0, index);
}

std::string ARM_extract_shift_offset(std::string operand, std::string shift_mnem)
{
	int index = operand.find(shift_mnem);
	index = index + shift_mnem.size();
	if(operand.find(']')!=-1)
		return trim_begin_end_space(operand.substr(index, operand.find(']')-index));
	else
		return trim_begin_end_space(operand.substr(index, operand.size() - index));
}

bool is_ARM_register(std::string operand)
{
	if (operand == "R0" || operand == "R1" || operand == "R2" || operand == "R3" || operand == "R4" || operand == "R5" || operand == "R6"\
		|| operand == "R7" || operand == "R8" || operand == "R9" || operand == "R10" || operand == "R11" || operand == "R12"||operand=="SP"\
		|| operand == "LR"|| operand == "PC")
		return true;
	return false;
}

void ARM_convert_to_code(ea_t ea)
{
	if (ARM_is_data_segment(ea))
	{
		create_insn(ea);
		while (ea && ARM_not_junping_insn(ea))
		{
			ea = get_first_cref_from(ea);
		}
		ea += DWORD_LEN;
		ARM_convert_to_code(ea);
	}
}

bool ARM_is_data_segment(ea_t ea)
{
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_string = disasm.c_str();
	if (disasm_string.find("DCB") != -1 || disasm_string.find("DCD") != -1)
		return true;
	return false;
}

bool ARM_not_junping_insn(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (Mnemq.find('B') == 0)
		return false;
	return true;
}

bool ARM_is_regiter_offset(std::string operand)
{
	int exclamation_index, last_comma_index, righ_bracket_index;
	exclamation_index = operand.find('!');
	righ_bracket_index = operand.find(']');
	last_comma_index = operand.rfind(',');
	if (exclamation_index == -1 && last_comma_index < righ_bracket_index)
		return true;
	return false;
}

bool ARM_is_pre_indexed(std::string operand)
{
	int exclamation_index;
	exclamation_index = operand.find('!');

	if (exclamation_index != -1)
		return true;
	return false;
}

bool ARM_is_post_indexed(std::string operand)
{
	int exclamation_index, last_comma_index, righ_bracket_index;
	exclamation_index = operand.find('!');
	righ_bracket_index = operand.find(']');
	last_comma_index = operand.rfind(',');
	if (exclamation_index == -1 && last_comma_index > righ_bracket_index)
		return true;
	return false;
}

std::string ARM_replace_comma_with_plus(std::string operand)
{
	for (int i = 0;i < operand.size();i++)
	{
		if (operand[i] == ',')
			operand[i] = '+';
	}
	return operand;
}

std::string ARM_translate_shift(std::string operand1)
{
	int i;
	if (operand1.find('[') == -1)
	{
		for (i = 0; i < operand1.size();i++)
		{
			if (operand1[i] == ',')
				break;
		}
		operand1.replace(i, 1, "");
	}
	else if (operand1.find('[') != -1)
	{
		for (i = 0; i < operand1.size();i++)
		{
			if (operand1[i] == ',')
				break;
		}
		operand1.replace(i, 1, "+");
		if (operand1.find(','))
			operand1.replace(operand1.find(','), 1, "");
	}
	i = operand1.find("ASR");
	if (i != -1)
	{
		operand1.replace(i, 3, ">>");
		return operand1;
	}
	i = operand1.find("LSR");
	if (i != -1)
	{
		operand1.replace(i, 3, ">>");
		return operand1;
	}
	i = operand1.find("ROR");
	if (i != -1)
	{
		operand1.replace(i, 3, ">>");
		return operand1;
	}
	i = operand1.find("LSL");
	if (i != -1)
	{
		operand1.replace(i, 3, "<<");
		return operand1;
	}
	i = operand1.find("RRX");
	if (i != -1)
	{
		operand1.replace(i, 3, ">>1");
		return operand1;
	}
}

bool ARM_is_pop_insn(ea_t ea) {
	qstring Mnem;
	print_insn_mnem(&Mnem, ea);
	if (Mnem == "POP")
		return true;
	return false;
}
void ARM_propagate_to_operand(ea_t ea, std::string defined_value, int index)
{
	if (index == 0)
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
	else if (index == 1)
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value;
	else if (index == 2)
		ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = defined_value;
	else if (index == 3)
		ARM_my_insn[ea2ARM_my_insn[ea]].operand3 = defined_value;
}

std::string ARM_extract_bracket_base(std::string operand)
{
	int left_bracket = operand.find('[');
	int right_bracket = operand.find(']');
	int first_comma = operand.find(',');
	if (first_comma == -1||first_comma>right_bracket)
	{
		return operand.substr(left_bracket + 1, right_bracket - left_bracket - 1);
	}
	else if (first_comma && first_comma < right_bracket)
	{
		return operand.substr(left_bracket + 1, first_comma - left_bracket - 1);
	}

}

std::string ARM_translate_type4_register_offset(std::string operand, std::string defined_value)
{
	std::string result;
	int comma_index = operand.find(',');
	if (comma_index == -1)
	{
		
		return defined_value;
	}
	else
	{
		int right_bracket = operand.find(']');
		if (comma_index < right_bracket)
		{
			std::string num = operand.substr(comma_index+1,right_bracket-comma_index-1);
			result= defined_value + "+" + num;
			return result;
		}
		else if (comma_index > right_bracket)
		{
			std::string num = operand.substr(comma_index + 1, operand.size()-1-comma_index);
			result= defined_value + "+" + num ;
			return result;
		}
	}
}

std::string ARM_extract_bracket_second_register(std::string operand, bool & has_minus)
{
	int first_comma = operand.find(',');
	int minus = operand.find('-');
	if (minus == -1)
	{
		has_minus = false;
		int last_comma = operand.rfind(',');
		int right_bracket = operand.find(']');
		if (last_comma > first_comma)
		{
			return operand.substr(first_comma+1,last_comma-first_comma-1);
		}
		else if (last_comma == first_comma)
		{
			if (first_comma < right_bracket)
			{
				return operand.substr(first_comma+1,right_bracket-first_comma-1);
			}
			else if (first_comma > right_bracket)
			{
				return operand.substr(first_comma + 1, operand.size() - 1 - first_comma);
			}
		}
	}
	else
	{
		has_minus = true;
		int last_comma = operand.rfind(',');
		int right_bracket = operand.find(']');
		if (last_comma > first_comma)
		{
			return operand.substr(minus + 1, last_comma - minus - 1);
		}
		else if (last_comma == first_comma)
		{
			if (first_comma < right_bracket)
			{
				return operand.substr(minus + 1, right_bracket - minus - 1);
			}
			else if (first_comma > right_bracket)
			{
				return operand.substr(minus + 1, operand.size() - 1 - minus);
			}
		}
	}
}

//Param 1: operand in disasm view, like [PC,R3].
//Param 2: looked up value of the base within []
//Param 3: looked up value of the second register within []
std::string ARM_translate_type3_register_offset(std::string operand, std::string defined_value1, std::string defined_value2, ea_t ea, func_t* func)
{
	int last_comma = operand.rfind(',');
	int first_comma = operand.find(',');
	if (last_comma > first_comma)// in the form of [reg, +/-reg {,shift}] 
	{
		operand = ARM_translate_shift(operand);
		std::string shift_mnem = ARM_extract_shift_mnem(operand);
		std::string tmp2 = ARM_extract_shift_offset(operand, shift_mnem);
		if (is_ARM_register(tmp2))
		{
			std::string tmp = ARM_lookForDefine(tmp2, ea, func);
			if (tmp == "")
				tmp = arm_allocate_new_variable(tmp2);
			ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,tmp });
			if (defined_value2.find('-') != 0)
				return defined_value1 + "+" + defined_value2 + shift_mnem + "(" + tmp + ")";
			else if (defined_value2.find('-') == 0)
				return defined_value1 + defined_value2 + shift_mnem + "(" + tmp + ")";
		}
		else
		{
			if (defined_value2.find('-') != 0)
				return defined_value1 + "+" + defined_value2 + shift_mnem + tmp2;
			else if (defined_value2.find('-') == 0)
				return defined_value1 + defined_value2 + shift_mnem + tmp2;
		}
	}
	else if (last_comma == first_comma)//In the form of [,]
	{
		bool minus;
		std::string tmp1, tmp2;
		//tmp1= ARM_lookForDefine(ARM_extract_bracket_base(operand), ea, func);
		//tmp2 = ARM_lookForDefine(ARM_extract_bracket_second_register(operand, minus),ea,func);
		operand = defined_value1 + "+" + defined_value2;;
		return operand;
	}
}

std::vector<std::string> ARM_get_reg_list(std::string operand)
{
	std::vector<std::string> reg_list;
	std::string tmp;
	int left_bracket = operand.find('{');
	int start = left_bracket, end;
	for (end = start + 1; end < operand.size();end++)
	{
		if (operand[end] == '}' || operand[end] == ',')
		{
			tmp = operand.substr(start + 1, end - start - 1);
			if (tmp.find('-') == -1)
				reg_list.push_back(tmp);
			else
			{
				std::vector<std::string> sub_list = ARM_get_regs_from_range(tmp);
				for (int i = 0;i < sub_list.size();i++)
				{
					reg_list.push_back(sub_list[i]);
				}
			}
			start = end;
		}
	}
	return reg_list;
}

std::vector<std::string> ARM_get_regs_from_range(std::string reg_range)
{
	std::vector<std::string> reg_list;
	int dash = reg_range.find('-');
	int start = strtol(reg_range.substr(0, dash).replace(0, 1, "").c_str(),NULL,16);
	int end = strtol(reg_range.substr(dash + 1, reg_range.size() - 1 - dash).replace(0, 1, "").c_str(),NULL,16);
	for (int i = start;i <= end;i++)
	{
		reg_list.push_back("R" + std::to_string(i));
	}
	return reg_list;
}

std::string ARM_find_last_compare_const(std::string operand, ea_t ea, func_t* func)
{
	qstring Mnem;
	bool minus;
	std::string second_reg_in_bracket;
	ea_t index;
	for (index = insn_last_insn[ea];index > func->start_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnem, index);
		if (Mnem == "LDR" && ARM_get_operand(index, 0) == operand)
		{
			second_reg_in_bracket = ARM_extract_bracket_second_register(ARM_get_operand(index, 1), minus);
			break;
		}
	}
	for (index = insn_last_insn[index];index > func->start_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnem, index);
		if (Mnem == "CMP" || Mnem == "TST" && ARM_get_operand(index, 0) == second_reg_in_bracket)
		{
			if (ARM_get_operand(index, 1).find('#') == 0)
				return ARM_get_operand(index, 1).replace(0, 1, "");
			else
				warning("failed to find jump table size!");
		}
	}
}

//Given an instruction address ea and which operand you want to look up its previous defined value.
void ARM_look_for_displ(ea_t ea, func_t* func,int target_operand_num)
{
	std::string to_look_up;
	std::string defined_value_looked_up = "";
	if (target_operand_num == 1)//It is the second operand need to look up.
		to_look_up = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (target_operand_num == 2)//It is the third operand need to look up.
		to_look_up= ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	int equation_index;
	for (ea_t index = insn_last_insn[ea]; index > func->start_ea;index = insn_last_insn[index])//check in previous define for disp content
	{
		if (ARM_my_insn[ea2ARM_my_insn[index]].operand1.find(to_look_up + "=") == 0)
		{
			equation_index = ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('=');
			defined_value_looked_up =  ARM_my_insn[ea2ARM_my_insn[index]].operand1.substr(equation_index + 1, ARM_my_insn[ea2ARM_my_insn[index]].operand1.size()-1 - equation_index);
			break;
		}
		else if (ARM_my_insn[ea2ARM_my_insn[index]].operand0.find(to_look_up + "=") == 0)
		{
			equation_index = ARM_my_insn[ea2ARM_my_insn[index]].operand0.find('=');
			defined_value_looked_up = ARM_my_insn[ea2ARM_my_insn[index]].operand0.substr(equation_index + 1, ARM_my_insn[ea2ARM_my_insn[index]].operand0.size()-1 - equation_index);
			break;
		}
	}
	std::string disp_content = strip_disp(to_look_up);
	if (is_hex_string(disp_content))//check in data section for constant value, if the content in disp is an address
	{
		disp_content = ARM_clear_num_string(disp_content);
		ea_t ea1 = stoi(disp_content,0,16);
		//get_strlit_contents(&buffer, 0x203d30, 10, STRTYPE_C);//get the string content
		if (ea1<=0)
			return;
		qstring buffer1;
		get_strlit_contents(&buffer1, ea1, 10, STRTYPE_C);//we test to get the string content
		std::string defined_value = filter_specific_string(buffer1.c_str());
		if (!defined_value.empty())//if we get some string, that means there is some value at this memory address
		{
			int content = get_32bit(ea1);
			std::string content_string = dec2hex(content);
			if (!content_string.empty())//if we successfully got the content
				defined_value_looked_up = content_string;
		}
		
	}
	
	if (defined_value_looked_up == "")//The looked up value not defined previously
		return;
	else//The looked up value defined previously
	{
		if (target_operand_num == 1)//It is the second operand need to look up.
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1+="="+ defined_value_looked_up;
		else if (target_operand_num == 2)//It is the third operand need to look up.
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2+="="+ defined_value_looked_up;
	}

}

void ARM_look_for_same_displ(int operand_num, ea_t ea, func_t* func)
{
	int equation_index;
	if (operand_num == 1)
	{
		for (ea_t index = insn_last_insn[ea];index > func->start_ea;index = insn_last_insn[index])
		{
			if (ARM_my_insn[ea2ARM_my_insn[index]].operand0.find(ARM_my_insn[ea2ARM_my_insn[ea]].operand1 + "=") == 0)
			{
				equation_index = ARM_my_insn[ea2ARM_my_insn[index]].operand0.find('=');
				ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[index]].operand0.substr(equation_index + 1, ARM_my_insn[ea2ARM_my_insn[index]].operand0.size() - equation_index);
				return;
			}
			else if (ARM_my_insn[ea2ARM_my_insn[index]].operand1.find(ARM_my_insn[ea2ARM_my_insn[ea]].operand1 + "=") == 0)
			{
				equation_index = ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('=');
				ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[index]].operand1.substr(equation_index + 1, ARM_my_insn[ea2ARM_my_insn[index]].operand1.size() - equation_index);
				return;
			}

		}
	}
	else if (operand_num == 0)
	{
		for (ea_t index = insn_last_insn[ea];index > func->start_ea;index = insn_last_insn[index])
		{
			if (ARM_my_insn[ea2ARM_my_insn[index]].operand0.find(ARM_my_insn[ea2ARM_my_insn[ea]].operand0 + "=") == 0)
			{
				equation_index = ARM_my_insn[ea2ARM_my_insn[index]].operand0.find('=');
				ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[index]].operand0.substr(equation_index + 1, ARM_my_insn[ea2ARM_my_insn[index]].operand0.size() - equation_index);
				return;
			}
			else if (ARM_my_insn[ea2ARM_my_insn[index]].operand1.find(ARM_my_insn[ea2ARM_my_insn[ea]].operand0 + "=") == 0)
			{
				equation_index = ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('=');
				ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[index]].operand1.substr(equation_index + 1, ARM_my_insn[ea2ARM_my_insn[index]].operand1.size() - equation_index);
				return;
			}

		}
	}
}

//Check whether the long string contains register reg. Should be noted that R12 contains R1 but it is not a hit.
bool ARM_contain_register(std::string long_string, std::string reg)
{
	//Firstly find all occurance of substring reg in long string.
	std::vector<size_t> positions;
	size_t pos = long_string.find(reg, 0);
	while (pos != std::string::npos)
	{
		positions.push_back(pos);
		pos = long_string.find(reg, pos + 1);
	}
	//Next for each occurance we check whether it is like R12 contains R1
	for (int item = 0;item < positions.size();item++)
	{
		if (isdigit(long_string[positions[item] + reg.size()]))//If the occurance is like R12 contains R1.
			continue;
		else 
			return true;
	}
	return false;
}

//If found this instruction's symbolic value is too large return true
bool ARM_is_symbolic_value_explosion(ea_t ea)
{
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() > 1000)
		return true;
	else if(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size() > 1000)
		return true;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() > 1000)
		return true;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand3.size() > 1000)
		return true;
	else
	{
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters0)
			if (each_pair.second.size() > 0x1000)
				return true;
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters1)
			if (each_pair.second.size() > 0x1000)
				return true;
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters2)
			if (each_pair.second.size() > 0x1000)
				return true;
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters3)
			if (each_pair.second.size() > 0x1000)
				return true;
	}
	return false;
}

//If found this instruction's is not caculatable (i.e., instruction set not supported or symbolic value explosion)
bool ARM_is_not_calculatable(ea_t ea)
{
	if (ARM_is_symbolic_value_explosion(ea))
		return true;
	else if (ARM_Mnem_not_support(ea))
		return true;
}

//If Mnem not supported, return true
bool ARM_Mnem_not_support(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (Mnem[0] == 'V')
		return true;
	return false;
}

//To update [ea+DWORD_LEN], if content within [] is calculatable, calculate it. Otherwise leave it alone.
std::string ARM_translate_LDRD_STRD_second_op(std::string ea)
{
	std::string result;
	if (is_hex_string(ea))//calculatable
		result = "[" + dec2hex(stoi(ea, 0, 16) + DWORD_LEN) + "]";
	else//uncalculatable
		result = "[" + ea + "+" + std::to_string(DWORD_LEN) + "]";
	return result;
}

//Delete the # and 0x out of string.
std::string ARM_clear_num_string(std::string string)
{
	if (string.find('#') == 0)
		string = string.replace(string.find('#'), 1, "");
	if (string.find("0x") == 0)
		string = string.replace(string.find("0x"), 2, "");
	return string;
}

void ARM_unname_all_regs(func_t* func)
{
	int result1 = del_regvar(func, func->start_ea, func->end_ea, "R0");
	int result2 = del_regvar(func, func->start_ea, func->end_ea, "R1");
	int result3 = del_regvar(func, func->start_ea, func->end_ea, "R2");
	int result4 = del_regvar(func, func->start_ea, func->end_ea, "R3");
	int result5 = del_regvar(func, func->start_ea, func->end_ea, "R4");
	int result6 = del_regvar(func, func->start_ea, func->end_ea, "R5");
	int result7 = del_regvar(func, func->start_ea, func->end_ea, "R6");
	int result8 = del_regvar(func, func->start_ea, func->end_ea, "R7");
	int result9 = del_regvar(func, func->start_ea, func->end_ea, "R8");
	int result10 = del_regvar(func, func->start_ea, func->end_ea, "R9");
	int result11 = del_regvar(func, func->start_ea, func->end_ea, "R10");
	int result12 = del_regvar(func, func->start_ea, func->end_ea, "R11");
	int result13 = del_regvar(func, func->start_ea, func->end_ea, "R12");
	int result14 = del_regvar(func, func->start_ea, func->end_ea, "SP");
	int result15 = del_regvar(func, func->start_ea, func->end_ea, "LR");
	int result16 = del_regvar(func, func->start_ea, func->end_ea, "PC");
}