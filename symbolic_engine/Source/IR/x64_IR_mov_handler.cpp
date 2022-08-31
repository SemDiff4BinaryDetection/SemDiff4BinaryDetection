#include "../../Headers/IR/x64_IR_mov_handler.h"
#include "../../Headers/IR/x64_IR.h"

void explain_displ(ea_t ea)
{

	std::string operand0, operand1, transformed;
	operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0;
	if (x64_my_insn[ea2x64_my_insn[ea]].operand1 == "") operand1 = x64_get_operand(ea, 1);
	else operand1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	if (is_multi_level_stru(operand0))
	{
		transformed = transform_to_c_stru(operand0);
		x64_my_insn_IR[ea2x64_my_insn[ea]] = transformed;
		if (x64_my_insn_IR[ea2x64_my_insn[ea]].find("=") == -1)
			x64_my_insn_IR[ea2x64_my_insn[ea]] + " = " + operand1;
	}

	else
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_my_insn[ea2x64_my_insn[ea]].operand0;
		if (x64_my_insn_IR[ea2x64_my_insn[ea]].find("=") == -1)
			x64_my_insn_IR[ea2x64_my_insn[ea]] + " = " + operand1;
	}
	
}

bool is_multi_level_stru(std::string operand0)
{
	int last_left_bracket = 0;
	int first_right_bracket = 0;
	for (int i = 0; i < operand0.length();i++)
		if (operand0[i] == '[')
			last_left_bracket=i;
	for (int i = 0; i < operand0.length();i++)
		if (operand0[i] == ']')
		{
			first_right_bracket = i;
			break;
		}
	if (last_left_bracket!=0 && first_right_bracket!=0 && last_left_bracket <first_right_bracket)
		return true;
	return false;
}

std::string transform_to_c_stru(std::string operand0)
{
	std::string result, offset;
	int inner_most_left_bracket, inner_most_right_bracket;
	for (int i = 0;i < operand0.length();i++)
	{
		if (operand0[i] == '[')
			inner_most_left_bracket = i;
		if (operand0[i] == ']')
		{
			inner_most_right_bracket = i;
			break;
		}
	}

	result = operand0.substr(inner_most_left_bracket + 1, inner_most_right_bracket - inner_most_left_bracket - 1);
	while (inner_most_left_bracket != -1)
	{
		offset = extract_offset(inner_most_right_bracket, operand0);
		result += "." + offset;
		inner_most_left_bracket = last_left_bracket(inner_most_left_bracket, operand0);
		inner_most_right_bracket = next_right_bracket(inner_most_right_bracket, operand0); 
	}
	return result;
}

std::string extract_offset(int inner_most_right_bracket, std::string operand0)
{
	for (int i = inner_most_right_bracket;i < operand0.length();i++)
		if (operand0[i] == ']')
		{
			if (i = inner_most_right_bracket + 1)
				return "0";
			return operand0.substr(inner_most_right_bracket + 1, i - inner_most_right_bracket - 1);
		}
		else if (i == operand0.length() - 1)
		{
			return operand0.substr(inner_most_right_bracket + 1, i - inner_most_right_bracket);
		}

}

int last_left_bracket(int inner_most_left_bracket, std::string operand0)
{
	for (int i = inner_most_left_bracket-1;i >=0;i--)
		if (operand0[i] == '[')
			return i;
	return -1;
}

int next_right_bracket(int inner_most_right_bracket, std::string operand0)
{
	for (int i = inner_most_right_bracket;i < operand0.length();i++)
		if (operand0[i] == ']')
			return i;

	return operand0.length() - 1;
}

/*void init_IR_reserve_insns(func_t* func)
{
	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
		IR_reserve_insns.push_back("");
}*/

/*void reserve_loop(ea_t ea, ea_t next_ea, func_t* func)
{
	qstring Mnem;
	ea_t last_compare_insn;
	print_insn_mnem(&Mnem, ea);
	if (Mnem[0] == 'j' && Mnem != "jmp")
		last_compare_insn = find_last_compare(ea, next_ea, func);

	else return;

	translate_decide_insn(last_compare_insn);

	std::string operand0,operand1;
	operand0 = x64_get_operand(last_compare_insn,0);
	operand1 = x64_get_operand(last_compare_insn, 1); 
	std::string tmp_operand0, tmp_operand1;
	bool is_iterator_insn = false;
	std::string iterator_var;
	int operand_index;
	for (ea_t index = insn_last_insn[ea];index !=insn_last_insn[next_ea];index=insn_last_insn[index])
	{
		print_insn_mnem(&Mnem, index);
		tmp_operand0 = x64_get_operand(index, 0);
		tmp_operand1 = x64_get_operand(index, 1);
		if (Mnem != "cmp" && Mnem != "test")
			if (tmp_operand0.find(operand0) != -1) { is_iterator_insn = true; operand_index = 0; }
			else if (tmp_operand0.find(operand1) != -1) { is_iterator_insn = true; operand_index = 0;}
			else if (tmp_operand1.find(operand1) != -1) { is_iterator_insn = true; operand_index = 1;}
			else if (tmp_operand1.find(operand0) != -1) { is_iterator_insn = true; operand_index = 1;		}
		if (is_iterator_insn)
		{
			iterator_var = allocate_iterator_var();
			reserve_insn(index,operand_index,iterator_var);
			forward_propagate_iterator_variable(index,operand_index,iterator_var);
		}
	}
}*/

/*ea_t find_last_compare(ea_t ea, ea_t next_ea, func_t * func)
{
	ea_t index;
	qstring Mnem;
	
	for (index = insn_last_insn[ea];index != next_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnem, index);
		if (Mnem == "test" || Mnem == "cmp")
			return index;
	}
	return -1;
}
*/
/*void translate_decide_insn(ea_t ea)
{
	IR_reserve_insns[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + " == " + x64_get_operand(ea, 1);
}

void reserve_insn(ea_t index,int operand_index, std::string iterator_variable)
{
	qstring Mnem;
	print_insn_mnem(&Mnem, index);
	IR_reserve_insns[ea2x64_my_insn[index]] = Mnem.c_str();
	if(operand_index==0)
		IR_reserve_insns[ea2x64_my_insn[index]] += " " + iterator_variable + ", " + x64_get_operand(index, 1);
	else if(operand_index==1)
		IR_reserve_insns[ea2x64_my_insn[index]] += " " + x64_get_operand(index,0) + ", " + iterator_variable;
}
*/


/*void translate_loop_insns(ea_t ea, func_t* func)
{
 
	ea_t next_ea, next_ea1;
	init_iterator_var();
	for (ea_t index = ea;index > func->start_ea;index = insn_last_insn[index])
	{

		next_ea = get_first_cref_from(index);
		next_ea1 = get_next_cref_from(index, next_ea);

		if (next_ea != -1 && is_in_loop(index, next_ea, func))
		{
			reserve_loop(index, next_ea, func);

		}
		if (next_ea1 != -1 && is_in_loop(index, next_ea1, func))
		{
			reserve_loop(index, next_ea1, func);

		}

	}
}
*/
