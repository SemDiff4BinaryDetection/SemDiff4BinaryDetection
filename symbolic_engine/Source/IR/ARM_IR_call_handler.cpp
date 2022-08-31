#include "../../Headers/IR/ARM_IR_call_handler.h"
void ARM_translate_return_value(ea_t ea, func_t* func)
{
	qstring Mnemq;
	std::string operand0;
	for (ea_t index = insn_last_insn[ea];index > func->start_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		operand0 = ARM_get_operand(index, 0);
		if (operand0 == "R0" && ((Mnemq.find("MOV") != -1) || Mnemq.find("ADD") != -1 || Mnemq.find("SUB") != -1 || Mnemq.find("MUL") != -1 || Mnemq.find("DIV") != -1))
		{
			ARM_my_insn_IR[ea2ARM_my_insn[index]] = "return " + ARM_my_insn[ea2ARM_my_insn[index]].operand0;
			return;
		}
	}
}

std::vector <std::string>  ARM_look_for_parameters(ea_t ea, func_t* func)
{
	std::vector <std::string> result_parameters;
	std::string R0, R1, R2, R3;
	std::vector <std::string> stack_parameters;
	std::string value;
	if (ea == 0x118f4)
		int breakp = 1;
	R0 = ARM_look_for_parameter_define("R0", ea, func);
	if (R0 != "")
	{
		result_parameters.push_back(R0);
		R1 = ARM_look_for_parameter_define("R1", ea, func);
		if (R1 != "")
		{
			result_parameters.push_back(R1);
			R2 = ARM_look_for_parameter_define("R2", ea, func);
			if (R2 != "")
			{
				result_parameters.push_back(R2);
				R3 = ARM_look_for_parameter_define("R3", ea, func);
				if (R3 != "")
				{
					result_parameters.push_back(R3);
					stack_parameters = ARM_look_for_stack_parameters(ea, func);
					if (stack_parameters.size() > 1) stack_parameters = ARM_sort_stack_parameters(stack_parameters);
					for (int i = 0;i < stack_parameters.size();i++)
					{
						if (stack_parameters[i].find("=") != -1)
							value = stack_parameters[i].substr(stack_parameters[i].find("=") + 1, stack_parameters[i].length() - 1 - stack_parameters[i].find("="));
						else 
							value = stack_parameters[i];
						result_parameters.push_back(value);
					}
				}
			}
		}
	}
	result_parameters = translate_address_parameter_to_string_or_value(result_parameters);
	return result_parameters;
}


std::string ARM_look_for_parameter_define(std::string reg, ea_t ea, func_t* func)
{
	ea_t index = insn_last_insn[ea];
	qstring Mnemq;
	std::string Mnem;
	std::string operand0,operand1;
	int basic_block_num = 0;
	for (; index >= func->start_ea && index != BADADDR; index = insn_last_insn[index]) {
		if (basic_block_num == 2)
			return "";
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		operand0 = ARM_get_operand(index, 0);
		operand1 = ARM_get_operand(index, 1);
		if (Mnem.find('B') == 0 && Mnem != "BIC")
		{
			if (reg!="R0"|| (reg == "R0" && operand0.find("loc_")!=-1))
				return "";
			else if (reg == "R0" && operand0.find("loc_") == -1)//if index is calling subfunction
			{
				return "RETURN" + dec2hex(index);
			}
		}
		if (operand0 == reg)
		{
			if (ARM_is_use_stmt(Mnemq, index, 0) == 0)//If this operand is defined in this instruction, this is what we are looking for.
			{
				return ARM_my_insn[ea2ARM_my_insn[index]].operand0;
			}
			else if (ARM_is_use_stmt(Mnemq, index, 0) == 1)//If this operand is used in here. This is not we are looking for.
				continue;
		}
		else if (operand1 == reg )
		{
				return ARM_my_insn[ea2ARM_my_insn[index]].operand1;
		}
		if (arm_is_joint_node(index))
			basic_block_num++;
	}
	return "";
}

bool arm_is_joint_node(ea_t ea)
{
	int next_ea, next_ea1;
	next_ea = get_first_cref_from(ea);
	next_ea1 = get_next_cref_from(ea, next_ea);
	int next_number = 0;
	if (next_ea != -1)
		next_number++;
	if (next_ea1 != -1)
		next_number++;
	if (next_number == 2)
		return true;
	return false;
}

std::vector <std::string> ARM_look_for_stack_parameters(ea_t ea, func_t* func)
{
	if (ea == 0x8d29c)
		int breakp = 1;
	ea_t index = insn_last_insn[ea];
	std::string operand1;
	qstring Mnemq;
	std::vector <std::string> stack_parameters;
	for (; ARM_not_jump_insn(index)&& index != BADADDR && index>=func->start_ea; index = insn_last_insn[index]) {
		print_insn_mnem(&Mnemq, index);
		if (Mnemq == "BL")
			return stack_parameters;
		operand1 = ARM_get_operand(index, 1);
		if (ARM_is_stack_parameter(operand1) && Mnemq=="STR")
		{
			if (is_calculatable_stack(operand1))
				stack_parameters.push_back(operand1 + ARM_my_insn[ea2ARM_my_insn[index]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('='), \
					ARM_my_insn[ea2ARM_my_insn[index]].operand1.size()- ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('=')));
		}
	}
	return stack_parameters;
}

bool ARM_is_stack_parameter(std::string operand)
{
	if (operand.find("[SP") == 0)
		return true;
	return false;
}

//If the arguments for the calling subfunction is disp (i.e., []), we need to order these arguments.
std::vector <std::string> ARM_sort_stack_parameters(std::vector <std::string> stack_parameters)
{
	std::vector <std::string> descend_sorted;
	int offset, max_offset = 0, index;
	for (int i = 0;i < stack_parameters.size();i++)
	{
		ARM_calculate_stack_value(&stack_parameters[i]);
	}
	while (stack_parameters.size() > 0) {
		max_offset = 0;
		for (int i = 0;i < stack_parameters.size();i++)
		{
			offset = ARM_extract_stack_offset(stack_parameters[i]);
			if (offset >= max_offset)
			{
				max_offset = offset;
				index = i;
			}
		}
		descend_sorted.push_back(stack_parameters[index]);
		stack_parameters.erase(stack_parameters.begin() + index);

	}
	return descend_sorted;
}

int ARM_extract_stack_offset(std::string stack_expression)
{
	int offset;
	int index, end;
	for (index = 0;index < stack_expression.length();index++)
	{
		if (stack_expression[index] == '+' || stack_expression[index] == '-')
			break;
	}
	end = stack_expression.rfind('=');
	stack_expression = stack_expression.substr(index + 1, end - index - 1);
	offset = std::stoi(stack_expression);
	return offset;
}

//calculate stack value within the '[]' in order to sort them later.
void ARM_calculate_stack_value(std::string* stack_operand)
{
	int index = 0, sum;
	std::string to_resolve, result;
	std::string value;
	index = stack_operand->find("[SP,");
	index += 4;
	(*stack_operand).replace(0, 4, "[SP+");
	if((*stack_operand).find('=')!=-1)
		value = (*stack_operand).substr((*stack_operand).find('='), (*stack_operand).length()- (*stack_operand).find('='));
	while (index < (*stack_operand).length())
	{
		to_resolve = get_next_element((*stack_operand), &index);
		if (to_resolve.find("var_") == 0)
		{
			result = "-" + to_resolve.substr(4, to_resolve.length() - 3);
			index = index - to_resolve.length() - 1;
			(*stack_operand).replace(index, to_resolve.length(), result);
			index += result.length();
		}
		else if (to_resolve.find("arg_") == 0)
		{
			result = "+" + to_resolve.substr(4, to_resolve.length() - 3);
			index = index - to_resolve.length() - 1;
			(*stack_operand).replace(index, to_resolve.length(), result);
			index += result.length();
		}
	}
	//index= stack_operand->find("[SP,");
	//(*stack_operand).replace(index, 4, "[SP+");
	index = (*stack_operand).find("+-");
	while (index != -1)
	{
		(*stack_operand).replace(index, 2, "-");
		index = (*stack_operand).find("+-");
	}


	sum = ARM_iterate_calculate((*stack_operand));
	//stack_operand->replace(stack_operand->find('SP') + 2, stack_operand->length() - stack_operand->find('SP') - 2, "+"+std::to_string(sum));
	*stack_operand = "[SP+" + std::to_string(sum)+"]";
	index = (*stack_operand).find("+-");
	while (index != -1)
	{
		(*stack_operand).replace(index, 2, "-");
		index = (*stack_operand).find("+-");
	}
	(*stack_operand) += value;
}

int ARM_iterate_calculate(std::string stack_operand)
{
	int index = 0, start;
	int operand0, new_operand = 0;
	std::string operand_0s;
	char Mnem;
	for (int i = 0;i < stack_operand.length();i++)
	{
		if (stack_operand[i] == '+')
		{
			index = i + 1;
			break;
		}
		else if (stack_operand[i] == '-')
		{
			index = i + 1;
			break;
		}
		else if (stack_operand[i] == '*')
		{
			index = i + 1;
			break;
		}
		else if (stack_operand[i] == '/')
		{
			index = i + 1;
			break;
		}
	}
	do {
		Mnem = stack_operand[index - 1];
		if (Mnem == ']')//[]=13 terminates at equation.
			break;
		operand_0s = get_next_element(stack_operand, &index);
		operand0 = stoi(operand_0s,0,16);
		if (Mnem == '+')
			new_operand += operand0;
		else if (Mnem == '-')
			new_operand -= operand0;
		else if (Mnem == '*')
			new_operand *= operand0;
		else if (Mnem == '/')
			new_operand /= operand0;

	} while ((Mnem == '+' || Mnem == '-' || Mnem == '*' || Mnem == '/')&& index < stack_operand.length());
	return new_operand;
}

bool ARM_not_jump_insn(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	if (Mnemq.find('B') != 0)
		return true;
	return false;
}