#include "../../Headers/IR/x64_IR_call_handler.h"

void init_x64_my_insn_IR(func_t* func)
{
	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
		x64_my_insn_IR.push_back("");
}


std::vector  <std::string> x64_look_for_parameters(ea_t ea, func_t* func)
{
	if (file_type.find("ELF") == 0)
	{
		return x64_linux_look_for_parameters(ea, func);
	}
	else if (file_type == "Portable executable")
	{
		return  x64_windows_look_for_parameters(ea, func);
	}
}

//Linux calling convention:rdi, rsi, rdx, rcx, r8, r9, stack.
std::vector <std::string>  x64_linux_look_for_parameters(ea_t ea, func_t* func)
{
	std::vector <std::string> result_parameters;
	std::string param0, param1, param2, param3, param4,param5;
	std::vector <std::string> stack_parameters;
	param0 = x64_linux_look_for_parameter_n(0, ea, func);
	if (param0 != "")
	{
		result_parameters.push_back(param0);
		param1 = x64_linux_look_for_parameter_n(1, ea, func);
		if (param1 != "")
		{
			result_parameters.push_back(param1);
			param2 = x64_linux_look_for_parameter_n(2, ea, func);
			if (param2 != "")
			{
				result_parameters.push_back(param2);
				param3 = x64_linux_look_for_parameter_n(3, ea, func);
				if (param3 != "")
				{
					result_parameters.push_back(param3);
					param4 = x64_linux_look_for_parameter_n(4, ea, func);
					if (param4 != "")
					{
						result_parameters.push_back(param4);
						param5 = x64_linux_look_for_parameter_n(5, ea, func);
						if (param5 != "")
						{
							result_parameters.push_back(param5);
							stack_parameters = x64_look_for_stack_parameters(ea, func);
							if (stack_parameters.size() > 1) stack_parameters = x64_sort_stack_parameters(stack_parameters);
							for (int i = 0;i < stack_parameters.size();i++)
							{
								if (stack_parameters[i].find("=") != -1)
									param4 = stack_parameters[i].substr(stack_parameters[i].find("=") + 1, stack_parameters[i].length() - 1 - stack_parameters[i].find("="));
								else
									param4 = stack_parameters[i];
								result_parameters.push_back(param4);
							}
						}
					}
				}
			}
		}
	}
	result_parameters = translate_address_parameter_to_string_or_value(result_parameters);
	return result_parameters;
}

//Windows calling convention: rcx, rdx, r8, r9, stack.
std::vector <std::string>  x64_windows_look_for_parameters(ea_t ea, func_t* func)
{
	std::vector <std::string> result_parameters;
	std::string param0, param1, param2, param3,param4;
	std::vector <std::string> stack_parameters;
	param0 = x64_windows_look_for_parameter_n(0, ea, func);
	if (param0 != "")
	{
		result_parameters.push_back(param0);
		param1 = x64_windows_look_for_parameter_n(1, ea, func);
		if (param1 != "")
		{
			result_parameters.push_back(param1);
			param2 = x64_windows_look_for_parameter_n(2, ea, func);
			if (param2 != "")
			{
				result_parameters.push_back(param2);
				param3 = x64_windows_look_for_parameter_n(3, ea, func);
				if (param3 != "")
				{
					result_parameters.push_back(param3);
					stack_parameters = x64_look_for_stack_parameters(ea, func);
					if (stack_parameters.size() > 1) stack_parameters = x64_sort_stack_parameters(stack_parameters);
					for (int i = 0;i < stack_parameters.size();i++)
					{
						if (stack_parameters[i].find("=") != -1)
							param4 = stack_parameters[i].substr(stack_parameters[i].find("=") + 1, stack_parameters[i].length() - 1 - stack_parameters[i].find("="));
						else
							param4 = stack_parameters[i];
						result_parameters.push_back(param4);
					}
				}
			}
		}
	}
	result_parameters = translate_address_parameter_to_string_or_value(result_parameters);
	return result_parameters;
}

std::string x64_windows_look_for_parameter_n(int param_n, ea_t ea, func_t *func)
{
	std::string param;
	if (param_n == 0)
	{
		param=x64_look_for_parameter_define("rcx", ea, func);
		if(param=="")
			param = x64_look_for_parameter_define("xmm0", ea, func);
		return param;
	}
	else if (param_n == 1)
	{
		param = x64_look_for_parameter_define("rdx", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm1", ea, func);
		return param;
	}
	else if (param_n == 2)
	{
		param = x64_look_for_parameter_define("r8", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm2", ea, func);
		return param;
	}
	else if (param_n == 3)
	{
		param = x64_look_for_parameter_define("r9", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm3", ea, func);
		return param;
	}
}

std::string x64_linux_look_for_parameter_n(int param_n, ea_t ea, func_t* func)
{
	std::string param;
	if (param_n == 0)
	{
		param = x64_look_for_parameter_define("rdi", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm0", ea, func);
		return param;
	}
	else if (param_n == 1)
	{
		param = x64_look_for_parameter_define("rsi", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm1", ea, func);
		return param;
	}
	else if (param_n == 2)
	{
		param = x64_look_for_parameter_define("rdx", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm2", ea, func);
		return param;
	}
	else if (param_n == 3)
	{
		param = x64_look_for_parameter_define("rcx", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm3", ea, func);
		return param;
	}
	else if (param_n == 4)
	{
		param = x64_look_for_parameter_define("r8", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm4", ea, func);
		return param;
	}
	else if (param_n == 5)
	{
		param = x64_look_for_parameter_define("r9", ea, func);
		if (param == "")
			param = x64_look_for_parameter_define("xmm5", ea, func);
		return param;
	}
}

std::string x64_look_for_parameter_define(std::string reg, ea_t ea, func_t* func)
{
	ea_t index = insn_last_insn[ea];
	qstring Mnemq;
	std::string operand0,operand1;
	if (ea == 0x7f8)
		int i = 1;
	int basic_block_num = 0;
	for (; index>func->start_ea && index != BADADDR && insn_last_insn.find(index) != insn_last_insn.end(); index = insn_last_insn[index]) {
		if (basic_block_num == 2)
			return "";
		print_insn_mnem(&Mnemq, index);
		if (Mnemq == "call")
			return "";
		else if (Mnemq == "nop")
			continue;
		operand0 = x64_get_operand(index, 0);
		operand1= x64_get_operand(index, 1);
		if (x64_is_equal_register(operand0, reg))
		{
			if (x64_is_use_stmt(Mnemq, ea, 0) == 0)//If operand is defined here, this is what we are looking for.
				//if (x64_my_insn[ea2x64_my_insn[index]].operand0.find("ITERATOR") == -1)
				return x64_my_insn[ea2x64_my_insn[index]].operand0;
			//else
				//return operand0;
			else if (x64_is_use_stmt(Mnemq, ea, 0) == 1)//If operand is used here, this is not what we are looking for.
				continue;
		}
		else if (x64_is_equal_register(operand1, reg)|| x64_contain_equal_register(operand1, reg)!="")
			return "";
		if (x64_is_joint_node(index))
			basic_block_num++;
	}
	return "";
}

bool x64_is_joint_node(ea_t ea)
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

std::vector <std::string> x64_look_for_stack_parameters(ea_t ea, func_t* func)
{
	ea_t index = insn_last_insn[ea];
	std::string operand0;
	qstring Mnemq;
	std::vector <std::string> stack_parameters;
	int basic_block_num=0;
	for (; index > func->start_ea && index != BADADDR && insn_last_insn.find(index) != insn_last_insn.end(); index = insn_last_insn[index]) {
		print_insn_mnem(&Mnemq, index);
		if (basic_block_num++)
			return stack_parameters;
		if (Mnemq == "call")
			return stack_parameters;
		operand0 = x64_get_operand(index, 0);
		if (x64_is_stack_parameter(operand0) && Mnemq=="mov")
		{
			if (is_calculatable_stack(operand0))
			stack_parameters.push_back(x64_my_insn[ea2x64_my_insn[index]].operand0);
		}
		if (x64_is_joint_node(index))
			basic_block_num++;
	}
	return stack_parameters;
}

bool x64_is_stack_parameter(std::string operand0)
{
	if (operand0.find("[rsp") == 0)
		return true;
	return false;
}

std::vector <std::string> x64_sort_stack_parameters(std::vector <std::string> stack_parameters)
{
	std::vector <std::string> descend_sorted;
	int offset, max_offset = 0, index;
	for (int i = 0;i < stack_parameters.size();i++)
	{
		x64_calculate_stack_value(&stack_parameters[i]);
	}
	while (stack_parameters.size() > 0) {
		max_offset = 0;
		for (int i = 0;i < stack_parameters.size();i++)
		{
			offset = x64_extract_stack_offset(stack_parameters[i]);
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

int x64_extract_stack_offset(std::string stack_expression)
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

void x64_calculate_stack_value(std::string* stack_operand)
{
	int index = 0, sum;
	std::string to_resolve, result;
	std::string value;
	uval_t out;
	int real_value;
	value = (*stack_operand).substr((*stack_operand).find("=") + 1, (*stack_operand).length() - 1 - (*stack_operand).find("="));
	index = stack_operand->find("sp") + 3;
	while (index < (*stack_operand).length()&& (*stack_operand)[index-1]!=']')
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

	index = (*stack_operand).find("+-");
	while (index != -1)
	{
		(*stack_operand).replace(index, 2, "-");
		index = (*stack_operand).find("+-");
	}


	sum = x64_iterate_calculate((*stack_operand));
	//stack_operand->replace(stack_operand->find('sp+') + 3, stack_operand->length() - 2 - stack_operand->find('sp+') - 3, std::to_string(sum));
	*stack_operand = "[rsp+" + std::to_string(sum) + "]";
	index = (*stack_operand).find("+-");
	while (index != -1)
	{
		(*stack_operand).replace(index, 2, "-");
		index = (*stack_operand).find("+-");
	}
	(*stack_operand) += "=" + value;
}

int x64_iterate_calculate(std::string stack_operand)
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

	} while ((Mnem == '+' || Mnem == '-' || Mnem == '*' || Mnem == '/')&& index< stack_operand.length());
	return new_operand;
}

void x64_translate_return_value(ea_t ea,func_t* func)
{
	qstring Mnemq;
	std::string operand0;
	for (ea_t index = func->end_ea;index > func->start_ea && insn_last_insn.find(index) != insn_last_insn.end();index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		operand0 = x64_get_operand(index, 0);
		if (x64_is_equal_register(operand0, "rax") && ((Mnemq.find("mov") != -1) || Mnemq.find("lea") != -1 || Mnemq.find("add") != -1 || Mnemq.find("sub") != -1 || Mnemq.find("mul") != -1 || Mnemq.find("div") != -1))
		{
			x64_my_insn_IR[ea2x64_my_insn[index]] = "return " + x64_my_insn[ea2x64_my_insn[index]].operand0;
			return;
		}
	}
}


bool x64_not_jump_insn(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	if (Mnemq.find('j') != 0)
		return true;
	return false;
}