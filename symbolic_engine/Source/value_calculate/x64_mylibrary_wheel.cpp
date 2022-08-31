#include "../../Headers/value_calculate/x64_mylibrary_wheel.h"
#include "../../Headers/value_calculate/x64_mylibrary_operator.h"
#include "../../Headers/value_calculate/x64_mylibrary_register.h"
#include "../../Headers/value_calculate/x64_mylibrary.h"

std::string x64_extractBase(std::string operand) {//extract rbx out of [rbx+xxxxx+xxxxx]
	std::string result_string;
	int left_bracket, first_operator;
	left_bracket = operand.find('[');
	first_operator = operand.find_first_of("+-*/");
	if (first_operator == -1)
		first_operator = operand.find(']');
	result_string = operand.substr(left_bracket + 1, first_operator - left_bracket - 1);
	return result_string;

}

void x64_define_base(ea_t ea, int operand_num, std::string value) {
	std::string operand0, operand1, original_value;
	msg("going to define %x with %s   ", ea, value.c_str());
	int plus_index, start_index;
	if (operand_num == 0)
	{
		operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0;
		start_index = operand0.find('[');
		if (start_index == -1)start_index = 0;
		plus_index = operand0.find_first_of("+-*/");
		if (plus_index == -1)
			plus_index = operand0.find(']');
		msg("operand0 before:%s  ", operand0.c_str());
		original_value = operand0.substr(start_index + 1, plus_index - start_index - 1);
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert(std::pair<std::string, std::string>(original_value, value));
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0.replace(start_index + 1, plus_index - start_index - 1, value);

		msg("operand0 after:%s  \n", x64_my_insn[ea2x64_my_insn[ea]].operand0.c_str());
	}

	else if (operand_num == 1)
	{
		operand1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
		start_index = operand1.find('[');
		if (start_index == -1)start_index = 0;
		plus_index = operand1.find_first_of("+-*/");
		if (plus_index == -1)
			plus_index = operand1.find(']');
		msg("operand1 before:%s  ", operand1.c_str());
		original_value = operand1.substr(start_index + 1, plus_index - start_index - 1);
		x64_my_insn[ea2x64_my_insn[ea]].parameters1.insert(std::pair<std::string, std::string>(original_value, value));
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1.replace(start_index + 1, plus_index - start_index - 1, value);
		msg("operand1 after:%s\n", x64_my_insn[ea2x64_my_insn[ea]].operand1.c_str());
	}

}

std::string x64_lookForDefine(std::string operand, ea_t ea, func_t* func) {
	if (ea == 0x2e28 && operand=="rsi")
		int motherf = 1;
	ea_t index;
	bool operandIsEax=false;
	bool operandIsEdx = false;
	qstring Mnem="";
	std::string equivilant_operand,return_val="";
	int which_op=-1;
	if (operand == "eax" || operand == "rax" || operand == "ax" || operand == "ah" || operand == "al")
		operandIsEax = true;
	else if (operand == "rdx" || operand == "edx" || operand == "dx" || operand == "dh" || operand == "dl")
		operandIsEdx = true;
	index = insn_last_insn[ea];
	for (; index >= func->start_ea && index != BADADDR; index = insn_last_insn[index]) {
		if (index == 0x281b||index==0x28d2||index==0x2982)
			int breakp = 1;
		print_insn_mnem(&Mnem, index);
		if (Mnem == "push" || Mnem == "pop" || Mnem == "nop"||Mnem.find('j')==0)
		{
			return_val = check_define_in_argument(index, operand, func,return_val);
			continue;
		}
		else if (Mnem == "call")
		{
			if (operandIsEax == true)
			{
				 return_val = "RETURN_" + dec2hex(index);
				 return return_val;
			}
			std::string expression = x64_get_operand(index, 0);
			std::vector<std::string> expression_list = split_expression(expression);
			bool has_this_reg = has_this_register(expression_list,operand);
			if (has_this_reg ==true)
			{
				if (x64_get_operand(index, 0).find('[') == -1)//operand is a register
					return_val = x64_my_insn[ea2x64_my_insn[index]].operand0;
				else if (x64_get_operand(index, 0).find('[') != -1)//operand is a []
					return_val = x64_my_insn[ea2x64_my_insn[index]].parameters0[operand];
				return return_val;
			}
			continue;
		}
		else if (Mnem==("div")|| Mnem == ("idiv") ||((Mnem=="mul"||Mnem=="imul")&&has_single_operand(index)==true))
		{
			if (operand == "eax" || operand == "rax" || operand == "ax" || operand == "ah" || operand == "al")
			{
				return x64_my_insn[ea2x64_my_insn[index]].parameters0["eax"];
			}
			else if (operand == "rdx" || operand == "edx" || operand == "dx" || operand == "dh" || operand == "dl")
			{
				return x64_my_insn[ea2x64_my_insn[index]].parameters0["edx"];
			}
			else if (x64_is_equal_register(x64_get_operand(index, 0), operand))
			{
				return  x64_extract_value_from_insn(index, 0, func);
			}
			else 
			{
				std::string tmp=x64_contain_equal_register(x64_get_operand(index, 0), operand);
				if(tmp!="")
				return x64_my_insn[ea2x64_my_insn[index]].parameters0[tmp];
			}

		}
		else if (Mnem == "cmpxchg")
		{
			if (operand== "eax" || operand == "rax" || operand == "ax" || operand == "ah" || operand == "al")
				return x64_my_insn[ea2x64_my_insn[index]].parameters0["eax"];
		}
		std::string operand0 = x64_get_operand(index, 0);
		std::string operand1 = x64_get_operand(index, 1);	
		std::string operand2 = x64_get_operand(index, 2);
		int op0_type= get_optype(index, 0);
		int op1_type = get_optype(index, 1);
		int op2_type = get_optype(index, 2);
		if (operand1.find(';') != -1) operand1 = operand1.substr(0, operand1.find(';'));
		if (x64_is_equal_register(operand0, operand)) 
		{ 
			return_val = x64_extract_value_from_insn(index, 0, func); 
			which_op = 0; 
		}
		else if (x64_is_equal_register(operand1, operand)) 
		{ 
			return_val = x64_extract_value_from_insn(index, 1, func); 
			which_op = 1; 
		}		
		else{
			equivilant_operand = x64_contain_equal_register(operand0, operand);
			if (equivilant_operand != "" && (op0_type==3|| op0_type == 4))
			{ 
				return_val = x64_extract_parameter_value_from_insn(index, 0, func, equivilant_operand); 
				which_op = 0; 
			}
			equivilant_operand = x64_contain_equal_register(operand1, operand);
			if (equivilant_operand != "" && (op1_type == 3 || op1_type == 4))
			{ 
				return_val = x64_extract_parameter_value_from_insn(index, 1, func, equivilant_operand); 
				which_op = 1; 
			}
			equivilant_operand = x64_contain_equal_register(operand2, operand);
			if (equivilant_operand != "" && (op2_type == 3 || op2_type == 4))
			{
				return_val = x64_extract_parameter_value_from_insn(index, 1, func, equivilant_operand);
				which_op = 0;
			}
		}
		//if not found the operand even in the first instruction in the function
		return_val=check_define_in_argument(index, operand, func,return_val);
		if (return_val != "") 
			return return_val;
		else if (return_val == "" && which_op != -1 && x64_is_use_stmt(Mnem, index, which_op)) continue;
		else if (return_val == "" && which_op != -1 && !x64_is_use_stmt(Mnem, index, which_op))
			return return_val;
	}
	return return_val;
}

std::string check_define_in_argument(int index, std::string operand,func_t * func,std::string return_val)
{
	if (index == func->start_ea)//if not found the operand even in the first instruction in the function
	{
		std::string tmp = x64_look_for_define_in_argument(operand);
		if (tmp != "")
			return_val = tmp;
		else
			return_val = return_val;
	}
	return return_val;
}

//If the operand we are looking for turn out to be the argument for the function, we return the corresponding argument.
std::string x64_look_for_define_in_argument(std::string operand)
{
	if (file_type.find("ELF") == 0)//linux binary
	{
		if (x64_is_equal_register(operand, "edi"))
			return "VAR0";
		else if (x64_is_equal_register(operand, "esi"))
			return "VAR1";
		else if (x64_is_equal_register(operand, "edx"))
			return "VAR2";
		else if (x64_is_equal_register(operand, "ecx"))
			return "VAR3";
		else if (x64_is_equal_register(operand, "r8"))
			return "VAR5";
		else if (x64_is_equal_register(operand, "r9"))
			return "VAR6";
		else if (x64_is_equal_register(operand, "esp"))
			return "VAR4";
	}
	else if (file_type == "Portable executable")
	{
		if (x64_is_equal_register(operand, "ecx"))
			return "VAR0";
		else if (x64_is_equal_register(operand, "edx"))
			return "VAR1";
		else if (x64_is_equal_register(operand, "r8"))
			return "VAR2";
		else if (x64_is_equal_register(operand, "r9"))
			return "VAR3";
		else if (x64_is_equal_register(operand, "esp"))
			return "VAR5";
	}
	return "";
}

void x64_redefine(ea_t ea, std::string defined_value, std::string new_value) {
	int equation_occurance = 0;
	for (int i = 0;i < defined_value.length();i++)
		if (defined_value[i] == '=')
			equation_occurance++;
	if (equation_occurance == 0)
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + new_value;
	}
	else if (equation_occurance == 1)
	{
		std::string substring = defined_value.substr(0, defined_value.find('='));
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = substring + "=" + new_value;
	}
}


void x64_replace_element(ea_t ea, int operand_num, std::string resolvable, std::string result, int* index) {
	if (operand_num == 0)
	{
		msg("x64_my_insn before replace resovable: %s  ", x64_my_insn[ea2x64_my_insn[ea]].operand0.c_str());
		x64_my_insn[ea2x64_my_insn[ea]].operand0.replace(x64_my_insn[ea2x64_my_insn[ea]].operand0.find(resolvable), resolvable.length(), result);
		msg("x64_my_insn after replace resovable: %s  \n", x64_my_insn[ea2x64_my_insn[ea]].operand0.c_str());
		*index = *index - resolvable.length() + result.length();
	}
	else if (operand_num == 1)
	{
		msg("x64_my_insn before replace resovable: %s  ", x64_my_insn[ea2x64_my_insn[ea]].operand1.c_str());
		x64_my_insn[ea2x64_my_insn[ea]].operand1.replace(x64_my_insn[ea2x64_my_insn[ea]].operand1.find(resolvable), resolvable.length(), result);
		msg("x64_my_insn after replace resovable: %s  \n", x64_my_insn[ea2x64_my_insn[ea]].operand1.c_str());
		*index = *index - resolvable.length() + result.length();
	}
}

//If "resolvable" is a register, look for its previous definition. If "resolvable" is a stack variable name, transform it into actual value.
std::string x64_resolve(ea_t ea, std::string resolvable, func_t* func) {
	ea_t index;
	std::string define;
	uval_t out;
	int real_value;
	define = x64_lookForDefine(resolvable, ea, func);
	if (x64_is_register(resolvable))//If "resolvable" is a register
	{
		if (define != "")
			return define;
		else
		{
			define = x64_allocate_new_variable(resolvable);
			return define;
		}
	}
	else if (regex_match(resolvable, std::regex("[$]*[0-9a-zA-Z_]+")))//If "resolvable" is a (stack) name
	{
		get_name_value(&out, ea, resolvable.c_str());
		real_value = 0 - out;
		return "-" + dec2hex(real_value);
	}
}

std::string x64_extract_value_from_insn(ea_t ea, int i, func_t* func) {

	if (i == 0) return x64_my_insn[ea2x64_my_insn[ea]].operand0;
	else if (i == 1) return x64_my_insn[ea2x64_my_insn[ea]].operand1;
}
std::string x64_extract_parameter_value_from_insn(ea_t ea, int i, func_t* func, std::string operand) {
	int index = ea2x64_my_insn[ea], start, end;
	if (i == 0)
	{
		if (x64_my_insn[index].operand0 == "") return "";
		return x64_my_insn[index].parameters0[operand];

	}
	else if (i == 1)
	{
		if (x64_my_insn[index].operand1 == "") return "";
		return x64_my_insn[index].parameters1[operand];
	}

}

void x64_look_for_same_displ(int operand_num, ea_t ea, func_t * func)
{
	int equation_index;
	if (operand_num == 1)
	{
		for (ea_t index=insn_last_insn[ea];index > func->start_ea;index = insn_last_insn[index])
		{
			if (x64_my_insn[ea2x64_my_insn[index]].operand0.find(x64_my_insn[ea2x64_my_insn[ea]].operand1+"=") == 0)
			{
				equation_index = x64_my_insn[ea2x64_my_insn[index]].operand0.find('=');
				x64_my_insn[ea2x64_my_insn[ea]].operand1 = x64_my_insn[ea2x64_my_insn[index]].operand0.substr(equation_index+1, x64_my_insn[ea2x64_my_insn[index]].operand0.size()-equation_index);
				return;
			}
			else if (x64_my_insn[ea2x64_my_insn[index]].operand1.find(x64_my_insn[ea2x64_my_insn[ea]].operand1+"=") == 0)
			{
				equation_index = x64_my_insn[ea2x64_my_insn[index]].operand1.find('=');
				x64_my_insn[ea2x64_my_insn[ea]].operand1 = x64_my_insn[ea2x64_my_insn[index]].operand1.substr(equation_index + 1, x64_my_insn[ea2x64_my_insn[index]].operand1.size() - equation_index);
				return;
			}

		}
	}
	else if (operand_num == 0)
	{
		for (ea_t index=ea;index > func->start_ea;index = insn_last_insn[index])
		{
			if (x64_my_insn[ea2x64_my_insn[index]].operand0.find(x64_my_insn[ea2x64_my_insn[ea]].operand0+"=") == 0)
			{
				equation_index = x64_my_insn[ea2x64_my_insn[index]].operand0.find('=');
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[index]].operand0.substr(equation_index+1, x64_my_insn[ea2x64_my_insn[index]].operand0.size() - equation_index);
				return;
			}
			else if (x64_my_insn[ea2x64_my_insn[index]].operand1.find(x64_my_insn[ea2x64_my_insn[ea]].operand0+"=") == 0)
			{
				equation_index = x64_my_insn[ea2x64_my_insn[index]].operand1.find('=');
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[index]].operand1.substr(equation_index + 1, x64_my_insn[ea2x64_my_insn[index]].operand1.size() - equation_index);
				return;
			}

		}
	}
}




bool is_in_loop(ea_t ea,int num)
{
	if (num == 0)
	{
		if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITER(") != -1)
			return true;
		else return false;
	}
	else if (num == 1)
	{
		if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find("ITER(") != -1)
			return true;
		else return false;
	}
}

//If any of the operand is renamed, we recover it back to its original register name.
/*void x64_recover_renamed_register(ea_t ea,std::string* operand0, std::string* operand1, std::string* operand2, int op0_type, int op1_type, int op2_type, int ea_operand_num)
{
	if (ea_operand_num == 1)
	{
		if (op0_type == 1 && !x64_is_register(*operand0))//if we detect this register has been renamed
			*operand0 = get_reg_name(ea,0);
	}
	else if (ea_operand_num == 2)
	{
		if (op0_type == 1 && !x64_is_register(*operand0))//if we detect this register has been renamed
			*operand0 = get_reg_name(ea, 0);
		if (op1_type == 1 && !x64_is_register(*operand1))//if we detect this register has been renamed
			*operand1 = get_reg_name(ea, 1);
	}
	else if (ea_operand_num == 3)
	{
		if (op0_type == 1 && !x64_is_register(*operand0))//if we detect this register has been renamed
			*operand0 = get_reg_name(ea, 0);
		if (op1_type == 1 && !x64_is_register(*operand1))//if we detect this register has been renamed
			*operand1 = get_reg_name(ea, 1);
		if (op2_type == 1 && !x64_is_register(*operand2))//if we detect this register has been renamed
			*operand2 = get_reg_name(ea, 2);
	}
}*/

//If found this instruction's is not caculatable (i.e., instruction set not supported or symbolic value explosion)
bool x64_is_not_calculatable(ea_t ea)
{
	if (x64_is_symbolic_value_explosion(ea))
		return true;
	else if (x64_Mnem_not_support(ea))
		return true;
}

//If Mnem not supported, return true
bool x64_Mnem_not_support(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (Mnem[0] == 'v'|| Mnem[0]=='k')
		return true;
	return false;
}

//If found this instruction's symbolic value is too large return true
bool x64_is_symbolic_value_explosion(ea_t ea)
{
	if (x64_my_insn[ea2x64_my_insn[ea]].operand0.size() > 7000)
		return true;
	else if (x64_my_insn[ea2x64_my_insn[ea]].operand1.size() > 7000)
		return true;
	else
	{
		for (const auto each_pair : x64_my_insn[ea2x64_my_insn[ea]].parameters0)
			if (each_pair.second.size() > 7000)
				return true;
		for (const auto each_pair : x64_my_insn[ea2x64_my_insn[ea]].parameters1)
			if (each_pair.second.size() > 7000)
				return true;
	}
	return false;
}

bool x64_is_switch_jump(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	int op0_type = get_optype(ea, 0);
	if (Mnem == "jmp" && (op0_type == 1|| op0_type == 3|| op0_type == 4|| op0_type == 2))
		return true;
	return false;
}

bool x64_is_number(std::string* operand)
{
	if ((*operand)[(*operand).size() - 1] == 'h' || (*operand)[(*operand).size() - 1] == 'H')
	{
		(*operand) = (*operand).substr(0, (*operand).size() - 1);
	}
	for (int i = 0;i < (*operand).size();i++)
	{
		if (isxdigit((*operand)[i]))
			continue;
		else
			return false;
	}
	return true;
}