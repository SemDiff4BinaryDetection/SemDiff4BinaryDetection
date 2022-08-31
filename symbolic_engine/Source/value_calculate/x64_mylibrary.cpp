#include "../../Headers/value_calculate/x64_mylibrary.h"
#include <map>


std::vector <x64_my_instruction> x64_my_insn;

std::map<int, int> ea2x64_my_insn;

std::vector<char> x64_iterate_mark;


void init_x64_my_instruction(func_t* func) {

	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		struct x64_my_instruction new_one;
		x64_my_insn.push_back(new_one);
		ea2x64_my_insn.insert(std::pair<int, int>(ea,x64_my_insn.size()-1));
		insn_last_insn.insert(std::pair<ea_t, ea_t>(ea, -1));
		x64_iterate_mark.push_back(' ');
	}
}

void check_windows_or_linux() 
{
	char file_type_char[20];
	get_file_type_name(file_type_char, 20);
	file_type = file_type_char;
}


/*void x64_allocate_assign_right_operand(ea_t ea) {
	std::string allocate_value;
	allocate_value = allocate_new_variable();
	x64_my_insn[ea2x64_my_insn[ea]].operand1 = allocate_value;//update right operand
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = allocate_value;//update left operand

}*/
void x64_propagate_to_left_operand(ea_t ea, std::string defined_value) {
	x64_my_insn[ea2x64_my_insn[ea]].operand0 += defined_value;//update left operand
}
void x64_propagate_to_right_operand(ea_t ea, std::string value) {
	x64_my_insn[ea2x64_my_insn[ea]].operand1 += value;//update right operand
}
void x64_propagate_to_right_left_operand(ea_t ea, std::string defined_value) {

	x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value;//update right operand
	x64_my_insn[ea2x64_my_insn[ea]].operand0 += defined_value;//update left operand
}



void x64_only_Rbase_is_defined_propagate(ea_t ea , std::string operand0,std::string defined_value,std::string defined_value1, func_t* func) {
	qstring Mnemq;
	std::string Mnem;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	x64_define_base(ea, 1, defined_value1);
	x64_further_explain_displace(ea, 1, func,defined_value1.length()+2);
	x64_look_for_same_displ(1, ea, func);
	defined_value1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	if (Mnem == "movd")
	{
		defined_value = x64_movd(operand0, defined_value, defined_value1);
	}
	else if (Mnem == "movq")
		defined_value = x64_movq(operand0, "[]", defined_value, defined_value1);
	else defined_value = x64_get_right_sub_reg(operand0,defined_value,defined_value1);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 =defined_value ;//update left operand
}


void x64_even_Rbase_is_not_defined_propagate(ea_t ea, func_t* func,std::string operand0,std::string left_op,std::string operand1) {
	qstring Mnemq;
	std::string Mnem, tmp;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string allocate_value;
	allocate_value = x64_allocate_new_variable(x64_extractBase(operand1));
	x64_define_base(ea, 1, allocate_value);
	x64_further_explain_displace(ea, 1, func,allocate_value.length()+2);
	tmp = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	if (Mnem == "movd")
	{
		left_op = x64_movd(operand0, left_op, tmp);
	}
	else if (Mnem == "movq")
		left_op = x64_movq(operand0, "[]", left_op, tmp);
	else left_op = x64_get_right_sub_reg(operand0, left_op, tmp);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = left_op;//update left operand
}

void x64_even_Rbase_is_not_defined_sub_update(ea_t ea, func_t* func, std::string defined_value)
{
	/*qstring Mnemq;
	std::string Mnem, tmp;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string allocate_value;
	allocate_value = allocate_new_variable();
	x64_define_base(ea, 1, allocate_value);
	x64_further_explain_displace(ea, 1, func, allocate_value.length() + 2);
	tmp = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	if (Mnem == "movd")
		tmp = tmp + "&ffffffff";
	else if (Mnem == "movq")
		tmp = tmp;
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value+"&"+ tmp;//update left operand*/
}


void x64_Ldefined_base_propagate(ea_t ea, std::string defined_value,std::string value, func_t* func) {
	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	x64_define_base(ea, 0, defined_value);
	x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);

	if (disasms.find("xmmword") != -1)//xmm
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
	else if (disasms.find("qword") != -1)//rx
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
	else if (disasms.find("dword") != -1)//ex
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
	else if (disasms.find("word") != -1)//x
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "= (" + x64_my_insn[ea2x64_my_insn[ea]].operand0 + "&ffffffffffff0000)|" + value;//update left operand
	}
	else if (disasms.find("byte") != -1)//al
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "= (" + x64_my_insn[ea2x64_my_insn[ea]].operand0 + "&ffffffffffffff00)|" + value;//update left operand
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
}

void x64_even_Lundefined_base_propagate(ea_t ea, std::string value, func_t* func,std::string operand0)
{
	std::string allocate_value;
	allocate_value = x64_allocate_new_variable(x64_extractBase(operand0));
	x64_define_base(ea, 0, allocate_value);
	x64_further_explain_displace(ea, 0,func,allocate_value.length()+2);

	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	if (disasms.find("xmmword") != -1)//xmm
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
	else if (disasms.find("qword") != -1)//rx
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
	else if (disasms.find("dword") != -1)//ex
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
	else if (disasms.find("word") != -1)//x
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "= (" + x64_my_insn[ea2x64_my_insn[ea]].operand0 + "&ffffffffffff0000)|" + value;//update left operand
	}
	else if (disasms.find("byte") != -1)//al
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "= (" + x64_my_insn[ea2x64_my_insn[ea]].operand0 + "&ffffffffffffff00)|" + value;//update left operand
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + value;//update left operand
	}
}


void x64_further_explain_displace(ea_t ea, int operand_num, func_t* func, int index) {
	int length;
	std::string to_resolve, result,result1,result2;
	if (ea == 0x65839e85)
		int breakp = 1;
	if (operand_num == 0)
	{
		while (index < x64_my_insn[ea2x64_my_insn[ea]].operand0.length())
		{
			to_resolve = get_next_element(x64_my_insn[ea2x64_my_insn[ea]].operand0, &index);
			if (not_resolvable(to_resolve) == true) continue;
			result = x64_resolve(ea, to_resolve, func);
			msg("next resolvable is: %s  ", to_resolve.c_str());			
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert(std::pair<std::string, std::string>(to_resolve, result));
			x64_replace_element(ea, 0, to_resolve, result,&index);
		}
	}
	else if (operand_num == 1)
	{
		while (index < x64_my_insn[ea2x64_my_insn[ea]].operand1.length())
		{
			to_resolve = get_next_element(x64_my_insn[ea2x64_my_insn[ea]].operand1, &index);
			if (not_resolvable(to_resolve) == true) continue;
			result = x64_resolve(ea, to_resolve, func);
			msg("next resolvable is %s  ", to_resolve.c_str());
			x64_my_insn[ea2x64_my_insn[ea]].parameters1.insert(std::pair<std::string, std::string>(to_resolve, result));
			x64_replace_element(ea, 1, to_resolve, result,&index);
		}
	}

}



void x64_display_results(func_t* func) {
	ea_t index;
	std::string comment;
	for (index = func->start_ea;index < func->end_ea && index != BADADDR; index = find_code(index, SEARCH_DOWN | SEARCH_NEXT)) {
		qstring disasm;
		generate_disasm_line(&disasm, index, GENDSM_REMOVE_TAGS);
		msg("%x  ", index);
		msg("%s  ", disasm.c_str());
		msg("operand0:%s  ", x64_my_insn[ea2x64_my_insn[index]].operand0.c_str());
		msg("operand1:%s  \n", x64_my_insn[ea2x64_my_insn[index]].operand1.c_str());
		comment = x64_my_insn[ea2x64_my_insn[index]].operand0.c_str();
		comment += ",";
		comment += x64_my_insn[ea2x64_my_insn[index]].operand1.c_str();
		set_cmt(index,comment.c_str(),false);
	}
}

void x64_lea_explain_member_propagate(ea_t ea, func_t* func)
{
	//x64_my_insn[ea2x64_my_insn[ea]].operand1 = x64_get_operand(ea, 1);
	std::string defined_value, operand1;
	defined_value = x64_lookForDefine(x64_extractBase(x64_get_operand(ea,1)),ea,func);
	if (defined_value == "")
		defined_value = x64_allocate_new_variable(x64_extractBase(x64_get_operand(ea, 1)));
	x64_define_base(ea, 1, defined_value);
	//x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"original",operand0 });
	x64_further_explain_displace(ea, 1, func, defined_value.length()+2);
	x64_my_insn[ea2x64_my_insn[ea]].operand1.replace(x64_my_insn[ea2x64_my_insn[ea]].operand1.find('['), 1,"(");
	x64_my_insn[ea2x64_my_insn[ea]].operand1.replace(x64_my_insn[ea2x64_my_insn[ea]].operand1.rfind(']'), 1,")");
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
}

void x64_lea_extract_string_content_propagate(ea_t ea, func_t* func,std::string operand0,std::string operand1) {
	ea_t ea1 = get_name_ea(BADADDR, operand1.c_str());
	func_t* func1 = get_func(ea1);
	std::string tmp;
	if (func1 == NULL)//if the label really points to a string
	{
		tmp = get_label_value(operand1);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = tmp;
	}
	else if (func1 != NULL)//if the label points to a function
	{
		tmp = x64_allocate_new_variable("rax");
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = tmp;
	}
}

//Look up *operand* value of *ea* in executed instructions, then put value into *defined_value*. 
void x64_get_reg_val(ea_t ea, std::string operand, func_t * func, std::string &defined_value)
{
	defined_value = x64_lookForDefine(operand, ea, func);
	if (defined_value == "") { defined_value = x64_allocate_new_variable(operand); }
	//if (defined_value[0] == '-')
	//	defined_value = "-(" + defined_value.substr(1, defined_value.size() - 2) + ')';
}

//Initialize displ operands by looking up each operand in the [], and translate the content within [].
void x64_get_disp_val(ea_t ea, int index, std::string operand, func_t* func)
{
	std::string defined_value;
	defined_value = x64_lookForDefine(x64_extractBase(operand), ea, func);
	if (defined_value == "") { defined_value = x64_allocate_new_variable(x64_extractBase(operand)); }
	x64_define_base(ea, index, defined_value);
	x64_further_explain_displace(ea, index, func, defined_value.length() + 2);
}

void  x64_arithmatic_propagate_reg_reg(std::string operand_to_decide, std::string defined_value, std::string defined_value1, ea_t ea,  std::string Mnem) {
	std::string operand;
	std::string operand_size = which_operand_size(operand_to_decide);
	x64_propagate_to_right_operand(ea, defined_value1);
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"original",defined_value });
	defined_value=x64_arithmatic_result_basedon_size(defined_value, defined_value1, operand_size, Mnem);
	x64_propagate_to_left_operand(ea, defined_value);
}

void x64_arithmatic_propagate_reg_displ(std::string operand_to_decide, std::string defined_value, ea_t ea, std::string Mnem) {
	std::string operand1;
	std::string operand_size = which_operand_size(operand_to_decide);
	operand1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	
	/*if(operand_size == "xmmword")//xmm
	{
		defined_value = "(" + defined_value + Mnem + operand1 + ")";
	}
	else if (operand_size == "qword")//rx
	{
		defined_value = "(" + defined_value + Mnem + operand1 + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(operand1, 32))
			operand1 = operand1;
		else
			operand1 = "(" + operand1 + "&ffffffff)";
		if (x64_is_within_size(defined_value, 32))
			defined_value = defined_value;
		else
			defined_value = "(" + defined_value + "&ffffffff)";
		defined_value = "(" + defined_value + Mnem + operand1 + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(defined_value, 16))
		{
			defined_value = defined_value;
			if (x64_is_within_size(operand1, 16))
				operand1 = operand1;
			else
				operand1 = "(" + operand1 + "&ffff)";
			defined_value = "("+defined_value + Mnem + operand1+")";
		}
		else
		{
			if (x64_is_within_size(operand1, 16))
				operand1 = operand1;
			else
				operand1 = "(" + operand1 + "&ffff)";
			defined_value = "(" + defined_value + "&(((" + defined_value + "&ffff)" + Mnem + operand1 + ")&ffff))";
		}
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(defined_value, 8))
		{
			defined_value = defined_value;
			if (x64_is_within_size(operand1, 8))
				operand1 = operand1;
			else
				operand1 = "(" + operand1 + "&ff00)";
			defined_value = "("+defined_value + Mnem + operand1+")";
		}
		else
		{
			if (x64_is_within_size(operand1, 8))
				operand1 = operand1;
			else
				operand1 = "(" + operand1 + "&ff00)";
			defined_value = "(" + defined_value + "&(((" + defined_value + "&ff00)" + Mnem + operand1 + ")&ff00))";
		}
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(defined_value, 8))
		{
			defined_value = defined_value;
			if (x64_is_within_size(operand1, 8))
				operand1 = operand1;
			else
				operand1 = "(" + operand1 + "&ff)";
			defined_value = "("+defined_value + Mnem + operand1+")";
		}
		else
		{
			if (x64_is_within_size(operand1, 8))
				operand1 = operand1;
			else
				operand1 = "(" + operand1 + "&ff)";
			defined_value = "(" + defined_value + "&(((" + defined_value + "&ff)" + Mnem + operand1 + ")&ff))";
		}
	}*/
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
	defined_value = x64_arithmatic_result_basedon_size(defined_value, operand1, operand_size, Mnem);
	x64_propagate_to_left_operand(ea,defined_value);
}

void x64_arithmatic_propagate_reg_num(std::string operand_to_decide,std::string defined_value, ea_t ea, std::string Mnem) {
	std::string num;
	std::string operand_size = which_operand_size(operand_to_decide);
	num = x64_get_operand(ea, 1);

	/*if (operand_size == "xmmword")//xmm
	{
		defined_value = "(" + defined_value + Mnem + num + ")";
	}
	else if (operand_size == "qword")//rx
	{
		defined_value = "(" + defined_value + Mnem + num + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(num, 32))
			num = num;
		else
			num = "(" + num + "&ffffffff)";
		if (x64_is_within_size(defined_value, 32))
			defined_value = defined_value;
		else
			defined_value = "(" + defined_value + "&ffffffff)";
		defined_value = "(" + defined_value + Mnem + num + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(defined_value, 16))
		{
			defined_value = defined_value;
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			defined_value = "("+defined_value + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			defined_value = "(" + defined_value + "&(((" + defined_value + "&ffff)" + Mnem + num + ")&ffff))";
		}
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(defined_value, 8))
		{
			defined_value = defined_value;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			defined_value = "("+defined_value + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			defined_value = "(" + defined_value + "&(((" + defined_value + "&ff00)" + Mnem + num + ")&ff00))";
		}
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(defined_value, 8))
		{
			defined_value = defined_value;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			defined_value = "("+defined_value + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			defined_value = "(" + defined_value + "&(((" + defined_value + "&ff)" + Mnem + num + ")&ff))";
		}
	}*/
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
	defined_value = x64_arithmatic_result_basedon_size(defined_value, num, operand_size, Mnem);
	x64_propagate_to_left_operand(ea, defined_value);
}

void x64_arithmatic_propagate_reg_label(std::string operand_to_decide, std::string defined_value, ea_t ea, std::string Mnem) {
	std::string operand1,tmp;
	std::string operand_size = which_operand_size(operand_to_decide);
	operand1 = x64_get_operand(ea, 1);
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });

	tmp = get_label_value(operand1);
	defined_value = x64_arithmatic_result_basedon_size(defined_value, tmp, operand_size, Mnem);
	x64_propagate_to_left_operand(ea, defined_value);
}



void x64_arithmatic_propagate_displ_reg(std::string operand_to_decide,std::string defined_value, ea_t ea, std::string Mnem) {
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
	//x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value;
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0;
	std::string address;
	if (operand0.find("=") != -1)
	{
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.length() - 1 - operand0.find("="));
		address= operand0.substr(0,operand0.find("="));
	}
	else if (operand0.find("=") == -1)
	{
		address = operand0;
	}
	/*if (operand_size == "xmmword")//xmm
	{
		operand0 = "(" + operand0 + Mnem + defined_value + ")";
	}
	else if (operand_size == "qword")//rx
	{
		operand0 = "(" + operand0 + Mnem + defined_value + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(defined_value, 32))
			defined_value = defined_value;
		else
			defined_value = "(" + defined_value + "&ffffffff)";
		if (x64_is_within_size(operand0, 32))
			operand0 = operand0;
		else
			operand0 = "(" + operand0 + "&ffffffff)";
		defined_value = "(" + operand0 + Mnem + defined_value + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(operand0, 16))
		{
			operand0 = operand0;
			if (x64_is_within_size(defined_value, 16))
				defined_value = defined_value;
			else
				defined_value = "(" + defined_value + "&ffff)";
			operand0 = "("+operand0 + Mnem + defined_value+")";
		}
		else
		{
			if (x64_is_within_size(defined_value, 16))
				defined_value = defined_value;
			else
				defined_value = "(" + defined_value + "&ffff)";
			operand0 = "(" + operand0 + "&(((" + operand0 + "&ffff)" + Mnem + defined_value + ")&ffff))";
		} 
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(operand0, 8))
		{
			operand0 = operand0;
			if (x64_is_within_size(defined_value, 8))
				defined_value = defined_value;
			else
				defined_value = "(" + defined_value + "&ff00)";
			operand0 = "("+operand0 + Mnem + defined_value+")";
		}
		else
		{
			if (x64_is_within_size(defined_value, 8))
				defined_value = defined_value;
			else
				defined_value = "(" + defined_value + "&ff00)";
			operand0 = "(" + operand0 + "&(((" + operand0 + "&ff00)" + Mnem + defined_value + ")&ff00))";
		}
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(operand0, 8))
		{
			operand0 = operand0;
			if (x64_is_within_size(defined_value, 8))
				defined_value = defined_value;
			else
				defined_value = "(" + defined_value + "&ff)";
			operand0 = "("+operand0 + Mnem + defined_value+")";
		}
		else
		{
			if (x64_is_within_size(defined_value, 8))
				defined_value = defined_value;
			else
				defined_value = "(" + defined_value + "&ff)";
			operand0 = "(" + operand0 + "&(((" + operand0 + "&ff)" + Mnem + defined_value + ")&ff))";
		}
		//operand0 = "(" + operand0 + "&(((" + operand0 + "&ff)" + Mnem + "(" + defined_value + "&ff))&ff))";
	}
	*/
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",operand0 });
	operand0 = x64_arithmatic_result_basedon_size(operand0, defined_value, operand_size, Mnem);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = address+"="+operand0;
}

void x64_arithmatic_propagate_displ_num(ea_t ea, std::string Mnem) {
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
	std::string operand_size = which_operand_size(ea);
	std::string operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0;
	std::string address;
	if (operand0.find("=") != -1)
	{
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.length() - 1 - operand0.find("="));
		address= operand0.substr(0, operand0.find("="));
	}
	else if (operand0.find("=") == -1)
	{
		address = operand0;
	}
	std::string num = x64_get_operand(ea, 1);
	/*if (disasms.find("qword") != -1)//rx
	{
		operand0 = "("+operand0 + Mnem + num+")";
	}
	else if (disasms.find("dword") != -1)//ex
	{
		if (x64_is_within_size(operand0, 32))
			operand0 = operand0;
		else
			operand0 = "(" + operand0 + "&ffffffff)";
		if (x64_is_within_size(num, 32))
			num = num;
		else
			num = "(" + num + "&ffffffff)";
		operand0 = "(" + operand0 + Mnem + num + ")";
	}
	else if (disasms.find(" word") != -1)//x
	{
		if (x64_is_within_size(operand0, 16))
		{
			operand0 = operand0;
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			operand0 = "("+operand0 + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			operand0 = "(" + operand0 + "&(((" + operand0 + "&ffff)" + Mnem + num + ")&ffff))";
		}
	}
	else if (disasms.find("byte") != -1)//al
	{
		if (x64_is_within_size(operand0, 8))
		{
			operand0 = operand0;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			operand0 = "("+operand0 + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			operand0 = "(" + operand0 + "&(((" + operand0 + "&ff)" + Mnem + num + ")&ff))";
		}
		//operand0 = "(" + operand0 + "&(((" + operand0 + "&ff)" + Mnem + "(" + num + "&ff))&ff))";
	}
	else
	{
		operand0 = "(" + operand0 + Mnem + num + ")";
	}
	*/
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",operand0 });
	operand0 = x64_arithmatic_result_basedon_size(operand0, num, operand_size, Mnem);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 =address+"="+operand0;
}

void x64_arithmatic_propagate_displ_label(ea_t ea, std::string Mnem) {
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
	std::string operand_size = which_operand_size(ea);
	std::string operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0;
	std::string address;
	if (operand0.find("=") != -1)
	{
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.length() - 1 - operand0.find("="));
		address = operand0.substr(0, operand0.find("="));
	}
	else if (operand0.find("=") == -1)
	{
		address = operand0;
	}
	std::string operand1 = x64_get_operand(ea, 1);
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",operand0 });

	std::string tmp = get_label_value(operand1);

	operand0 = x64_arithmatic_result_basedon_size(operand0, tmp, operand_size, Mnem);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=" + operand0;
}


void x64_arithmatic_propagate_reg_reg_num(std::string operand_to_decide,std::string defined_value, std::string defined_value1,std::string num, ea_t ea, std::string Mnem)
{
	std::string operand1;
	std::string operand_size = which_operand_size(operand_to_decide);
	if (defined_value1 == "dup 1")//imul eax, eax, xxx
		defined_value1 = defined_value;
	else
		x64_propagate_to_right_operand(ea, defined_value1);//imul eax, ex(not eax), xxx

	if (operand_size == "xmmword")//xmm
	{
		defined_value = "(" + defined_value1 + Mnem + num + ")";
	}
	else if (operand_size == "qword")//rx
	{
		defined_value = "(" + defined_value1 + Mnem + num + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(defined_value1, 32))
			defined_value1 = defined_value1;
		else
			defined_value1 = "(" + defined_value1 + "&ffffffff)";
		if (x64_is_within_size(num, 32))
			num = num;
		else
			num = "(" + num + "&ffffffff)";
		defined_value = "(" + defined_value1 + Mnem + num + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(defined_value1, 16))
		{
			defined_value1 = defined_value1;
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			defined_value1 = "("+defined_value1 + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			defined_value1 = "(((" + defined_value1 + "&ffff)" + Mnem + num + ")&ffff)";
		}
		defined_value = "(("+defined_value + "&ffffffffffff0000)|(" + defined_value1 + "))";
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(defined_value1, 8))
		{
			defined_value1 = defined_value1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			defined_value1 = "("+defined_value1 + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			defined_value1 = "(((" + defined_value1 + "&ff00)" + Mnem + num + ")&ff00)";
		}
		defined_value = "((" + defined_value + "&ffffffffffff00ff)|(" + defined_value1 + "))";
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(defined_value1, 8))
		{
			defined_value1 = defined_value1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			defined_value1 = "("+defined_value1 + Mnem + num+")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			defined_value1 = "(((" + defined_value1 + "&ff)" + Mnem + num + ")&ff)";
		}
		defined_value = "((" + defined_value + "&ffffffffffffff00)|(" + defined_value1 +"))";
	}
	//defined_value = x64_arithmatic_result_basedon_size(defined_value1, num, operand_size, Mnem);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
}

void x64_arithmatic_propagate_reg_disp_num(std::string operand_to_decide, ea_t ea, std::string Mnem,std::string defined_value1) {
	std::string num, operand1;
	num = x64_get_operand(ea, 2);
	if (num[0] == '-')
		num = "(-(" + num.substr(1,num.size()-1) + "))";
	std::string operand_size = which_operand_size(operand_to_decide);
	operand1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	if (operand_size == "xmmword")//xmm
	{
		defined_value1 = "(" + operand1 + Mnem + num + ")";
	}
	else if (operand_size == "qword")//rx
	{
		defined_value1 = "(" + operand1 + Mnem + num + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(operand1, 32))
			operand1 = operand1;
		else
			operand1 = "(" + operand1 + "&ffffffff)";
		if (x64_is_within_size(num, 32))
			num = num;
		else
			num = "(" + num + "&ffffffff)";
		defined_value1 = "(" + operand1 + Mnem + num + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(operand1, 16))
		{
			operand1 = operand1;
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			operand1 = "(" + operand1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			operand1 = "(((" + operand1 + "&ffff)" + Mnem + num + ")&ffff)";
		}
		defined_value1 = "((" + defined_value1 + "&ffffffffffff0000)|" + operand1 + ")";
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(operand1, 8))
		{
			operand1 = operand1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			operand1 = "(" + operand1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			operand1 = "(((" + operand1 + "&ff00)" + Mnem + num + ")&ff00)";
		}
		defined_value1 = "((" + defined_value1 + "&ffffffffffff00ff)|" + operand1 + ")";
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(operand1, 8))
		{
			operand1 = operand1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			operand1 = "(" + operand1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			operand1 = "(((" + operand1 + "&ff)" + Mnem + num + ")&ff)";
		}
		defined_value1 = "((" + defined_value1 + "&ffffffffffffff00)|" + operand1+")";
	}
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value1;
}

void x64_div_propagate_reg(std::string operand_to_decide,std::string defined_value, ea_t ea, func_t* func, std::string Mnem)
{
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string operand0 = x64_lookForDefine("eax", ea, func);
	std::string operand1= x64_lookForDefine("edx", ea, func);
	std::string catenate;
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
	if (operand_size == "qword")//rx
	{
		if (operand1 == "0" || operand1=="")
			catenate = operand0;
		else
			catenate = operand1 + "<<64|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size == "dword")//ex
	{
		if (!x64_is_within_size(operand1, 32))
			operand1 = "(" + operand1 + "&ffffffff)";
		if(!x64_is_within_size(operand0,32))
			operand0= "(" + operand0 + "&ffffffff)";
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "("+defined_value + "&ffffffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<32|" + operand0;
		operand0 = "(" +catenate + Mnem +  defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size == "word")//x
	{
		if (!x64_is_within_size(operand1, 16))
			operand1 = "(" + operand1 + "&ffff)";
		if (!x64_is_within_size(operand0, 16))
			operand0 = "(" + operand0 + "&ffff)";
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<16|" + operand0;
		operand0 = "((" + catenate + Mnem +  defined_value + ")&ffff)";
		operand1= "((" + catenate + "%" + defined_value + ")&ffff)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1});
	}
	else if (operand_size == "lbyte")//al
	{
		if (!x64_is_within_size(operand1, 8))
			operand1 = "(" + operand1 + "&ff)";
		if (!x64_is_within_size(operand0, 8))
			operand0 = "(" + operand0 + "&ff)";
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		operand0 = "((" + operand0 + "&ffffffffffffff00)|((" + operand0 + Mnem + defined_value +\
			")&ff)|((("+operand0+"%"+defined_value+")&ff)<<8))";
	}
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "eax",operand0 });
}

void x64_div_propagate_label(std::string label_operand, ea_t ea, func_t* func, std::string Mnem)
{
	std::string operand0 = x64_lookForDefine("eax", ea, func);
	std::string operand1 = x64_lookForDefine("edx", ea, func);
	std::string catenate;
	if (operand1 == "0" || operand1 == "")
		catenate = operand0;
	else
		catenate = operand1 + "<<64|" + operand0;
	operand0 = "(" + catenate + Mnem + label_operand + ")";
	operand1 = "(" + catenate + "%" + label_operand + ")";
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "eax",operand0 });
}


void x64_div_propagate_disp(ea_t ea, func_t* func, std::string Mnem)
{
	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	std::string operand0 = x64_lookForDefine("eax", ea, func);
	std::string operand1 = x64_lookForDefine("edx", ea, func);
	std::string defined_value=x64_my_insn[ea2x64_my_insn[ea]].operand0;
	std::string catenate;
	if (disasms.find("qword") != -1)//rx
	{
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<64|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	}
	else if (disasms.find("dword") != -1)//ex
	{
		if (!x64_is_within_size(operand1, 32))
			operand1 = "(" + operand1 + "&ffffffff)";
		if (!x64_is_within_size(operand0, 32))
			operand0 = "(" + operand0 + "&ffffffff)";
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "(" + defined_value + "&ffffffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<32|" + operand0;
		operand0 = "(" + catenate + Mnem +  defined_value + ")";
		operand1 = "(" + catenate + "%(" + defined_value + "&ffffffff))";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	}
	else if (disasms.find(" word") != -1)//x
	{
		if (!x64_is_within_size(operand1, 16))
			operand1 = "(" + operand1 + "&ffff)";
		if (!x64_is_within_size(operand0, 16))
			operand0 = "(" + operand0 + "&ffff)";
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<16|" + operand0;
		operand0 = "((" + catenate + Mnem + defined_value + ")&ffff)";
		operand1 = "((" + catenate + "%" + defined_value + ")&ffff)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	}
	else if (disasms.find("byte") != -1)//al
	{
		if (!x64_is_within_size(operand1, 8))
			operand1 = "(" + operand1 + "&ff)";
		if (!x64_is_within_size(operand0, 8))
			operand0 = "(" + operand0 + "&ff)";
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		operand0 = "((" + operand0 + "&ffffffffffffff00)|((" + operand0 + Mnem + defined_value + \
			")&ff)|(((" + operand0 + "%" + defined_value + ")&ff)<<8))";
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		if (operand1 == "0")
			catenate = operand0;
		else
			catenate = operand1 + "<<64|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx" ,operand1 });
	}
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"eax",operand0});//update left operand
}

void x64_mul_single_propagate_reg(std::string operand_to_decide, std::string defined_value, ea_t ea, func_t* func, std::string Mnem)
{
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string operand = x64_lookForDefine("eax", ea, func);
	std::string defined_value1= x64_lookForDefine("edx", ea, func);;
	if (operand_size == "qword")//rx
	{
		defined_value = "(" + defined_value + "*" + operand + "&ffffffffffffffff)";
		defined_value1 = "((" + defined_value + "*" + operand + "&ffffffffffffffff0000000000000000)>>64)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}
	else if (operand_size == "dword")//ex
	{
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "("+defined_value + "&ffffffff)";
		if (!x64_is_within_size(operand, 32))
			operand = "(" + operand + "&ffffffff)";
		defined_value ="((" + defined_value + "*" + operand + ")&ffffffff)";
		defined_value1 = "(((" + defined_value + "*" + operand + ")&ffffffff00000000)>>32)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}
	else if (operand_size == "word")//x
	{
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (!x64_is_within_size(operand, 16))
			operand = "(" + operand + "&ffff)";
		defined_value = "((" + operand + "&ffffffffffff0000)|(" + defined_value + "*" + operand + ")&ffff)";
		defined_value1 = "((" + defined_value1 + "&ffffffffffff0000)|((" + defined_value + "*" + operand + ")&ffff0000)>>16)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}
	else if (operand_size == "lbyte")//al
	{
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		if (!x64_is_within_size(operand, 8))
			operand = "(" + operand + "&ff)";
		defined_value = "((" + operand + "&ffffff00)|((" + defined_value + "*" + operand + ")&ffff))";
	}
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"eax",defined_value});
}

void x64_mul_single_propagate_disp(ea_t ea, func_t* func, std::string Mnem)
{
	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	std::string operand0 = x64_lookForDefine("eax", ea, func);
	std::string defined_value1 = x64_lookForDefine("edx", ea, func);
	std::string defined_value = x64_my_insn[ea2x64_my_insn[ea]].operand0;
	if (disasms.find("qword") != -1)//rx
	{
		defined_value = "((" + operand0 + "*" + defined_value + ")&ffffffffffffffff)";
		defined_value1 = "(((" + operand0 + "*" + defined_value + ")&ffffffffffffffff0000000000000000)>>64)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}
	else if (disasms.find("dword") != -1)//ex
	{
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "(" + defined_value + "&ffffffff)";
		if (!x64_is_within_size(operand0, 32))
			operand0 = "(" + operand0 + "&ffffffff)";
		defined_value = "((" + operand0 + "*" + defined_value + ")&ffffffff)";
		defined_value1 = "(((" + operand0 + "*" + defined_value + ")&ffffffff00000000)>>32)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}
	else if (disasms.find("word") != -1)//x
	{
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (!x64_is_within_size(operand0, 16))
			operand0 = "(" + operand0 + "&ffff)";
		defined_value = "(("+operand0 + "&ffffffffffff0000)|((" + operand0 + "*" + defined_value + ")&ffff))";
		defined_value1 = "(("+defined_value1 + "&ffffffffffff0000)|(((" + operand0 + "*" + defined_value + ")&ffff0000)>>16))";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}
	else if (disasms.find("byte") != -1)//al
	{
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		if (!x64_is_within_size(operand0, 8))
			operand0 = "(" + operand0 + "&ff)";
		defined_value = "(("+operand0 + "&ffffffffffffff00)|((" + operand0 + "*" + defined_value + ")&ffff))";
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		defined_value = "((" + operand0 + "*" + defined_value + ")&ffffffffffffffff)";
		defined_value1 = "(((" + operand0 + "*" + defined_value + ")&ffffffffffffffff0000000000000000)>>64)";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "edx",defined_value1 });
	}

	x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "eax",defined_value });//update left operand
}

bool x64_is_pop_insn(ea_t ea) {
	qstring Mnem;
	print_insn_mnem(&Mnem, ea);
	if (Mnem == "pop")
		return true;
	return false;
}

bool x64_is_conditional_insn(ea_t ea)
{
	qstring Mnem;
	print_insn_mnem(&Mnem, ea);
	if (Mnem.find("cmov")!=-1)
		return true;
	return false;
}

void x64_print_path(ea_t ea, func_t* func) {
	std::vector <ea_t> insns;
	for (ea_t index = insn_last_insn[ea];index > func->start_ea;index = insn_last_insn[index])
	{
		insns.push_back(index);
	}
	std::reverse(insns.begin(), insns.end());
	for (int i = insns.size() - 1;i > 0;i--)
	{
		printf("%x\n", insns[i]);
	}
}

//This is for processing when sliding operand is not a full register i.e., part of the register.
//Returns correct value
std::string sub_shift(std::string defined_value, std::string operand0, std::string operand1, std::string shift)
{
	std::string temp;
	std::string operand_size = which_operand_size(operand0);
	if (operand_size == "qword")//rol rx,num
		defined_value = defined_value + shift+operand1;
	else if (operand_size == "dword")//rol ex,num
	{
		if (!x64_is_within_size(defined_value, 32))
			temp = '(' + defined_value + "&0xffffffff)";
		else
			temp = defined_value;
		defined_value = temp + shift + operand1;
	}
	else if (operand_size == "word")//rol x, num
	{
		if (!x64_is_within_size(defined_value, 16))
			temp = '(' + defined_value + "&0xffff" + ')';
		else
			temp = defined_value;
		defined_value = "(("+defined_value + "&ffffffffffff0000)|(" + temp + shift + operand1+"))";
	}
	else if (operand_size == "hbyte")//rol ah,xxx
	{
		if (!x64_is_within_size(defined_value, 8))
			temp = '(' + defined_value + "&0xff00" + ')';
		else
			temp = defined_value;
		defined_value = "(("+defined_value + "&ffffffffffff00ff)|(" + temp + shift + operand1+"))";
	}
	else if (operand_size == "lbyte")//rol al, num
	{
		if (!x64_is_within_size(defined_value, 8))
			temp = '(' + defined_value + "&0xff)";
		else
			temp = defined_value;
		defined_value = "(("+defined_value + "&ffffffffffffff00)|(" + temp + shift + operand1+"))";
	}
	return defined_value;
}

//This is for returning the correct result when some operand moves into other operand e.g., mov ax,bx
//The correct result shoule be upper part of rax and bx.
std::string x64_get_right_sub_reg(std::string operand_to_decide,std::string left_op, std::string right_op)
{
	std::string return_string;
	std::string operand_size = which_operand_size(operand_to_decide);
	if(operand_size == "xmmword")//xmmword
		return_string = right_op;
	else if (operand_size == "qword")//rx
		return_string = right_op;
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(right_op, 32)==true)
			return_string = right_op;
		else
			return_string = "("+right_op + "&ffffffff)";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(right_op, 16)==true)
			return_string = "(("+left_op + "&ffffffffffff0000)|(" + right_op+"))" ;
		else
			return_string = "(("+left_op+"&ffffffffffff0000)|("+ right_op + "&ffff))";
	}
	else if (operand_size == "hbyte")//ah 
	{
		if (x64_is_within_size(right_op, 8)==true)
			return_string = "(("+left_op + "&ffffffffffff00ff)|(" + right_op+"))" ;
		else
			return_string = "(("+left_op+"&ffffffffffff00ff)|("+ right_op + "&ff00))";
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(right_op, 8)==true)
			return_string = "(("+left_op + "&ffffffffffffff00)|(" + right_op+"))";
		else
			return_string = "(("+left_op+"&ffffffffffffff00)|("+ right_op + "&ff))";
	}
	return return_string;
}


std::vector<std::string> split_expression(std::string expression)
{
	std::vector<std::string> expression_list;
	int index = 0;
	std::string to_resolve;
	while (index < expression.length())
	{
		to_resolve = get_next_element(expression, &index);
		expression_list.push_back(to_resolve);
 	}
	return expression_list;
}

bool x64_is_within_size(std::string operand, long long int size)
{
	if (x64_is_register(operand))//operand is not an expression, just a variable or a number
	{
		if (operand.find(".") != -1)//operand is like VAR1.64
		{
			std::string suffix = operand.substr(operand.find('.') + 1, operand.size() - 1 - operand.find("."));
			int ioperand_size;
			if (suffix == "128")
				ioperand_size = 128;
			else if (suffix == "64")
				ioperand_size = 64;
			else if (suffix == "32")
				ioperand_size = 32;
			else if (suffix == "16")
				ioperand_size = 16;
			else if (suffix == "8")
				ioperand_size = 8;
			if (ioperand_size <= size)
				return true;
			else
				return false;
		}
	}
	else if (x64_is_number(&operand) == true)//operand is a number
	{
		//operand = operand.substr(0, operand.size() - 1);
		long long int number = strtoull(operand.c_str(), 0, 16);
		if (size == 8)
			size = 0xff;
		else if (size == 16)
			size = 0xffff;
		else if (size == 32)
			size = 0xffffffff;
		else if (size == 64)
			size == 0xffffffffffffffff;
		if (number <= size)
			return true;
		else
			return false;
	}
	else if (operand[0] == '"' && operand[operand.size() - 1] == '"')
		return true;
	else//operand is an expression
		return false;
}

std::string x64_rotate_shift_reg(std::string operand_to_decide, std::string operand0, std::string operand1, std::string Mnem)
{
	std::string return_string;
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string neg_Mnem;
	if (Mnem == "<<")
		neg_Mnem = ">>";
	else if (Mnem == ">>")
		neg_Mnem = "<<";
	if (operand_size == "qword")//rx
		return_string = "(("+operand0+Mnem+operand1+")|("+operand0+neg_Mnem+operand1+"))";
	else if (operand_size == "dword")//ex
	{
			return_string = "(("+operand0+"&ffffffff" + Mnem + operand1 + ")|(" + operand0+"&ffffffff" + neg_Mnem + operand1+"))";
	}
	else if (operand_size == "word")//x
	{
		return_string = "(("+operand0 + "&ffffffffffff0000)|((" + operand0 + "&ffff" + Mnem + operand1 + ")|(" + operand0 + "&ffff" + neg_Mnem + operand1 + ")))";
	}
	else if (operand_size == "hbyte")//ah 
	{
		return_string = "(("+operand0 + "&ffffffffffff00ff)|((" + operand0 + "&ff00" + Mnem + operand1 + ")|(" + operand0 + "&ff00" + neg_Mnem + operand1 + ")))";
	}
	else if (operand_size == "lbyte")//al
	{
		return_string = "(("+operand0 + "&ffffffffffffff00)|((" + operand0 + "&ff" + Mnem + operand1 + ")|(" + operand0 + "&ff" + neg_Mnem + operand1 + ")))";
	}
	return return_string;
}

std::string x64_rotate_shift_disp(std::string instruction, std::string operand0, std::string operand1, std::string Mnem)
{
	std::string neg_Mnem,return_string;
	if (Mnem == "<<")
		neg_Mnem = ">>";
	else if (Mnem == ">>")
		neg_Mnem = "<<";
	std::string address="";
	if (operand0.find("=") != -1)
	{
		address = operand0.substr(0, operand0.find("=") - 1);
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.size() - 1 - operand0.find("="));
	}
	else if (operand0.find("=") == -1)
		address = operand0;
	if (instruction.find("qword") != -1)//rx
	{
		return_string = "(("+operand0 + Mnem + operand1 + ")|(" + operand0 + neg_Mnem + operand1+"))";
	}
	else if (instruction.find("dword") != -1)//ex
	{
		return_string = "(("+operand0 + "&ffffffff" + Mnem + operand1 + ")|(" + operand0 + "&ffffffff" + neg_Mnem + operand1+"))";
	}
	else if (instruction.find(" word") != -1)//x
	{
		return_string = "(("+operand0 + "&ffffffffffff0000)|((" + operand0 + "&ffff" + Mnem + operand1 + ")|(" + operand0 + "&ffff" + neg_Mnem + operand1 + ")))";
	}
	else if (instruction.find("byte") != -1)//al
	{
		return_string = "(("+operand0 + "&ffffffffffffff00)|((" + operand0 + "&ff" + Mnem + operand1 + ")|(" + operand0 + "&ff" + neg_Mnem + operand1 + ")))";
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		return_string = operand0 + Mnem + operand1 + "|" + operand0 + neg_Mnem + operand1;
	}
	return_string = address + "=" + return_string;
	return return_string;
}

std::string x64_arithmatic_result_basedon_size(std::string left,std::string right,std::string operand_size,std::string Mnem)
{
	if (operand_size == "xmmword")//xmm
	{
		left = "(" + left + Mnem + right + ")";
	}
	else if (operand_size == "qword")//rx
	{
		left = "(" + left + Mnem + right + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(right, 32))
			right = right;
		else
			right = "(" + right + "&ffffffff)";
		if (x64_is_within_size(left, 32))
			left = left;
		else
			left = "(" + left + "&ffffffff)";
		left = "(" + left + Mnem + right + ")";
	}
	else if (operand_size == "word")//x
	{

		if (x64_is_within_size(left, 16))
		{
			left = left;
			if (x64_is_within_size(left, 16))
				right = right;
			else
				right = "(" + right + "&ffff)";
			left = "(" + left + "&ffffffffffff0000|((" + left + Mnem + right + ")&ffff))";
		}
		else
		{
			left = "(" + left + "&ffff)";
			if (x64_is_within_size(right, 16))
				right = right;
			else
				right = "(" + right + "&ffff)";
			left = "(" + left + "&ffffffffffff0000|((" + left + Mnem + right + ")&ffff))";
		}

	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(left, 8))
		{
			left = left;
			if (x64_is_within_size(right, 8))
				right = right;
			else
				right = "(" + right + "&ff00)";
			left = "(" + left + "&ffffffffffff00ff|((" + left + Mnem + right + ")&ff00))";
		}
		else
		{
			left = "(" + left + "&ff00)";
			if (x64_is_within_size(right, 8))
				right = right;
			else
				right = "(" + right + "&ff00)";
			left = "(" + left + "&ffffffffffff00ff|((" + left + Mnem + right + ")&ff00))";
		}
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(left, 8))
		{
			left = left;
			if (x64_is_within_size(right, 8))
				right = right;
			else
				right = "(" + right + "&ff)";
			left = "(" + left + "&ffffffffffffff00|((" + left + Mnem + right + ")&ff))";
		}
		else
		{
			left = "(" + left + "&ff)";
			if (x64_is_within_size(right, 8))
				right = right;
			else
				right = "(" + right + "&ff)";
			left = "(" + left + "&ffffffffffffff00|((" + left + Mnem + right + ")&ff))";
		}
	}
	return left;
}

//handle punpck instructions. For different operand_to_decide(64-bit ot 128 bit), output different value.
std::string x64_punpck(std::string operand_to_decide, std::string defined_value, std::string defined_value1,std::string Mnem)
{
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string result;
	if (operand_size == "qword")//rx
	{
		if (Mnem == "punpcklbw")
		{
			result = defined_value + "&ff|(" + defined_value1 + "&ff)<<8|(" + defined_value + "&ff00)<<8|(" + \
				defined_value1 + "&ff00)<<16|(" + defined_value + "&ff0000)<<16|(" + defined_value1 + "&ff0000)<<24|("\
				+ defined_value + "&ff000000)<<24|(" + defined_value1 + "&ff000000)<<32";
		}
		else if (Mnem == "punpcklwd")
		{
			result = defined_value + "&ffff|(" + defined_value1 + "&ffff)<<16|(" + defined_value + "&ffff0000)<16|(" + \
				defined_value1 + "&ffff0000)<<32";
		}
		else if (Mnem == "punpckldq")
		{
			result = defined_value + "&ffffffff|(" + defined_value1 + "&ffffffff)<<32";
		}
		else if (Mnem == "punpckhbw")
		{
			result = defined_value + "&ff00000000|(" + defined_value1 + "&ff00000000)<<8|(" + defined_value + "&ff0000000000)<<8|(" + \
				defined_value1 + "&ff0000000000)<<16|(" + defined_value + "&ff000000000000)<<16|(" + defined_value1 + "&ff000000000000)<<24|("\
				+ defined_value + "&ff00000000000000)<<24|(" + defined_value1 + "&ff00000000000000)<<32";
		}
		else if (Mnem=="punpckhwd")
		{
			result = defined_value + "&ffff00000000|(" + defined_value1 + "&ffff00000000)<<16|(" + defined_value + "&ffff000000000000)<16|(" + \
				defined_value1 + "&ffff000000000000)<<32";
		}
		else if (Mnem == "punpckhdq")
		{
			result = defined_value + "&ffffffff00000000|(" + defined_value1 + "&ffffffff00000000)<<32";
		}
	}
	else if (operand_size == "xmmword")//xmm
	{
		if (Mnem == "punpcklbw")
		{
			result = defined_value + "&ff|(" + defined_value1 + "&ff)<<8|(" + defined_value + "&ff00)<<8|(" + \
				defined_value1 + "&ff00)<<16|(" + defined_value + "&ff0000)<<16|(" + defined_value1 + "&ff0000)<<24|("\
				+ defined_value + "&ff000000)<<24|(" + defined_value1 + "&ff000000)<<32|(" + defined_value + \
				"&ff00000000)<<32|(" + defined_value1 + "&ff00000000)<<40|(" + defined_value + "&ff0000000000)<<40|("\
				+ defined_value1 + "&ff0000000000)<<48|(" + defined_value + "&ff000000000000)<<48|(" + defined_value1\
				+ "&ff000000000000)<<56|(" + defined_value + "&ff00000000000000)<<56|(" + defined_value1 +
				"&ff00000000000000)<<64";
		}
		else if (Mnem == "punpcklwd")
		{
			result = defined_value + "&ffff|(" + defined_value1 + "&ffff)<<16|(" + defined_value + "&ffff0000)<16|(" + \
				defined_value1 + "&ffff0000)<<32|("+defined_value+"&ffff00000000)<<32|("+defined_value1+\
				"&ffff00000000)<<48|("+defined_value+"&ffff000000000000)<<48|("+defined_value1+\
				"&ffff000000000000)<<64";
		}
		else if (Mnem == "punpckldq")
		{
			result = defined_value + "&ffffffff|(" + defined_value1 + "&ffffffff)<<32|("+defined_value+
				"&ffffffff00000000)<<32|("+defined_value1+"&ffffffff00000000)<<64";
		}
		else if (Mnem == "punpcklqdq")
		{
			result = defined_value + "&ffffffffffffffff|(" + defined_value1 + "&ffffffffffffffff)<<64";
		}
		else if (Mnem == "punpckhbw")
		{
			result = defined_value + "&ff0000000000000000|(" + defined_value1 + "&ff0000000000000000)<<8|(" + defined_value + "&ff000000000000000000)<<8|(" + \
				defined_value1 + "&ff000000000000000000)<<16|(" + defined_value + "&ff00000000000000000000)<<16|(" + defined_value1 + "&ff00000000000000000000)<<24|("\
				+ defined_value + "&ff000000)<<24|(" + defined_value1 + "&ff000000)<<32|(" + defined_value + \
				"&ff000000000000000000000000)<<32|(" + defined_value1 + "&ff000000000000000000000000)<<40|(" + defined_value + "&ff00000000000000000000000000)<<40|("\
				+ defined_value1 + "&ff00000000000000000000000000)<<48|(" + defined_value + "&ff0000000000000000000000000000)<<48|(" + defined_value1\
				+ "&ff0000000000000000000000000000)<<56|(" + defined_value + "&ff000000000000000000000000000000)<<56|(" + defined_value1 +
				"&ff000000000000000000000000000000)<<64";
		}
		else if (Mnem == "punpckhwd")
		{
			result = defined_value + "&ffff0000000000000000|(" + defined_value1 + "&ffff0000000000000000)<<16|(" + defined_value + "&ffff00000000000000000000)<16|(" + \
				defined_value1 + "&ffff00000000000000000000)<<32|(" + defined_value + "&ffff000000000000000000000000)<<32|(" + defined_value1 + \
				"&ffff000000000000000000000000)<<48|(" + defined_value + "&ffff0000000000000000000000000000)<<48|(" + defined_value1 + \
				"&ffff0000000000000000000000000000)<<64";
		}
		else if (Mnem == "punpckhdq")
		{
			result = defined_value + "&ffffffff0000000000000000|(" + defined_value1 + "&ffffffff0000000000000000)<<32|(" + defined_value +
				"&ffffffff000000000000000000000000)<<32|(" + defined_value1 + "&ffffffff000000000000000000000000)<<64";
		}
		else if (Mnem == "punpckhqdq")
		{
			result = defined_value + "&ffffffffffffffff0000000000000000|(" + defined_value1 + "&ffffffffffffffff0000000000000000)<<64";
		}
	}
	return result;
}

void x64_convert_operand2offset_type(ea_t ea)
{
	bool success;
	int op0_type=-1, op1_type=-1, op2_type=-1;
	int ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
	{
		op0_type = get_optype(ea, 0);
	}
	else if (ea_operand_num == 2)
	{
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);

	}
	else if (ea_operand_num == 3)
	{
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		op2_type = get_optype(ea, 2);
	}

	if (op0_type == 3 || op0_type == 4)
	{
		success = set_op_type(ea, num_flag(), 0);
		if (op1_type == 5)
			success = set_op_type(ea, num_flag(), 1);
	}
	else if (op1_type == 3 || op1_type == 4)
		success = set_op_type(ea, num_flag(), 1);
	else if (op2_type == 3 || op2_type == 4)
		success = set_op_type(ea, num_flag(), 2);
	else if(op1_type == 5)
		success = set_op_type(ea, num_flag(), 1);
}

std::string x64_get_root(std::string Mnem)
{
	std::vector<std::string> root = { "cmov","movsx","movs","mov","xor","add","sub","imul","mul","idiv","divsd","rol","ror","shl","sal","and","or","punpck","set","sbb","adc" };
	for (int i = 0;i < root.size();i++)
	{
		if (Mnem.find(root[i]) != -1)
			return root[i];
	}
	return Mnem;
}

//The operand0 can exist if the instruction is stos ax. Operand0 can also non-exist if the instruction is stosb.
void x64_stos(ea_t ea,std::string operand0,func_t * func)
{
	qstring Mnemq;
	std::string Mnem,defined_value1,defined_value;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string operand_size;
	if (x64_is_register(operand0))//if contains register in this instruction
	{
		operand_size = which_operand_size(operand0);
	}
	else if (Mnem == "stosb")
		operand_size = "lbyte";
	else if (Mnem == "stosw")
		operand_size = "word";
	else if (Mnem == "stosd")
		operand_size = "dword";
	else if (Mnem == "stosq")
		operand_size = "xmmword";
	if (operand_size == "lbyte")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1 + "&ff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	else if (operand_size == "word")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1 + "&ffff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	else if (operand_size == "dword")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1 + "&ffffffff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	else if (operand_size == "xmmword")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1;
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_s = disasm.c_str();
	std::string address;
	std::string content;
	if (disasm_s.find("rep")!=-1)// if contains rep
	{
		address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
		content= x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=')+1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size()-1-\
			x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "ITER(" + address + ")=" + content;
	}
}


//The operand0 can exist if the instruction is stos ax. Operand0 can also non-exist if the instruction is stosb.
void x64_scas(ea_t ea, std::string operand0, func_t* func)
{
	qstring Mnemq;
	std::string Mnem, defined_value1, defined_value;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string operand_size;
	if (x64_is_register(operand0))//contains register in this instruction
	{
		operand_size = which_operand_size(operand0);
	}
	else if (Mnem == "scasb")
		operand_size = "lbyte";
	else if (Mnem == "scasw")
		operand_size = "word";
	else if (Mnem == "scasd")
		operand_size = "dword";
	else if (Mnem == "scasq")
		operand_size = "xmmword";
	if (operand_size == "lbyte")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1 + "&ff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	else if (operand_size == "word")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1 + "&ffff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	else if (operand_size == "dword")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1 + "&ffffffff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	else if (operand_size == "xmmword")
	{
		defined_value1 = x64_lookForDefine("rax", ea, func);
		defined_value1 = defined_value1;
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_s = disasm.c_str();
	std::string address;
	std::string content;
	if (disasm_s.find("rep") != -1)// if contains rep
	{
		address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('['), x64_my_insn[ea2x64_my_insn[ea]].operand0.find("cmp")\
		- x64_my_insn[ea2x64_my_insn[ea]].operand0.find('['));
		content = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find("cmp") + 4, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - \
			x64_my_insn[ea2x64_my_insn[ea]].operand0.find("cmp")-4);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(ITER(" + address + ") cmp " + content+")";
	}
}

std::string x64_rectify_specific_Mnem(std::string Mnem, std::string keyword,ea_t ea, int op1_type)
{
	if (Mnem.find("mul") != -1 && x64_count_comma_ea(ea) == 0 && op1_type == 1)
		keyword = "mul reg";
	else if (Mnem.find("mul") != -1 && x64_count_comma_ea(ea) == 0 && (op1_type == 3 || op1_type == 4))
		keyword = "mul []";
	else if (Mnem.find("mul") != -1 && x64_count_comma_ea(ea) == 0 && (op1_type == 2))
		keyword = "mul label";
	//No need to rectify div since all div instruction only be like: div operand (one operand).
	else if (Mnem.find("scas") != -1)
		keyword = "scas";
	else if (Mnem.find("stos") != -1)
		keyword = "stos";
	else if (Mnem.find("movsx") != -1)
		keyword = "mov" + keyword.substr(keyword.find("movsx")+5, keyword.size()-1- keyword.find("movsx")-4);
	else if (Mnem.find("movs")==0)//In case Mnem is cmovs
	{
		qstring disasm;
		generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
		std::string string1 = disasm.c_str();
		if (Mnem == "movs")
			keyword = "movs";
		else if ((Mnem == "movsb" || Mnem == "movsw" || Mnem == "movsd"|| Mnem == "movsq") && string1.find(',') == -1)//move string to string instruction
			keyword = "movs";
		else if (string1.find(',') != -1)//move value string like movsd xmm1, xmm2
			keyword = "mov " + keyword.substr(keyword.find(' ') + 1, keyword.size() - 1 - keyword.find(' '));
	}
	return keyword;
}

void x64_movs(ea_t ea, func_t* func, std::string operand0, std::string operand1)
{
	qstring Mnemq;
	std::string Mnem, defined_value1, defined_value;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string operand_size;
	if (x64_is_register(operand0))//contains register in this instruction
	{
		operand_size = which_operand_size(operand0);
	}
	else if (Mnem == "movsb")
		operand_size = "lbyte";
	else if (Mnem == "movsw")
		operand_size = "word";
	else if (Mnem == "movsd")
		operand_size = "dword";
	else if (Mnem == "movsq")
		operand_size = "xmmword";
	if (operand_size == "lbyte")
	{
		defined_value1 = x64_lookForDefine("rsi", ea, func);
		defined_value1 = defined_value1 + "&ff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	else if (operand_size == "word")
	{
		defined_value1 = x64_lookForDefine("rsi", ea, func);
		defined_value1 = defined_value1 + "&ffff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	else if (operand_size == "dword")
	{
		defined_value1 = x64_lookForDefine("rsi", ea, func);
		defined_value1 = defined_value1 + "&ffffffff";
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	else if (operand_size == "xmmword")
	{
		defined_value1 = x64_lookForDefine("rsi", ea, func);
		defined_value1 = defined_value1;
		defined_value = x64_lookForDefine("rdi", ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_s = disasm.c_str();
	std::string address;
	std::string content;
	if (disasm_s.find("rep") != -1)// if contains rep
	{
		address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
		content = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') + 1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - \
			x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "ITER(" + address + ")=" + content;
	}
}


std::string x64_movd(std::string operand0, std::string defined_value, std::string defined_value1)
{
	std::string operand_size = which_operand_size(operand0);
	if (operand_size == "xmmword")//If destination is xmm, zero extend 
		defined_value = defined_value1;
	else if (x64_is_within_size(defined_value1, 32) == true)
		defined_value = "((" + defined_value + "&ffffffff00000000)|(" + defined_value1 + "))";
	else
		defined_value = "((" + defined_value + "&ffffffff00000000)|(" + defined_value1 + "&0xffffffff))";
	return defined_value;
}

std::string x64_movq(std::string operand0, std::string operand1, std::string defined_value, std::string defined_value1)
{
	std::string operand_size0 = which_operand_size(operand0);
	std::string operand_size1 = which_operand_size(operand1);
	if (operand_size0 == "xmmword" && operand_size1 == "xmmword")// movq xmm, xmm
		defined_value = "((" + defined_value + "&ffffffffffffffff0000000000000000)|(" + defined_value1 + "&0xffffffffffffffff))";
	else if (operand_size0 == "xmmword" && operand_size1 == "notreg")//movq xmm, []
		defined_value = "(" + defined_value1 + " & 0xffffffffffffffff)";
	else
		defined_value = defined_value1;
	return defined_value;
}
