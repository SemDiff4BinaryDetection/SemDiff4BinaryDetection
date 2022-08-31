#include "../../Headers/value_calculate/x64_mylibrary_operator.h"


std::string x64_get_operand(ea_t ea, int index)
{
	if (ea == 0x158d||ea==0x146e)
		int motherf = 1;
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	const char* disasm_string = disasm.c_str();
	std::string string1 = disasm_string;
	if (string1.find(' ') == -1)
		return string1;
	string1 = remove_comment(string1);
	string1 = trim_begin_end_space(string1);
	if (string1.find(' ') == -1)//if only operator is present but no operand
		return "";
	string1 = string1.substr(string1.find(' '), string1.size() - string1.find(' '));
	int comma_count = x64_count_comma(string1);
	
		if (comma_count > 0 && index == 1)
		{
			if (comma_count == 1)
			{
				string1 = string1.substr(string1.find(',') + 1, string1.size() - string1.find(','));
				string1 = groom_string(string1);
				return string1;
			}
			else if (comma_count == 2)
			{
				string1 = string1.substr(string1.find(',') + 1, string1.size() - string1.find(','));
				string1 = string1.substr(0, string1.rfind(','));
				string1 = groom_string(string1);
				return string1;
			}
		}
		else if (index == 0) {


			if (comma_count > 0)
			{

				string1 = string1.substr(0, string1.find(','));
				string1 = groom_string(string1);
				return string1;
			}
			else if (comma_count == 0)
			{
				string1 = groom_string(string1);
				return string1;
			}

		}
		else if (comma_count > 0 && index == 2)
		{
			string1 = string1.substr(string1.find(',') + 1, string1.size() - string1.find(','));
			string1 = string1.substr(string1.find(',') + 1, string1.size() - string1.find(','));
			string1 = groom_string(string1);
			return string1;
		}
	return "";
}



int x64_count_comma(std::string disasm)
{
	int i,comma_count=0;
	for (i = 0;i < disasm.length();i++)
	{
		if (disasm[i] == ',')
			comma_count++;
	}
	return comma_count;
}






int x64_count_comma_ea(ea_t ea)
{
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	const char* disasm_string = disasm.c_str();
	std::string string1 = disasm_string;
	int comma = x64_count_comma(string1);
	return comma;
}

//If this operand is used here, return 1. Else if this operand is defined here, return 0.
int x64_is_use_stmt(qstring Mnem, ea_t ea, int which_op)
{
	if (which_op == 1)
		return 1;
	else if (which_op == 0 && Mnem == "call")
		return 1;
	else if (Mnem == "test" || Mnem == "cmp")
		return 1;
	else if (which_op==0 && (Mnem == "pop" || Mnem == "push"))
	{
		//int op0_type = get_optype(ea, 0);
		//if (op0_type == 3 || op0_type == 4)
			return 1;
	}
	return 0;
}

bool has_single_operand(ea_t ea)
{
	int ea_operand_num = x64_count_comma_ea(ea)+1;//Because some mul instruction might only has one operand in assmebly but their insn.op might has more than one operand, we count the amount of comma.
	if (ea_operand_num == 1)
		return true;
	else
		return false;
}