#include "../../Headers/value_calculate/ARM_my_library_operator.h"
int ARM_count_comma(std::string disasm)
{
	int i, comma_count = 0;
	for (i = 0;i < disasm.length();i++)
	{
		if (disasm[i] == ',' && ARM_comma_not_in_offset(disasm, i))
			comma_count++;
	}
	return comma_count;
}

std::string ARM_get_operand(ea_t ea, int index)
{
	if (ea == 0xd9f00)
		int breakp = 1;
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	const char* disasm_string = disasm.c_str();
	std::string string1 = disasm_string;
	if (string1.find(' ') == -1)
		return string1;

	string1 = trim_begin_end_space(string1);
	string1 = string1.substr(string1.find(' '), string1.size() - string1.find(' '));
	string1 = remove_comment(string1);
	int comma_count = ARM_count_comma(string1);

	if (comma_count > 0 && index == 1)
	{
		if (comma_count == 1)
		{
			string1 = string1.substr(ARM_first_real_comma(string1) + 1, string1.size() - ARM_first_real_comma(string1));
			//string1 = remove_comment(string1);
			string1 = trim_begin_end_space(string1);
			return string1;
		}
		else if (comma_count >= 2)
		{
			string1 = string1.substr(ARM_first_real_comma(string1) + 1, string1.size() - ARM_first_real_comma(string1));
			string1 = string1.substr(0, ARM_first_real_comma(string1));
			string1 = groom_string(string1);
			return string1;
		}
	}
	else if (index == 0) {


		if (comma_count > 0)
		{

			string1 = string1.substr(0, ARM_first_real_comma(string1));
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
		if (comma_count == 2)
		{
			string1 = string1.substr(ARM_last_real_comma(string1) + 1, string1.size() - ARM_last_real_comma(string1));
			//string1 = remove_comment(string1);
			string1 = trim_begin_end_space(string1);
			return string1;
		}
		else if (comma_count > 2)
		{
			string1 = string1.substr(ARM_first_real_comma(string1) + 1, string1.size() - ARM_first_real_comma(string1));
			string1 = string1.substr(ARM_first_real_comma(string1) + 1, string1.size() - ARM_first_real_comma(string1));
			string1= string1.substr(0,ARM_first_real_comma(string1));
			string1 = groom_string(string1);
			return string1;
		}
	}

	else if (comma_count > 0 && index == 3)
	{
		if (comma_count == 3)
		{
			string1 = string1.substr(ARM_last_real_comma(string1) + 1, string1.size() - ARM_last_real_comma(string1));
			string1 = groom_string(string1);
			return string1;
		}
	}
	return "";
}


int ARM_first_real_comma(std::string string1)
{
	int i;
	for (i = 0;i < string1.size();i++)
	{
		if (string1[i] == ',' && ARM_comma_not_in_offset(string1, i))
			return i;
	}
}

int ARM_last_real_comma(std::string string1)
{
	int i;
	for (i = string1.size() - 1;i >= 0;i--)
	{
		if (string1[i] == ',' && ARM_comma_not_in_offset(string1, i))
			return i;
	}
}

//Returns true if ',' not in [], other wise, return false.
bool ARM_comma_not_in_offset(std::string disasm, int i)
{
	if (disasm[i - 1] == ']') 
		return false;
	std::string r_substring = disasm.substr(i+1, disasm.size() - 1 - i);
	std::string l_substring = disasm.substr(0, i - 1);
	if (l_substring.find('[') != -1 && r_substring.find(']') != -1)
		return false;
	else if (l_substring.find('{') != -1 && r_substring.find('}') != -1)
		return false;
	int next_comma_index = r_substring.find(',');
	if (next_comma_index != -1)
	{
		r_substring = r_substring.substr(0, next_comma_index + 1);
	}

	if (r_substring.find("ASR") == 0)
		return false;
	else if (r_substring.find("LSL") == 0)
		return false;
	else if (r_substring.find("LSR") == 0)
		return false;
	else if (r_substring.find("ROR") == 0)
		return false;
	else if (r_substring.find("RRX") == 0)
		return false;
	return true;
}

std::string ARM_contain_equal_register(std::string reg1, std::string reg2)
{
	size_t pos = reg1.find(reg2, 0);
	while (pos != std::string::npos)
	{
		if (!isdigit(reg1[pos + reg2.length()]))
			return reg2;

	}
	return "";
}


//If operand is use case, return 1. If operand is define case, return 0.
int ARM_is_use_stmt(qstring Mnem, ea_t ea, int which_op)
{
	if (which_op == 1)
		return 1;
	else if (which_op == 0 && (Mnem.find("BL")!=-1 || Mnem.find( "TST" )!=-1|| Mnem.find( "CMP")!=-1))
		return 1;
	else if (which_op == 0 && Mnem == "POP" || Mnem == "PUSH" || Mnem=="STR")
	{
	//	int op0_type = get_optype(ea, 0);
		//if (op0_type == 3 || op0_type == 4)
			return 1;
	}
	return 0;
}