#include "../../Headers/value_calculate/x64_mylibrary_register.h"
std::string registers[32][5] = {
{ "rax", "eax", "ax","ah", "al" },
{ "rbx", "ebx", "bx","bh", "bl" },
{ "rcx", "ecx", "cx","ch", "cl" },
{ "rdx", "edx", "dx","dh", "dl" },
{ "rsi", "esi", "si","", "sil" },
{ "rdi", "edi", "di","", "dil" },
{ "rbp", "ebp", "bp","", "bpl" },
{ "rsp", "esp", "sp","", "spl" },
{ "r8", "r8d", "r8w","", "r8b" },
{ "r9", "r9d", "r9w","", "r9b" },
{ "r10", "r10d", "r10w","", "r10b" },
{ "r11", "r11d", "r11w","", "r11b" },
{ "r12", "r12d", "r12w","", "r12b" },
{ "r13", "r13d", "r13w","", "r13b" },
{ "r14", "r14d", "r14w","", "r14b" },
{ "r15", "r15d", "r15w","", "r15b" },
{"xmm0","","","",""},
{"xmm1","","","",""},
{"xmm2","","","",""},
{"xmm3","","","",""},
{"xmm4","","","",""},
{"xmm5","","","",""},
{"xmm6","","","",""},
{"xmm7","","","",""},
{"xmm8","","","",""},
{"xmm9","","","",""},
{"xmm10","","","",""},
{"xmm11","","","",""},
{"xmm12","","","",""},
{"xmm13","","","",""},
{"xmm14","","","",""},
{"xmm15","","","",""}
};
int register_dimention1 = 32;
int register_dimentsion2 = 5;


int x64_is_equal_register(std::string reg1, std::string reg2)
{
	if (reg1 == "" || reg2 == "")
		return 0;
	int i, j, k;
	for (i = 0;i < register_dimention1;i++)
	{
		for (j = 0;j < register_dimentsion2;j++)
		{
			if (reg1 == registers[i][j])
			{
				for (k = 0;k < register_dimentsion2;k++)
				{
					if (reg2 == registers[i][k])
						return 1;
				}
				return 0;
			}
			
		}
	}
	return 0;
}

std::vector<std::string> x64_get_equivalent_registers(std::string reg)
{
	int i, j, z;
	std::vector<std::string> return_string_array;

	for (i = 0;i < register_dimention1;i++)
	{
		for (j = 0;j < register_dimentsion2;j++)
		{
			if (registers[i][j] == reg)
			{
				for (z = 0;z < register_dimentsion2;z++)
				{
					return_string_array.push_back(registers[i][z]);
				}
				return return_string_array;
			}

		}
	}
	return_string_array.push_back(reg);
	return_string_array.push_back("");
	return_string_array.push_back("");
	return_string_array.push_back("");
	return_string_array.push_back("");
	return return_string_array;
}

std::string x64_contain_equal_register(std::string reg1, std::string reg2)
{
	int i;
	std::vector<std::string> equivalent_regs;
	equivalent_regs = x64_get_equivalent_registers(reg2);
	if (reg1 == "") return "";
	for (i = 0;i < register_dimentsion2;i++)
	{
		//if (reg1.find(equivalent_regs[i]) != -1)
		if(x64_contain_register(reg1, equivalent_regs[i]))
			return equivalent_regs[i];
	}
	return "";
}

//Check whether the long string contains register reg. Should be noted that xmm12 contains xmm1 but it is not a hit.
bool x64_contain_register(std::string long_string, std::string reg)
{
	//Firstly find all occurance of substring reg in long string.
	std::vector<size_t> positions;
	size_t pos = long_string.find(reg, 0);
	while (pos != std::string::npos)
	{
		positions.push_back(pos);
		pos = long_string.find(reg, pos + 1);
	}
	//Next for each occurance we check whether it is like R12 contains R1 or like  mov .., cs:bb_common_siz1.c_cc contains si
	for (int item = 0;item < positions.size();item++)
	{
		if (isdigit(long_string[positions[item] + reg.size()]))//If the occurance is like R12 contains R1.
			continue;
		else if (isalpha(long_string[positions[item] + reg.size()]) || isalpha(long_string[positions[item] - 1]))//If the occurance is like si in the middle of mov .., cs:bb_common_siz1.c_cc
			continue;
		else
			return true;
	}
	return false;
}

std::string which_operand_size(std::string operand)
{
	if (operand.find("xmm") != -1)
		return "xmmword";
	else if (operand == "rax" || operand == "rbx" || operand == "rcx" || operand == "rdx" || operand == "rsi" || operand == "rdi"\
		|| operand == "rbp" || operand == "rsp" || operand == "r8" || operand == "r9" || operand == "r10"\
		|| operand == "r11" || operand == "r12" || operand == "r13" || operand == "r14" || operand == "r15")
		return "qword";
	else if (operand == "eax" || operand == "ebx" || operand == "ecx" || operand == "edx" || operand == "esi" || operand == "edi"\
		|| operand == "ebp" || operand == "esp" || operand == "r8d" || operand == "r9d" || operand == "r10d"\
		|| operand == "r11d" || operand == "r12d" || operand == "r13d" || operand == "r14d" || operand == "r15d")
		return "dword";
	else if (operand == "ax" || operand == "bx" || operand == "cx" || operand == "dx" || operand == "si" || operand == "di"\
		|| operand == "bp" || operand == "sp" || operand == "r8w" || operand == "r9w" || operand == "r10w"\
		|| operand == "r11w" || operand == "r12w" || operand == "r13w" || operand == "r14w" || operand == "r15w")
		return "word";
	else if (operand == "ah" || operand == "bh" || operand == "ch" || operand == "dh")
		return "hbyte";
	else if (operand == "al" || operand == "bl" || operand == "cl" || operand == "dl" || operand == "sil" || operand == "dil"\
		|| operand == "bpl" || operand == "spl" || operand == "r8b" || operand == "r9b" || operand == "r10b"\
		|| operand == "r11b" || operand == "r12b" || operand == "r13b" || operand == "r14b" || operand == "r15b")
		return "lbyte";
	return "notreg";
}

std::string which_operand_size(ea_t ea)
{
	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	if (disasms.find("qword") != -1)//rx
	{
		return "qword";
	}
	else if (disasms.find("dword") != -1)//ex
	{
		return "dword";
	}
	else if (disasms.find("word") != -1)//x
	{
		return "word";
	}
	else if (disasms.find("byte") != -1)//al
	{
		return "lbyte";
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		return "qword";
	}
}

bool  has_this_register(std::vector<std::string> expression_list,std::string reg)
{

	for (int i = 0;i < expression_list.size();i++)
	{
		if (reg == expression_list[i])
			return true;
	}
	return false;
}

bool x64_is_register(std::string string)
{
	for (int row=0;row< register_dimention1;row++)
		for (int column = 0;column < register_dimentsion2;column++)
		{
			if (registers[row][column] == string && string != "")
				return true;
		}
	return false;
}


void x64_unname_all_regs(func_t* func)
{
	int result1=del_regvar(func, func->start_ea , func->end_ea, "rax");
	int result2 = del_regvar(func, func->start_ea, func->end_ea, "rbx");
	int result3 = del_regvar(func, func->start_ea, func->end_ea, "rcx");
	int result4 = del_regvar(func, func->start_ea, func->end_ea, "rdx");
	int result5 = del_regvar(func, func->start_ea, func->end_ea, "rsi");
	int result6 = del_regvar(func, func->start_ea, func->end_ea, "rdi");
	int result7 = del_regvar(func, func->start_ea, func->end_ea, "rsp");
	int result8 = del_regvar(func, func->start_ea, func->end_ea, "rbp");
	int result9 = del_regvar(func, func->start_ea, func->end_ea, "r8");
	int result10 = del_regvar(func, func->start_ea, func->end_ea, "r9");
	int result11 = del_regvar(func, func->start_ea, func->end_ea, "r10");
	int result12 = del_regvar(func, func->start_ea, func->end_ea, "r11");
	int result13 = del_regvar(func, func->start_ea, func->end_ea, "r12");
	int result14 = del_regvar(func, func->start_ea, func->end_ea, "r13");
	int result15 = del_regvar(func, func->start_ea, func->end_ea, "r14");
	int result16 = del_regvar(func, func->start_ea, func->end_ea, "r15");
	int result17 = del_regvar(func, func->start_ea, func->end_ea, "xmm0");
	int result18 = del_regvar(func, func->start_ea, func->end_ea, "xmm1");
	int result19 = del_regvar(func, func->start_ea, func->end_ea, "xmm2");
	int result20 = del_regvar(func, func->start_ea, func->end_ea, "xmm3");
	int result21 = del_regvar(func, func->start_ea, func->end_ea, "xmm4");
	int result22 = del_regvar(func, func->start_ea, func->end_ea, "xmm5");
	int result23 = del_regvar(func, func->start_ea, func->end_ea, "xmm6");
	int result24 = del_regvar(func, func->start_ea, func->end_ea, "xmm7");
	int result25 = del_regvar(func, func->start_ea, func->end_ea, "xmm8");
	int result26 = del_regvar(func, func->start_ea, func->end_ea, "xmm9");
	int result27 = del_regvar(func, func->start_ea, func->end_ea, "xmm10");
	int result28 = del_regvar(func, func->start_ea, func->end_ea, "xmm11");
	int result29 = del_regvar(func, func->start_ea, func->end_ea, "xmm12");
	int result30 = del_regvar(func, func->start_ea, func->end_ea, "xmm13");
	int result31 = del_regvar(func, func->start_ea, func->end_ea, "xmm14");
	int result32 = del_regvar(func, func->start_ea, func->end_ea, "xmm15");
}

