#include "../../Headers/value_calculate/common_library.h"
//std::vector <ea_t> iter_source;
std::map <ea_t, ea_t> insn_last_insn;
int variable_number=4;//We reserve 0-4 for 1st-4th parameters for the function
std::map <ea_t, int> recalculated_yet_map;
std::map <std::string, std::string> conditional_jump_map;
std::vector<std::string> uncalculatable_function_names;
std::string file_type;

int count_ea_operands(ea_t ea)
{
	if (ea == 0x40252d)
		int i = 1;
	insn_t insn;
	if (decode_insn(&insn, ea) < 1)
		return -1;
	if (insn.ops[0].type != 0 && insn.ops[1].type == 0)//only one operand
		return 1;
	else if (insn.ops[0].type != 0 && insn.ops[1].type != 0 && insn.ops[2].type == 0)//two operands
		return 2;
	else if (insn.ops[0].type != 0 && insn.ops[1].type != 0 && insn.ops[2].type != 0 && insn.ops[3].type == 0)//three operands
		return 3;
	else if (insn.ops[0].type != 0 && insn.ops[1].type != 0 && insn.ops[2].type != 0 && insn.ops[3].type != 0 && insn.ops[4].type == 0)//four operands
		return 4;
}

std::string trim_begin_end_space(std::string string1)
{
	size_t first, last;
	first = string1.find_first_not_of(' ');
	last = string1.find_last_not_of(' ');
	string1 = string1.substr(first, last - first + 1);
	return string1;
}

std::string remove_comment(std::string string1) {
	size_t comment = string1.find(';');
	if (comment != -1)
		string1 = string1.substr(0, comment);
	return string1;
}

//remove "ptr word" in "ptr word [eax+5]"
std::string remove_adjective(std::string string1) {
	if ((string1.find("ds:") != -1|| string1.find("gs:") != -1) && string1.find("[") != -1)//remove all the other words before []
	{
		string1 = string1.substr(string1.find('['), string1.size() - string1.find('['));
		return string1;
	}
	else {
		size_t last_space = string1.rfind(' ');
		if (last_space != -1)
			string1 = string1.substr(last_space + 1, string1.length() - 1 - last_space);
		return string1;
	}
}

std::string groom_string(std::string string1)
{
	string1 = remove_comment(string1);
	string1 = trim_begin_end_space(string1);
	string1 = remove_adjective(string1);
	return string1;
}

int get_optype(ea_t ea, int index) {
	insn_t insn;
	if (decode_insn(&insn, ea) < 1)
		return -1;
	return insn.ops[index].type;
}

//Get the operand register regardless of register rename.
/*std::string get_reg_name(ea_t ea, int index)
{
	insn_t insn;
	if (decode_insn(&insn, ea) < 1)
		return "get_reg_name err";
	switch (insn.ops[index].n)
	{
	case 0:
		return "rax";
	case 1:
		return "rcx";
	case 2:
		return "rdx";
	case 3:
		return "rbx";
	case 4:
		return "rsp";
	case 5:
		return "rbp";
	case 6:
		return "rsi";
	case 7:
		return "rdi";
	case 8:
		return "r8";
	case 9:
		return "r9";
	case 10:
		return "r10";
	case 11:
		return "r11";
	case 12:
		return "r12";
	case 13:
		return "r13";
	case 14:
		return "r14";
	case 15:
		return "r15";

	}


}
*/
void initialize_global_variable() {
	variable_number = 4;
}


std::string arm_allocate_new_variable(std::string operand) {
	if (operand == "R0")
		return "VAR0";
	else if (operand == "R1")
		return "VAR1";
	else if (operand == "R2")
		return "VAR2";
	else if (operand == "R3")
		return "VAR3";
	else if (operand == "SP")
		return "VAR4";
	else if (operand == "R4" || operand == "R5" || operand == "R6" || operand == "R7"\
		|| operand == "R8" || operand == "R9" || operand == "R10"\
		|| operand == "R11" || operand == "R12" || operand == "LR" || operand == "PC")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number);
	}
	else//If the operand is strange string, not a register, we deem it as a normal register.
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number);
	}
}
bool is_in_loop(ea_t ea, ea_t next_ea, func_t* func) {
	ea_t index = insn_last_insn[ea];
	for (;index > func->start_ea && insn_last_insn.find(index)!= insn_last_insn.end();index = insn_last_insn[index])
	{
		if (next_ea == index)
			return true;
	}
	return false;
}

std::string dec2hex(int i)
{
	std::stringstream ioss;
	std::string s_temp;
	ioss << std::setiosflags(std::ios::uppercase) << std::hex << i;
	ioss >> s_temp;
	return s_temp;
}

std::string lldec2hex(long long int i)
{
	std::stringstream ioss;
	std::string s_temp;
	ioss << std::setiosflags(std::ios::uppercase) << std::hex << i;
	ioss >> s_temp;
	return s_temp;
}

std::string ldec2hex(long int i)
{
	std::stringstream ioss;
	std::string s_temp;
	ioss << std::setiosflags(std::ios::uppercase) << std::hex << i;
	ioss >> s_temp;
	return s_temp;
}



bool not_resolvable(std::string to_resolve) {
	if (to_resolve.find("VAR") != -1)
		return true;
	else if (regex_match(to_resolve, std::regex("[0-9ABCDEF]+h")))
		return true;
	else if (regex_match(to_resolve, std::regex("[0-9ABCDEF]+")))
		return true;
	else if (to_resolve.find("arg_") != -1)
		return true;
	else if (to_resolve.find("var_") != -1)
		return true;
	else if (to_resolve == "UNKNONWN")
		return true;
	else if (to_resolve.find("RETURN") != -1)
		return true;
	else if (to_resolve.find("ITERATOR") != -1)
		return true;
	else return false;
}

//Get next element in the expression. If has non-Mnem elements after this index i , should return that elements' index, other wise index should point to the end of the string.
//Parameter 1: expression.
//Parameter 2: starting index of next element
std::string get_next_element(std::string operand, int* index) {
	int i, start_index = (*index);
	std::string resolvable;
	for (i = (*index);i < operand.length();i++) {//i should be the next Mnem index
		if (operand[i] == '+' || operand[i] == '-' || operand[i] == '*' || operand[i] == '/')
			break;
		else if (operand[i] == '[')
		{
			start_index = i + 1;
			continue;
		}
		else if (operand[i] == '(' || operand[i] == ')' || operand[i] == '=')
			break;
		else if (operand[i] == ']')
			break;
	}
	resolvable = operand.substr(start_index, i - start_index);
	//Index i now should be the Mnem index.If has non-Mnem elements after this index i , should return that elements' index, other wise index should point to the end of the string.
	*index = get_next_none_Mnem(i,operand);
	if(regex_match(resolvable, std::regex("[#0-9ABCDEF]+[h]*")))//only if this resolvable is hex string
		resolvable = clean_number(resolvable);//we clean the string
	return resolvable;
}

/*void reset_iter_source()
{
	iter_source.clear();
}*/
void random_swap(ea_t& next_ea, ea_t& next_ea1)
{
	std::vector<ea_t> array1;
	ea_t element = next_ea;
	ea_t element1 = next_ea1;
	array1.push_back(element);
	array1.push_back(element1);
	int random = rand() % 2;
	next_ea = array1[random];
	next_ea1 = array1[1 - random];
}
bool insn_has_not_been_touched(ea_t ea, func_t* func)
{
	for (const auto each_insn : insn_last_insn)
		if (each_insn.second == ea)
			return false;
	return true;
}

void put_loop_first(ea_t & next_ea, ea_t & next_ea1,ea_t ea,func_t *func)
{
	if (ea == 0x1e55)
		int bp = 1;
	std::vector<ea_t> array1;
	ea_t element = next_ea;
	ea_t element1 = next_ea1;
	array1.push_back(element);
	array1.push_back(element1);
	if (is_in_loop(ea, array1[0],func))
		return;
	else if (is_in_loop(ea, array1[1], func))
	{
		next_ea = array1[1];
		next_ea1 = array1[0];
		return;
	}

}
std::vector <ea_t> find_first_child_of(ea_t ea)
{
	std::vector <ea_t> children;
	for (const auto each_pair : insn_last_insn)
		if (each_pair.second == ea)
			children.push_back(each_pair.first);
	return children;
}

void init_recalculated_yet_map()
{
	recalculated_yet_map.clear();
}

//Some instructions mught be joint point for multiple paths. For example: 
//A->B->C->A; B->D->A. In this situation, we onlu recalculate this joint point
//once to avoid ITER(ITER(ITER(ITER())))......
bool insn_not_recalculate_yet(ea_t ea)
{
	if (recalculated_yet_map.find(ea) == recalculated_yet_map.end())
		return true;
	else if (recalculated_yet_map[ea] == 1)
		return false;
}

void init_conditional_jump_map()
{
	conditional_jump_map.clear();
}

void print_conditional_jump(std::string working_path)
{
	std::string filename = working_path+"\\IR_conditional_map.txt";
	FILE* MyFile = qfopen(filename.c_str(), "wb");
	if (MyFile == NULL)
		warning("qfopen fail!");
	std::string tmp;
	for (const auto each_item : conditional_jump_map)
	{
		tmp = each_item.first + ";" + each_item.second+"\n";
		if (qfwrite(MyFile, tmp.c_str(), tmp.size()) != tmp.size())
			warning("qfwrite failed!");

	}
	qfclose(MyFile);
}

//When handle the loop. we need to check in the second time of execution, whether the value change is a loop update,
//or is it completely different
bool is_loop_update(std::string before, std::string after)
{
	if (after.find(before) == 0 && after.size()> before.size())
		return true;
	else
		return false;
}

std::string clean_number(std::string num_string)
{
	int index;
	index = num_string.find('h');
	if (index != -1)
		num_string = num_string.replace(index,1,"");
	index = num_string.find("0x");
	if (index != -1)
		num_string = num_string.replace(index, 2, "");
	index = num_string.find('#');
	if (index != -1)
		num_string = num_string.replace(index, 1, "");
	return num_string;
}

int get_next_none_Mnem(int index, std::string operand)
{
	if (index == operand.size() - 1)
		return operand.size();
	else if (operand[index] == '+' || operand[index] == '-' || operand[index] == '*' || operand[index] == '/' || operand[index] == '='\
		|| operand[index] == '(' || operand[index] == ')' || operand[index] == '[')//If current character is a Mnem, find the next none-Mnem.
		for (index += 1;index < operand.length();index++)
		{
			if (operand[index] != '+' && operand[index] != '-' && operand[index] != '*' && operand[index] != '/'\
				&& operand[index] != '(' && operand[index] != ')' && operand[index] != '[' && operand[index] != ']' && operand[index] != '=')//if current index is non-Mnem, return this index.
				return index;
			else if (operand[index] == ']')//return the index after =
				return index+1;
			else if (index == operand.size() - 1)
				return operand.size();;
		}
	else if (operand[index] == ']')
		return index+1;
	else//If current operand is none-Mnem, return next character.
	{
		return index + 1;
	}
}

bool is_calculatable_stack(std::string operand)
{
	int index = 0;
	std::string element;
	if(operand.find(',')!=-1)
		index = operand.find(',') + 1;
	while (index < operand.length())
	{
		element=get_next_element(operand, &index);
		if (element.find("VAR") != -1)
			continue;
		else if (element.find("var_") != -1 || element.find("arg_") != -1)
			continue;
		else if (is_hex_string(element))
			continue;
		else
			return false;
	}
	return true;
}

bool is_hex_string(std::string operand)
{
	if (operand.find("0x") != -1)
		operand = operand.replace(operand.find("0x"), 2, "");
	else if (operand[operand.size() - 1] == 'h')
		operand = operand.substr(0, operand.size() - 1);
	else if(operand.find("#") != -1)
		operand = operand.replace(operand.find("#"), 1, "");
	for (int i = 0;i < operand.size();i++)
	{
		if ((operand[i] >= '0' && operand[i] <= '9') || (operand[i] >= 'a' && operand[i] <= 'f')||(operand[i] >= 'A' && operand[i] <= 'F'))
			continue;
		else
			return false;
	}
	return true;
}

void print_to_time_out_functions(std::string filename, std::string content)
{
	FILE* MyFile = qfopen(filename.c_str(), "wb");
	if (MyFile == NULL)
		warning("qfopen fail!");
	if (qfwrite(MyFile, content.c_str(), content.size()) != content.size())
		warning("qfwrite failed!");

	qfclose(MyFile);
}

//Strip the outmost '[' and ']' bracket 
std::string strip_disp(std::string disp)
{
	int left = disp.find('[');
	int right = disp.rfind(']');
	std::string content = disp.substr(left + 1, right - left - 1);
	return content;
}

//Print all the uncalculatable functions into a file
void print_uncalcuulateble_functions(std::string this_binary_path)
{
	std::string filename = this_binary_path + "\\" +  "uncalculatable_function.txt";
	FILE* MyFile = qfopen(filename.c_str(), "wb");
	if (MyFile == NULL)
		warning("qfopen fail!");
	std::string to_write = "";
	for (ea_t index = 0;index < uncalculatable_function_names.size();index++)
	{
		to_write = uncalculatable_function_names[index].c_str();
		to_write += "\n";
		if (qfwrite(MyFile, to_write.c_str(), to_write.size()) != to_write.size())
			warning("qfwrite failed!");
	}
	qfclose(MyFile);
}

//filter \ in the string
std::string filter_specific_string(std::string label_string)
{
	std::vector <char> toErase_list = {'\n','\t','\r','\"'};
	for (int index =0;index< toErase_list.size();index++)
		label_string.erase(std::remove(label_string.begin(), label_string.end(), toErase_list[index]), label_string.end());
	if (label_string.find(";;") != -1)
		label_string.erase(label_string.find(";;"), 2);
	return label_string;
}

void add_uncalculatable_function(ea_t ea)
{ 
	qstring function_name;//add this function name to a global list
	get_func_name(&function_name, ea);
	uncalculatable_function_names.push_back(function_name.c_str());
	return;
}

std::string get_label_value(std::string label)
{
	ea_t ea1 = get_name_ea(BADADDR, label.c_str());
	std::string result;
	if (label.find("xmmword_") == 0)//if the data decided by IDA as an integer with size xmmword
	{
		/*long long int value1=get_64bit(ea1);
		long long int value2 = get_64bit(ea1+8);
		result = lldec2hex(value1)+ lldec2hex(value2);*/
		result = dec2hex(ea1);
		return result;
	}
	else if (label.find("qword_") == 0)//if the data decided by IDA as an integer with size qword
	{
		/*long long int value1 = get_64bit(ea1);
		result = lldec2hex(value1);*/
		result = dec2hex(ea1);
		return result;
	}
	else if (label.find("dword_") == 0)//if the data decided by IDA as an integer with size dword
	{
		/*long int value1 = get_32bit(ea1);
		result = ldec2hex(value1);*/
		result = dec2hex(ea1);
		return result;
	}
	else if (label.find("word_") == 0)//if the data decided by IDA as an integer with size word
	{
		/*int value1 = get_16bit(ea1);
		result = dec2hex(value1);*/
		result = dec2hex(ea1);
		return result;
	}
	else if (label.find("byte_") == 0)//if the data decided by IDA as an integer with size byte
	{
		/*short int value1 = get_16bit(ea1)&0xff;
		result = dec2hex(value1);*/
		result = dec2hex(ea1);
		return result;
	}
	else if (label.find("byte3_") == 0)//if the data decided by IDA as an integer with size byte3
	{
		/*int value1 = get_16bit(ea1);
		short int value2 = get_16bit(ea1+2);
		result = dec2hex(value1) + dec2hex(value2);*/
		result = dec2hex(ea1);
		return result;
	}
	else//if the data decided by IDA as a string, this prefix of 'a' is default in IDA pro. One can change it to any other string.
	{
		qstring buffer;
		get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
		std::string defined_value = filter_specific_string(buffer.c_str());
		std::string tmp;
		if (!defined_value.empty() && defined_value != "\"\"")//has some content at this address
			tmp = '"' + defined_value + '"';
		else//do not have any known value at this address
		{
			if (ph.id == 0)
				tmp = x64_allocate_new_variable("rax");
			else if (ph.id == 13)
				tmp = arm_allocate_new_variable("R0");
			//tmp = '"' + defined_value + '"';
		}
		return tmp;
	}
}


std::string x64_allocate_new_variable(std::string operand) {
	if (file_type.find("ELF") == 0)
	{
		return x64_linux_allocate_new_variable(operand);
	}
	else if (file_type == "Portable executable")
	{
		return  x64_windows_allocate_new_variable(operand);
	}
}


std::string x64_windows_allocate_new_variable(std::string operand) {
	if (operand == "rcx")
		return "VAR0.64";
	else if (operand == "rdx")
		return "VAR1.64";
	else if (operand == "r8")
		return "VAR2.64";
	else if (operand == "r9")
		return "VAR3.64";
	else if (operand == "rsp")
		return "VAR4.64";
	else if (operand == "ecx")
		return "VAR0.32";
	else if (operand == "edx")
		return "VAR1.32";
	else if (operand == "r8d")
		return "VAR2.32";
	else if (operand == "r9d")
		return "VAR3.32";
	else if (operand == "esp")
		return "VAR4.32";
	else if (operand == "cx")
		return "VAR0.16";
	else if (operand == "dx")
		return "VAR1.16";
	else if (operand == "r8w")
		return "VAR2.16";
	else if (operand == "r9w")
		return "VAR3.16";
	else if (operand == "sp")
		return "VAR4.16";
	else if (operand == "ch" || operand == "cl")
		return "VAR0.8";
	else if (operand == "dh" || operand == "dl")
		return "VAR1.8";
	else if (operand == "r8b")
		return "VAR2.8";
	else if (operand == "r9b")
		return "VAR3.8";
	else if (operand == "spl")
		return "VAR4.8";
	else if (operand.find("xmm") != -1)
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".128";
	}
	else if (operand == "rax" || operand == "rbx" || operand == "rsi" || operand == "rdi"\
		|| operand == "rbp" || operand == "rsp" || operand == "r10"\
		|| operand == "r11" || operand == "r12" || operand == "r13" || operand == "r14" || operand == "r15")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".64";
	}
	else if (operand == "eax" || operand == "ebx" || operand == "esi" || operand == "edi"\
		|| operand == "ebp" || operand == "esp" || operand == "r10d"\
		|| operand == "r11d" || operand == "r12d" || operand == "r13d" || operand == "r14d" || operand == "r15d")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".32";
	}
	else if (operand == "ax" || operand == "bx" || operand == "si" || operand == "di"\
		|| operand == "bp" || operand == "sp" || operand == "r10w"\
		|| operand == "r11w" || operand == "r12w" || operand == "r13w" || operand == "r14w" || operand == "r15w")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".16";
	}
	else if (operand == "ah" || operand == "bh")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".8";
	}
	else if (operand == "al" || operand == "bl" || operand == "sil" || operand == "dil"\
		|| operand == "bpl" || operand == "spl" || operand == "r10b"\
		|| operand == "r11b" || operand == "r12b" || operand == "r13b" || operand == "r14b" || operand == "r15b")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".8";
	}

}


std::string x64_linux_allocate_new_variable(std::string operand) {
	if (operand == "rdi")
		return "VAR0.64";
	else if (operand == "rsi")
		return "VAR1.64";
	else if (operand == "rdx")
		return "VAR2.64";
	else if (operand == "rcx")
		return "VAR3.64";
	else if (operand == "r8")
		return "VAR5.64";
	else if (operand == "r9")
		return "VAR6.64";
	else if (operand == "rsp")
		return "VAR4.64";
	else if (operand == "edi")
		return "VAR0.32";
	else if (operand == "esi")
		return "VAR1.32";
	else if (operand == "edx")
		return "VAR2.32";
	else if (operand == "ecx")
		return "VAR3.32";
	else if (operand == "r8d")
		return "VAR5.32";
	else if (operand == "r9d")
		return "VAR6.32";
	else if (operand == "esp")
		return "VAR4.32";
	else if (operand == "di")
		return "VAR0.16";
	else if (operand == "si")
		return "VAR1.16";
	else if (operand == "dx")
		return "VAR2.16";
	else if (operand == "cx")
		return "VAR3.16";
	else if (operand == "r8w")
		return "VAR5.16";
	else if (operand == "r9w")
		return "VAR6.16";
	else if (operand == "sp")
		return "VAR4.16";
	else if (operand == "di" || operand == "dil")
		return "VAR0.8";
	else if (operand == "si" || operand == "sil")
		return "VAR1.8";
	else if (operand == "dh" || operand == "dl")
		return "VAR2.8";
	else if (operand == "ch" || operand == "cl")
		return "VAR3.8";
	else if (operand == "r8b")
		return "VAR5.8";
	else if (operand == "r9b")
		return "VAR6.8";
	else if (operand == "spl")
		return "VAR4.8";
	else if (operand.find("xmm") != -1)
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".128";
	}
	else if (operand == "rax" || operand == "rbx" || operand == "rsi" || operand == "rdi"\
		|| operand == "rbp" || operand == "rsp" || operand == "r10"\
		|| operand == "r11" || operand == "r12" || operand == "r13" || operand == "r14" || operand == "r15")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".64";
	}
	else if (operand == "eax" || operand == "ebx" || operand == "esi" || operand == "edi"\
		|| operand == "ebp" || operand == "esp" || operand == "r10d"\
		|| operand == "r11d" || operand == "r12d" || operand == "r13d" || operand == "r14d" || operand == "r15d")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".32";
	}
	else if (operand == "ax" || operand == "bx" || operand == "si" || operand == "di"\
		|| operand == "bp" || operand == "sp" || operand == "r10w"\
		|| operand == "r11w" || operand == "r12w" || operand == "r13w" || operand == "r14w" || operand == "r15w")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".16";
	}
	else if (operand == "ah" || operand == "bh")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".8";
	}
	else if (operand == "al" || operand == "bl" || operand == "sil" || operand == "dil"\
		|| operand == "bpl" || operand == "spl" || operand == "r10b"\
		|| operand == "r11b" || operand == "r12b" || operand == "r13b" || operand == "r14b" || operand == "r15b")
	{
		variable_number++;
		return "VAR" + std::to_string(variable_number) + ".8";
	}

}

//Decides whether this string is a number
bool is_number(std::string *string1)
{
	if ((*string1).find('h') == (*string1).size() - 1)
	{
		(*string1) = (*string1).substr(0, (*string1).size() - 1);
	}
	if ((*string1).find("0x")==0)
	{
		(*string1) = (*string1).substr(2, (*string1).size() - 2);
	}
	for (int i = 0;i < (*string1).size();i++)
	{
		if (isxdigit((*string1)[i]))
			continue;
		else
			return false;
	}
	return true;
}

//In the recovered calling subfunction instructions, we now represent the label as addresses. There are two possibilities of having a number as parameter\
, 1. just a constant value, 2. a string label offset, 3. a function offset. Thus we first check whether that's a function, then chech whether that's  a \
string offset. Otherwise, if the number is not an address, but a constant, we just leave it there.
std::vector <std::string>  translate_address_parameter_to_string_or_value(std::vector <std::string>  result_parameters)
{
	std::vector <std::string> result_result_parameters;
	qstring buffer;
	for (int i = 0;i < result_parameters.size();i++)
	{
		std::string parameter = result_parameters[i];
		if (is_number(&parameter))//if parameter is a number, we firstly test whether that is a function, then try to convert it to string or data.
		{
			ea_t ea;
			ea = strtoull(parameter.c_str(), 0, 16);
			func_t* func = get_func(ea);
			if (func != NULL)//if this number points to a function
			{
				result_result_parameters.push_back("RETURN_" + dec2hex(ea));
			}
			else//if this number is not a function pointer
			{
				long long int ea1 = strtoull(parameter.c_str(), 0, 16);
				get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
				std::string defined_value = filter_specific_string(buffer.c_str());
				std::string tmp;
				if (!defined_value.empty() && defined_value != "\"\"")//has some content at this address
				{
					tmp = '"' + defined_value + '"';
					result_result_parameters.push_back(tmp);
				}
				else//has no content at this address, we just copy and pasete content
				{
					result_result_parameters.push_back(parameter);
				}
			}
		}
		else//if parameter is not number, we directly copy and paste content
		{
			result_result_parameters.push_back(parameter);
		}
	}
	return result_result_parameters;
}