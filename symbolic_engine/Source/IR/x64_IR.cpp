#include "../../Headers/IR/x64_IR.h"

int x64_file_num;

std::string calling_convection[4][2] = {
	{"rcx","xmm0"},
	{"rdx","xmm1"},
	{"r8","xmm2"},
	{"r9","xmm3"}
};

std::vector <std::string> x64_my_insn_IR;
//std::vector <std::string> IR_reserve_insns;
void x64_translate_all_insn(func_t* func)
{

	qstring Mnemq;
	std::string Mnem;
	int ea_operand_num;
	int op0_type = 0, op1_type = 0, op2_type = 0;
	std::string operand0, operand1, operand2;
	
	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea= find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{	
		if (ea == 0x1c31d4)
			int breakp = 1;
		op0_type = 0, op1_type = 0, op2_type = 0;
		
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		ea_operand_num = count_ea_operands(ea);

		if (ea_operand_num == 1)
		{
			operand0 = x64_get_operand(ea, 0);
			op0_type = get_optype(ea, 0);

		}
		else if (ea_operand_num == 2)
		{
			operand0 = x64_get_operand(ea, 0);
			operand1 = x64_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);

		}
		else if (ea_operand_num == 3)
		{
			operand0 = x64_get_operand(ea, 0);
			operand1 = x64_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);
			operand2 = x64_get_operand(ea, 2);
			op2_type = get_optype(ea, 2);
		}
		/*if (x64_contain_iterators(ea)) 
		{ 
			x64_sub_IR(3, ea, func,Mnem, op0_type,op1_type,op2_type); 
		}*/
		if ((Mnem.find("mov") != -1|| Mnem.find("add") != -1|| Mnem.find("adc") != -1|| Mnem.find("sub") != -1\
			|| Mnem.find("sbb") != -1|| Mnem.find("or") != -1|| Mnem.find("xor") != -1|| Mnem.find("and") != -1\
			|| Mnem.find("mul") != -1) && (op0_type == 3 || op0_type == 4||op0_type==2)) { x64_sub_IR(0,ea,func); }//Case 1, storing some value into the memory address.
		else if(Mnem.find("stos") != -1|| x64_is_movs(ea,Mnem)) { x64_sub_IR(0, ea, func); }//Case 1, storing some value into the memory address.
		else if ((Mnem.find('j') == 0 && Mnem != "jmp")||Mnem.find("cmov")!=-1||Mnem.find("set")!=-1) { x64_sub_IR(1, ea, func); }//Case 2, comparing instruction.
		else if (Mnem.find("scas")!=-1) { x64_sub_IR(5, ea, func); }//Case 5, comparing instruction scas.
		else if (Mnem == "call" && op0_type!=1 && op0_type!=4 && op0_type!=3) { x64_sub_IR(2, ea, func); }//Case 3, calling subfunction whose name is a label.
		else if(Mnem=="call" && (op0_type == 1 || op0_type == 4 || op0_type == 3)) { x64_sub_IR(4, ea, func); }//Case 3, calling subfunction whose name is memory address.
	}
}
//Each x64_my_insn contains one line of IR if this instruction is key instrction. 
void x64_sub_IR(int num, ea_t ea, func_t* func) {
	
	if (num == 0)//mov [],
	{
		//explain_displ(ea);
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_my_insn[ea2x64_my_insn[ea]].operand0+";";
	}
	else if (num == 1)//Conditional jump/move
	{
		if (ea == 0x65a8c06d)
			int breakp = 1;
		qstring Mnemq;
		std::string Mnem;
		//Find backwoard for the first comparison instruction. This instruction corresponds to this conditional instruction.
		ea_t last_cmp_insn = x64_find_backward4cmp(ea, func);
		if (last_cmp_insn == 0x2e28)
			int breakp = 1;
		print_insn_mnem(&Mnemq, last_cmp_insn);
		Mnem = Mnemq.c_str();
		//Now we need to process differently for test rax, 8 and test rax, rbx
		std::string operand1_,operand0_;
		std::string operand1 = x64_get_operand(last_cmp_insn, 1);
		int op1_type = get_optype(last_cmp_insn, 1);
		if (op1_type == 5)//constant
			operand1_ = operand1;
		else
			operand1_ = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand1;
			//Next We shall recover IR
		if (Mnem.find("cmp")!=-1)
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]]=x64_check_for_last_last_and_or(last_cmp_insn, "cmp", func);
		else if (Mnem == "sub" || Mnem == "sbb")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "sub", func);
		else if (Mnem == "sbb")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "sbb", func);
		else if (Mnem == "test")
		{
			if (x64_get_operand(last_cmp_insn, 1) == x64_get_operand(last_cmp_insn, 0))//Case like test rax,rax
				x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = "("+x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0 + " cmp 0)";
			else//Case like test rax, rbx
				x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "and", func);
		}
		//For some instance, 'and' as the last comparison instruction, can be testing if two conditions are all true. e.g.,
		//cmp edx,5
		//setnz al
		//cmp eax,6
		//setz cl
		//and al, cl 
		else if (Mnem == "and")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_further_investigate_this_branch(last_cmp_insn,func);
			//x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		//For some instance, 'or' as the last comparison instruction, can be testing if two conditions are all true. e.g.,
		//cmp edx,5
		//setnz al
		//cmp eax,6
		//setz cl
		//and al, cl 
		else if (Mnem == "or")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_further_investigate_this_branch(last_cmp_insn,func);
		else if (Mnem == "xor")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "xor", func);
		else if (Mnem == "not")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "not", func);
		else if (Mnem == "neg")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "neg", func);
		else if (Mnem == "add" || Mnem == "adc")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_check_for_last_last_and_or(last_cmp_insn, "add", func);
		else if (Mnem == "inc")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		else if (Mnem == "dec")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		else if (Mnem == "mul" || Mnem == "imul")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		else if (Mnem == "div" ||Mnem == "idiv")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].parameters0["eax"];
		else if (Mnem == "shr")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		else if (Mnem == "shl")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		else if(Mnem == "ror")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
		else if(Mnem == "rol")
			x64_my_insn_IR[ea2x64_my_insn[last_cmp_insn]] = x64_my_insn[ea2x64_my_insn[last_cmp_insn]].operand0;
	}
	else if (num == 2)//call label
	{
		std::vector <std::string> parameters;
		std::string function_name= "RETURN_" + dec2hex(ea);
		parameters=x64_look_for_parameters(ea,func);
		x64_my_insn_IR[ea2x64_my_insn[ea]] += function_name+" (";
		for (int i = 0;i < parameters.size();i++)
		{
			x64_my_insn_IR[ea2x64_my_insn[ea]] += parameters[i] + ",";
		}
		int last_comma = x64_my_insn_IR[ea2x64_my_insn[ea]].rfind(',');
		if(last_comma!=-1)
		x64_my_insn_IR[ea2x64_my_insn[ea]][last_comma] = ' ';
		x64_my_insn_IR[ea2x64_my_insn[ea]] += ");";
	}
	else if (num == 4)//call []/ call reg
	{
		if (ea == 0x2a36)
			int breakp = 1;
		std::vector <std::string> parameters;
		std::string function_name = x64_my_insn[ea2x64_my_insn[ea]].operand0;
		parameters = x64_look_for_parameters(ea, func);
		x64_my_insn_IR[ea2x64_my_insn[ea]] += function_name + " (";
		for (int i = 0;i < parameters.size();i++)
		{
			x64_my_insn_IR[ea2x64_my_insn[ea]] += parameters[i] + ",";
		}
		int last_comma = x64_my_insn_IR[ea2x64_my_insn[ea]].rfind(',');
		if (last_comma != -1)
			x64_my_insn_IR[ea2x64_my_insn[ea]][last_comma] = ' ';
		x64_my_insn_IR[ea2x64_my_insn[ea]] += ");";
	}
	else if (num == 3)//contains ITERATOR
	{
		//x64_iterator_handler_v1(ea,Mnem, op0_type,op1_type,op2_type);
	}
	else if (num == 5)//scas
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_my_insn[ea2x64_my_insn[ea]].operand0;
    }
	
}


void x64_display_translate_result(func_t* func) {
	for (ea_t i = func->start_ea;i <func->end_ea ;i = find_code(i, SEARCH_DOWN | SEARCH_NEXT))
	{
		if(x64_my_insn_IR[ea2x64_my_insn[i]]!="")
		set_cmt(i, x64_my_insn_IR[ea2x64_my_insn[i]].c_str(), false);
	}
}


void x64_print_to_file(ea_t ea, std::string working_path,func_t* func)
{ 
	std::string filename = working_path +"\\"+std::to_string(x64_file_num) + "_output.txt";
	//std::string filename = "C:\\Users\\nuc\\Desktop\\" + std::to_string(file_num) + "_output.txt";
	std::string each_insn;
	std::vector <std::string> content;
	qstring disasm;
	FILE* MyFile=qfopen(filename.c_str(),"wb");
	if (MyFile == NULL)
		warning("qfopen fail!");
	for (ea_t index = func->start_ea;index < func->end_ea;index = find_code(index, SEARCH_DOWN | SEARCH_NEXT))
	{ 
		
		generate_disasm_line(&disasm, index, GENDSM_REMOVE_TAGS);
		each_insn = dec2hex(index)+";;	"+disasm.c_str()+"		"+x64_my_insn[ea2x64_my_insn[index]].operand0 + ", " + x64_my_insn[ea2x64_my_insn[index]].operand1;
		//each_insn += "		" + IR_reserve_insns[ea2x64_my_insn[index]];
		each_insn += "		;;";
		//if (x64_iterate_mark[ea2x64_my_insn[index]] == '{')
			//each_insn += '{';
		each_insn += x64_my_insn_IR[ea2x64_my_insn[index]];
		//if (x64_iterate_mark[ea2x64_my_insn[index]] == '}')
			//each_insn += '}';
		each_insn += '\n';
		content.push_back(each_insn);

	}
   	//std::reverse(content.begin(), content.end());
	for (ea_t index = 0;index < content.size();index++)
		if (qfwrite(MyFile, content[index].c_str(), content[index].size()) != content[index].size())
			warning("qfwrite failed!");

	qfclose(MyFile);
	//x64_file_num++;
	x64_clear_each_random_run();
}

void x64_clear_each_random_run()
{
	x64_my_insn.clear();
	insn_last_insn.clear();
	ea2x64_my_insn.clear();
	x64_my_insn_IR.clear();
}

void x64_print_IR_file(std::string working_path,func_t* func)
{
	ea_t next_ea, next_ea1;
	std::string next_eas_string="";
	std::string filename = working_path+"\\IR_output.txt";
	FILE* MyFile = qfopen(filename.c_str(), "wb");
	if (MyFile == NULL)
		warning("qfopen fail!");
	std::string tmp;
	for (ea_t ea = func->start_ea;ea < func->end_ea;ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		if (ea == 0x43fd31)
			int breakp = 1;
		next_eas_string = "";
		next_ea= get_first_cref_from(ea);
		if (next_ea!=-1 && next_ea>= func->start_ea && next_ea<= func->end_ea)
			next_eas_string += dec2hex(next_ea)+",";
		while (next_ea != -1 && next_ea <= func->end_ea && next_ea >= func->start_ea)
		{
			next_ea = get_next_cref_from(ea, next_ea);
			if (is_in_loop(ea, next_ea, func))
			{
				//x64_add_while_before_IR(ea);
				continue;
			}
			if (next_ea!=-1 && next_ea >= func->start_ea && next_ea <= func->end_ea)
			 next_eas_string += dec2hex(next_ea)+",";
		}
		//if (next_ea > func->end_ea || next_ea < func->start_ea)
		//	next_ea = -1;
		//if (next_ea1 > func->end_ea || next_ea1 < func->start_ea)
		//	next_ea1 = -1;
		//if (next_ea != -1)
		//	next_ea_s = dec2hex(next_ea);
		//else
		//	next_ea_s = "";
		//if (next_ea1 != -1)
		//	next_ea1_s = dec2hex(next_ea1);
		//else
		//	next_ea1_s = "";
		if (next_eas_string.find(',') == next_eas_string.size() - 1)//trim the ending ',' if there is one
			next_eas_string = next_eas_string.substr(0, next_eas_string.size() - 1);
		tmp = dec2hex(ea)+"-->"+ next_eas_string +"\n";
		if (qfwrite(MyFile, tmp.c_str(),tmp.size()) != tmp.size())
				warning("qfwrite failed!");
		
	}
	qfclose(MyFile);
}

//Now we detect that ea has one branch goes to a node precedes ea (thus a loop). Now we need to add a 'while' before this ea's IR.
void x64_add_while_before_IR(ea_t ea)
{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = "while " + x64_my_insn_IR[ea2x64_my_insn[ea]];
}

//Translate only one instruction into IR.
void x64_translate_one_insn(ea_t ea, func_t* func)
{

	qstring Mnemq;
	std::string Mnem;
	int ea_operand_num;
	int op0_type = 0, op1_type = 0, op2_type = 0;
	std::string operand0, operand1, operand2;
	op0_type = 0, op1_type = 0, op2_type = 0;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
		{
			operand0 = x64_get_operand(ea, 0);
			op0_type = get_optype(ea, 0);

		}
	else if (ea_operand_num == 2)
		{
			operand0 = x64_get_operand(ea, 0);
			operand1 = x64_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);

		}
	else if (ea_operand_num == 3)
		{
			operand0 = x64_get_operand(ea, 0);
			operand1 = x64_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);
			operand2 = x64_get_operand(ea, 2);
			op2_type = get_optype(ea, 2);
		}
		
	if (Mnem.find("mov") != -1 && (op0_type == 3 || op0_type == 4)) { x64_sub_IR(0, ea, func); }
	else if (Mnem == "test" || Mnem.find("cmp")!=-1) { x64_sub_IR(1, ea, func); }
	else if (Mnem == "call" && op0_type != 1 && op0_type != 4 && op0_type != 3) { x64_sub_IR(2, ea, func); }
	else if (Mnem == "call" && (op0_type == 1 || op0_type == 4 || op0_type == 3)) { x64_sub_IR(4, ea, func); }
	
}

ea_t x64_find_forward4key_IR(ea_t ea, func_t* func)
{
	for (ea_t index = ea;index < func->end_ea && ea != BADADDR; index = get_first_cref_from(index))
	{
		if (x64_my_insn_IR[ea2x64_my_insn[index]] != "")
			return index;
	}
}

ea_t x64_find_backward4cmp(ea_t ea, func_t* func)
{
	qstring Mnemq;
	std::string Mnem;
	for (ea_t index = insn_last_insn[ea];index >= func->start_ea && insn_last_insn.find(index)!= insn_last_insn.end();index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		if (Mnem.find("cmp")!=-1 || Mnem == "test" || Mnem == "and" || Mnem == "or" || Mnem == "xor" || Mnem == "not"\
			|| Mnem == "neg" || Mnem == "add" || Mnem == "sub" || Mnem == "inc" || Mnem == "dec" || Mnem == "mul" \
			|| Mnem == "div" || Mnem == "imul" || Mnem == "idiv" || Mnem == "adc" || Mnem == "sbb" || Mnem == "shr"\
			|| Mnem == "shl" || Mnem == "ror" || Mnem == "rol")
			return index;
	}
	return 0;
}

//This is to handle when last comparison instruction is 'and' or 'or'. This function will look backward for 'and' or 'or''s
//operands. If it turns out that some operand is dependent on some conditional instruction, this means this 'and' or 'or' 
//instruction is a branching-like instruction that connect conditions.
std::string x64_further_investigate_this_branch(ea_t ea, func_t* func)
{
	bool result=x64_look_backward_4_conditional(ea,func,true);
	if (result == true)
	{
		return x64_translate_branching_insn(ea,func,true);
	}
	else 
		return x64_my_insn[ea2x64_my_insn[ea]].operand0;

}

//Look backward to find out whether the 'and' or 'or' instruction is dependent on some conditional instructions.
//We assume a set of condition instructions are connected by multiple 'and' and 'or' instructions. The cases might be ensure all the conditions holds or only if one condition holds.
//Yhus the last instruction might be 'oring'/'anding' the n-1 th conditions with the last (n th) condition. The last instruction can also be comparing the n th conditions with some magic value.
//So we need to starting from this last comparing instruction and look up backward to find out whether its value comes from some conditional instructions such as moveq etc. Note that sub,eor 
//can also function like cmp... moveq thus sub, eor, add are also condidered as conditional instructions.
//Parameter 1: the address of 'and' or 'or' instruction.
//Parameter 2: function.
//Parameter 3: whether instruction ea is the starting checking instruction (i.e., the last comparing instruction)
bool x64_look_backward_4_conditional(ea_t ea, func_t *func,bool ea_is_last_cmp)
{
	if (ea == 0x2616)
		int breakp = 1;
	bool result;
	qstring Mnemq;
	std::string Mnem;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	ea_t last_define_ea;
	int op0_type = get_optype(ea, 0);
	int op1_type = get_optype(ea, 1);
	if (Mnem == "or"|| (Mnem == "and" && x64_get_operand(ea, 0) != x64_get_operand(ea, 1)))
	{
		std::vector <std::string> operands_list = x64_get_operands_list(ea);
		for (int index = 0;index < operands_list.size();index++)
		{
			last_define_ea = x64_find_backward4define(operands_list[index], ea,func);
			if (last_define_ea == -1)//One operand's definition not found, skip to next operand
				continue;
			result=x64_look_backward_4_conditional(last_define_ea, func,false);
			if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
				return true;
		}
	}
	else if (Mnem.find("set") != -1 || Mnem.find("cmov") != -1)
		return true;
	else if (Mnem == "sub" || Mnem == "sbb" || Mnem == "add" || Mnem == "adc" || Mnem == "xor"|| (Mnem == "and"&&x64_get_operand(ea,0)==x64_get_operand(ea,1)))
	{
		if (ea_is_last_cmp)
		{
			std::vector <std::string> operands_list = x64_get_operands_list(ea);
			for (int index = 0;index < operands_list.size();index++)
			{
				last_define_ea = x64_find_backward4define(operands_list[index], ea, func);
				if (last_define_ea == -1)//One operand's definition not found, skip to next operand
					continue;
				result = x64_look_backward_4_conditional(last_define_ea, func, false);
				if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
					return true;
			}
		}
		else if (!ea_is_last_cmp)
			return true;
	}
	else if (Mnem == "mov")
	{
		std::string operand1 = x64_get_operand(ea, 1);
		if (op1_type == 5)
			return false;
		last_define_ea = x64_find_backward4define(operand1, ea, func);
		if (last_define_ea != -1)
		{
			result = x64_look_backward_4_conditional(last_define_ea, func,false);
			if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
				return true;
		}
	}
	else if (Mnem.find("cmp")!=-1 || Mnem == "test")
	{
		std::string operand1 = x64_get_operand(ea, 1);
		std::string operand0= x64_get_operand(ea, 0);
		if (op0_type == 1 || op0_type == 3 || op0_type == 4)
		{
			last_define_ea = x64_find_backward4define(operand0, ea, func);
			if (last_define_ea != -1)
			{
				result = x64_look_backward_4_conditional(last_define_ea, func,false);
				if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
					return true;
			}
		}
		if (op1_type == 1 || op1_type == 3 || op1_type == 4)
		{
			last_define_ea = x64_find_backward4define(operand1, ea, func);
			if (last_define_ea != -1)
			{
				result = x64_look_backward_4_conditional(last_define_ea, func,false);
				if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
					return true;
			}
		}
	}
	return false;
}

//Given an address, return a list of all its operands if the operand is register. Because we are looking for operands coming from previous logic 'and' or
//'or' instructions. Thus we only check registers. Disp and num should be ignored.
std::vector<std::string> x64_get_operands_list(ea_t ea)
{
	std::vector<std::string> operands_list;
	int ea_operand_num;
	std::string operand0, operand1, operand2;
	int op0_type, op1_type, op2_type;
	ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
	{
		operand0 = x64_get_operand(ea, 0);
		op0_type = get_optype(ea, 0);
		if(op0_type==1|| op0_type == 3|| op0_type == 4)
			operands_list.push_back(operand0);
		return operands_list;
	}
	else if (ea_operand_num == 2)
	{
		operand0 = x64_get_operand(ea, 0);
		operand1 = x64_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		if (op0_type == 1 || op0_type == 3 || op0_type == 4)
			operands_list.push_back(operand0);
		if (op1_type == 1 || op1_type == 3 || op1_type == 4)
			operands_list.push_back(operand1);
		return operands_list;
	}
	else if (ea_operand_num == 3)
	{
		operand0 = x64_get_operand(ea, 0);
		operand1 = x64_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = x64_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
		if (op0_type == 1 || op0_type == 3 || op0_type == 4)
			operands_list.push_back(operand0);
		if (op1_type == 1 || op1_type == 3 || op1_type == 4)
			operands_list.push_back(operand1);
		if (op2_type == 1 || op2_type == 3 || op2_type == 4)
			operands_list.push_back(operand2);
		return operands_list;
	}
}

//Given a operand at address ea, find from ea backward to find its defined address.
ea_t x64_find_backward4define(std::string operand, ea_t ea,func_t * func)
{
	qstring Mnemq;
	std::string Mnem;
	std::string operand0;
	for (ea_t index = insn_last_insn[ea];index >= func->start_ea && insn_last_insn.find(index) != insn_last_insn.end();index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		if (Mnem == "nop" || Mnem=="push")
			continue;
		operand0 = x64_get_operand(index, 0);
		if (operand0 == operand && Mnem!="test" && Mnem.find("cmp")==-1)
			return index;
	}
	return -1;
}

//For branching-like 'and' or 'or' instructions, we translate them into more comprehensive format to facilitate similarity compare.
std::string x64_translate_branching_insn(ea_t ea, func_t* func,bool ea_is_last_cmp)
{
	if (ea == 0x340109)
		int breakp = 1;
	qstring Mnemq;
	std::string Mnem, result;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string left, right;
	ea_t last_define_ea;
	std::string operand0, operand1;
	operand0 = x64_get_operand(ea, 0);
	operand1 = x64_get_operand(ea, 1);
	int op0_type = get_optype(ea, 0);
	int op1_type = get_optype(ea, 1);
	if ((Mnem == "and" || Mnem == "or") && x64_look_backward_4_conditional(ea, func, ea_is_last_cmp))//if current address contain conditional value
	{
		last_define_ea = x64_find_backward4define(operand0, ea, func);
		if (op0_type == 1 || op0_type == 3 || op0_type == 4)
		{
			left = x64_translate_branching_insn(last_define_ea, func, false);
		}
		else 
			left = operand0;
		last_define_ea = x64_find_backward4define(operand1, ea, func);
		if (op1_type == 1 || op1_type == 3 || op1_type == 4)
			right = x64_translate_branching_insn(last_define_ea, func, false);
		else if (op1_type == 2)
			right = get_label_value(x64_get_operand(last_define_ea, 1));
		else
			right = operand1;
		if (Mnem == "and")
			result = "(" + left + " and " + right + ")";
		else if(Mnem=="or")
			result= "(" + left + " or " + right + ")";
		return result;
	}
	else if (Mnem.find("mov")==0)
	{
		last_define_ea = x64_find_backward4define(operand1, ea, func);
		if (op1_type == 1 || op1_type == 3 || op1_type == 4)
		{
			if (last_define_ea != -1)
				result = x64_translate_branching_insn(last_define_ea, func,false);
			else
				result = x64_my_insn[ea2x64_my_insn[ea]].operand1;
		}
		else
			result = x64_my_insn[ea2x64_my_insn[ea]].operand0;
		return result;
	}
	else if (Mnem == "lea")
	{
		result = x64_my_insn[ea2x64_my_insn[ea]].operand1;
		return result;
	}
	else//if current address is source instruction of conditional value.
	{
	
		operand1 = x64_get_original_operands(ea)[1];
		operand0 = x64_get_original_operands(ea)[0];
		if (Mnem == "xor")
		{
			if (x64_get_operand(ea, 0) != x64_get_operand(ea, 1))//xor eax,ebx
				result = "(" + operand0 + " xor " + operand1 + ")";
			else//xor eax,eax
				result = "0";
		}
		else if (Mnem == "add")
			result = "(" + operand0 + " add " + operand1 + ")";
		else if (Mnem == "adc")
			result = "(" + operand0 + " adc " + operand1 + ")";
		else if (Mnem == "sub")
			result = "(" + operand0 + " sub " + operand1 + ")";
		else if (Mnem == "sbb")
			result = "(" + operand0 + " sbb " + operand1 + ")";
		else if (Mnem.find("set") != -1)
			result = x64_explain_set(ea,func, ea_is_last_cmp);
		else if(Mnem.find("cmov")!=-1)
			result= x64_explain_cmov(ea, func, ea_is_last_cmp);
		else if (Mnem.find("shl") != -1|| Mnem.find("shr") != -1|| Mnem.find("sal") != -1|| Mnem.find("sar") != -1)
			result = operand0;
		else if (Mnem=="and"||Mnem=="or")
			result= "(" + operand0 +" "+ Mnem +" "+ operand1 + ")";
		return result;
	}
}

std::string  x64_explain_set(ea_t ea, func_t *func,bool ea_is_last_cmp)
{
	qstring Mnemq;
	std::string Mnem, result;
	ea_t last_cmp = x64_find_backward4cmp(ea,func);
	print_insn_mnem(&Mnemq, last_cmp);
	Mnem = Mnemq.c_str();

	//We firstly get operand0 and operand1 correctly.
	std::string operand0 = x64_get_original_operands(last_cmp)[0];
	std::string operand1 = x64_get_original_operands(last_cmp)[1];

	if (Mnem == "xor")
	{
		if (x64_get_operand(last_cmp, 0) != x64_get_operand(last_cmp, 1))//xor eax,ebx
			result = "(" + operand0 + " xor " + operand1 + ")";
		else//xor eax,eax
			result = "0";
	}
	else if (Mnem == "add")
		result = "(" + operand0 + " add " + operand1 + ")";
	else if (Mnem == "adc")
		result = "(" + operand0 + " adc " + operand1 + ")";
	else if (Mnem == "sub")
		result = "(" + operand0 + " sub " + operand1 + ")";
	else if (Mnem == "sbb")
		result = "(" + operand0 + " sbb " + operand1 + ")";
	else if (Mnem == "test")
	{
		if (x64_get_operand(last_cmp, 0) == x64_get_operand(last_cmp, 1))//Case like test rax, rax
			result = "(" + x64_my_insn[ea2x64_my_insn[last_cmp]].operand0 + " cmp 0)";
		else//Case liek test rax,rbx
			result = "(" + operand0 + " test " + operand1 + ")";
	}
	else if (Mnem.find("cmp")!=-1)
		result = "(" + operand0 + " cmp " + operand1 + ")";
	else if (Mnem == "or"||Mnem=="and")
		result = x64_translate_branching_insn(last_cmp,func, ea_is_last_cmp);
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	result += Mnem;
	result = "(" + result + ")";
	return result;
}

std::string  x64_explain_cmov(ea_t ea, func_t* func,bool ea_is_last_cmp)
{
	qstring Mnemq;
	std::string Mnem, result;
	ea_t last_cmp = x64_find_backward4cmp(ea, func);
	print_insn_mnem(&Mnemq, last_cmp);
	Mnem = Mnemq.c_str();

	//We firstly get operand0 and operand1 correctly.
	std::string operand0 = x64_get_original_operands(last_cmp)[0];
	std::string operand1 = x64_get_original_operands(last_cmp)[1];
	if (Mnem == "xor")
	{
		if (x64_get_operand(last_cmp, 0) != x64_get_operand(last_cmp, 1))//xor eax,ebx
			result = "(" + operand0 + " xor " + operand1 + ")";
		else//xor eax,eax
			result = "0";
	}
	else if (Mnem == "add")
		result = "(" + operand0 + " add " + operand1 + ")";
	else if (Mnem == "adc")
		result = "(" + operand0 + " adc " + operand1 + ")";
	else if (Mnem == "sub")
		result = "(" + operand0 + " sub " + operand1 + ")";
	else if (Mnem == "sbb")
		result = "(" + operand0 + " sbb " + operand1 + ")";
	else if (Mnem == "test")
	{
		if (x64_get_operand(last_cmp, 0) == x64_get_operand(last_cmp, 1))//Case like test rax, rax
			result = "("+x64_my_insn[ea2x64_my_insn[last_cmp]].operand0+" cmp 0)";
		else//Case like test rax, rbx
			result = "(" + operand0 + " test " + operand1 + ")";
	}
	else if (Mnem.find("cmp")!=-1)
		result = "(" + operand0 + " cmp " + operand1 + ")";
	else if (Mnem == "or" || Mnem == "and")
		result = x64_translate_branching_insn(last_cmp, func, ea_is_last_cmp);
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	result += Mnem+operand1;
	result = "(" + result + ")";
	return result;
}

//For cmp instruction, we need to further check its operands whether come from some logic instructions. In this case,
//This cmp can be actually comparing whether two conditions hold. Thus a braching-like instruction.
//Parameter 1: the comparison instruction before conditional instruction ,say cmp.
//Parameter 2: the comparison instruction Mnem, say cmp.
//Parameter 3: original comparison instruction operand0.
//Parameter 4: original comparison instruction oeprand1.
//Parameter 5: func.
//returns the correct IR string for this comparison instruction.
std::string x64_check_for_last_last_and_or(ea_t last_insn,std::string Mnem,func_t * func)
{
	if (last_insn ==0x34037a)
		int breakp = 1;
	int op1_type, op0_type;
	std::string operand0_, operand1_;
	op0_type = get_optype(last_insn, 0);
	op1_type = get_optype(last_insn, 1);
	//Firstly we find the value of operand0 and operand1.
	operand0_ = x64_get_original_operands(last_insn)[0];
	operand1_ = x64_get_original_operands(last_insn)[1];
	//If this comparison instruction is not a braching-like instruction. i.e., not to test whether two conditions hold.
	if (!x64_look_backward_4_conditional(last_insn, func, true))
	{
		if (operand0_.find('=') != -1)//If [] has '='
			operand0_ = operand0_.substr(operand0_.find('=') + 1, operand0_.size() - 1 - operand0_.find('='));
		if (operand1_.find('=') != -1)//If [] has '='
			operand1_ = operand1_.substr(operand1_.find('=') + 1, operand1_.size() - 1 - operand1_.find('='));
		return  " (" + operand0_ + " " + Mnem + " " + operand1_ + ")";
	}
	//If this comparison instruction is a braching-like instruction. i.e., test whether two conditions hold.
	else
	{
		ea_t last_last_and_or_insn = x64_find_backward4define(x64_get_operand(last_insn, 0), last_insn,func);
		if (last_last_and_or_insn!=-1)
			operand0_ = x64_translate_branching_insn(last_last_and_or_insn, func,false);
		last_last_and_or_insn = x64_find_backward4define(x64_get_operand(last_insn, 1), last_insn, func);
		if (last_last_and_or_insn!=-1)
			operand1_ = x64_translate_branching_insn(last_last_and_or_insn, func,false);
		//groom the result to delete '[]=' 
		if (operand0_.find('=') != -1)//If [] has '='
			operand0_ = operand0_.substr(operand0_.find('=') + 1, operand0_.size() - 1 - operand0_.find('='));
		if (operand1_.find('=') != -1)//If [] has '='
			operand1_ = operand1_.substr(operand1_.find('=') + 1, operand1_.size() - 1 - operand1_.find('='));
		return "(" + operand0_ + " "+Mnem+" " + operand1_ + ")";
	}
}


//For an address ea and its number 'index' operand, if the operand comes from a 'and' or 'or' instruction,
//return the address of that 'and' or 'or' instruction. Return -1 if not from 'and' or 'or' instruction.
/*ea_t x64_operand_from_and_or_insn(int index, ea_t ea, func_t *func)
{
	int op_type;
	std::string operand,tmp;
	qstring Mnemq;
	std::string Mnem;
	op_type = get_optype(ea, index);
	if (op_type != 1)//not register
		return -1;
	operand = x64_get_operand(ea, index);
	for (ea_t index1 = insn_last_insn[ea];index1 != func->start_ea;index1 = insn_last_insn[index1])
	{
		print_insn_mnem(&Mnemq, index1);
		Mnem = Mnemq.c_str();
		tmp = x64_get_operand(index1, 0);
		if (tmp == operand)
			if (Mnem == "and" || Mnem == "or")
				return index;
			else
				return -1;
	}
	return -1;
}
*/


std::vector<std::string> x64_get_original_operands(ea_t ea)
{
	qstring Mnemq;
	std::string Mnem;
	if (ea == 0x2cf6d)
		int breakp=0;
	std::vector<std::string> result;
	int ea_operand_num = count_ea_operands(ea);
	int op1_type = get_optype(ea, 1);
	if (ea_operand_num == 2)
	{
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		//add operand0
		if(Mnem=="test"||Mnem=="cmp")
			result.push_back(x64_my_insn[ea2x64_my_insn[ea]].operand0);
		else
			result.push_back(x64_my_insn[ea2x64_my_insn[ea]].parameters0["original"]);
		//add operand1
		if (op1_type == 1 || op1_type == 3 || op1_type == 4)
			result.push_back(x64_my_insn[ea2x64_my_insn[ea]].operand1);
		else if(op1_type==5)
			result.push_back(x64_get_operand(ea,1));
		else if (op1_type == 2)
		{
			//qstring buffer;
			//ea_t ea1 = get_name_ea(BADADDR, x64_get_operand(ea, 1).c_str());
			//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
			//std::string defined_value=filter_specific_string(buffer.c_str());
			std::string defined_value = get_label_value(x64_get_operand(ea, 1));
			result.push_back(defined_value);
		}
		return result;
	}
	else if (ea_operand_num == 3)
	{
		int op2_type = get_optype(ea, 2);
		//add operand0
		result.push_back(x64_my_insn[ea2x64_my_insn[ea]].operand1);
		//add operand1
		if(op2_type==5)
			result.push_back(x64_get_operand(ea,2));
		else
			result.push_back("");
		return result;
	}
	else {
		result.push_back("");
		result.push_back("");
		return result;
	}
}

//Determin whether this insn is move string to string like movsb, movsd, movsw or is it move value to value like movsd xmm1,xmm2
bool x64_is_movs(ea_t ea, std::string Mnem)
{
	if (Mnem.find("movs") == 0 && Mnem.find("movsx") == -1)
	{
		qstring disasm;
		generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
		std::string string1 = disasm.c_str();
		if (Mnem == "movs")
			return true;
		else if ((Mnem == "movsb" || Mnem == "movsw" || Mnem == "movsd") && string1.find(',') == -1)//move string to string instruction
			return true;
		else if (string1.find(',') != -1)//move value string like movsd xmm1, xmm2
			return false;
	}
	else
		return false;
}