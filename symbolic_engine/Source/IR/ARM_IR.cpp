#include "../../Headers/IR/ARM_IR.h"


std::vector <std::string> ARM_my_insn_IR;
int file_num;

void init_ARM_my_insn_IR(func_t * func)
{
	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
		ARM_my_insn_IR.push_back("");
}


void ARM_translate_each_insn(func_t * func)
{
	qstring Mnemq;
	std::string Mnem;
	int ea_operand_num;
	int op0_type = 0, op1_type = 0, op2_type = 0,op3_type;
	std::string operand0, operand1, operand2,operand3;


	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		if (ea == 0x2dc90)
			int breakp = 1;
		if (insn_last_insn[ea] == 0)//IDA sometimes may not able to generate a complete CFG. Thus some instructions within this function might not be able to be symbolically executred.
			continue;//For those instructions, we just ignore them.
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		ea_operand_num = count_ea_operands(ea);
		if (ea == 0x1204)
			int bp = 0;
		if (ea_operand_num == 1)
		{
			operand0 =ARM_get_operand(ea, 0);
			op0_type = get_optype(ea, 0);

		}
		else if (ea_operand_num == 2)
		{
			operand0 = ARM_get_operand(ea, 0);
			operand1 = ARM_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);

		}
		else if (ea_operand_num == 3)
		{
			operand0 = ARM_get_operand(ea, 0);
			operand1 = ARM_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);
			operand2 = ARM_get_operand(ea, 2);
			op2_type = get_optype(ea, 2);
		}

		else if (ea_operand_num == 4)
		{
			operand0 = ARM_get_operand(ea, 0);
			operand1 = ARM_get_operand(ea, 1);
			op0_type = get_optype(ea, 0);
			op1_type = get_optype(ea, 1);
			operand2 = ARM_get_operand(ea, 2);
			op2_type = get_optype(ea, 2);
			operand3 = ARM_get_operand(ea, 3);
			op3_type = get_optype(ea, 3);
		}

		//if (ARM_contain_iterators_v1(ea)) { ARM_sub_IR(3, ea, func, Mnem, op0_type, op1_type, op2_type); }
		if(Mnem.find("STREX")!=-1) 
			{ ARM_sub_IR(6, ea, func); }
		else if (Mnem.find("STR") != -1&& Mnem.find("STRD") == -1) 
			{ ARM_sub_IR(0, ea, func); }
		else if(Mnem.find("STRD")!=-1) 
			{ ARM_sub_IR(8, ea, func); }
		else if (Mnem.find("STM") != -1) 
			{ ARM_sub_IR(4, ea, func); }
		else if (Mnem.find('B') == 0 && ARM_contains_conditional_compare(ea)&&Mnem.find("BIC")==-1&& Mnem.find("BFC") == -1 && Mnem.find("BFI") == -1\
			&& operand0.find("loc_") == -1)//If the instruction is a conditional calling subfunction.
			{ ARM_sub_IR(1, ea, func); }
		else if(ARM_contains_conditional_compare(ea))
			{ARM_sub_IR(7, ea, func); }//Instruction is like MOVEEQ, MOVNE 
		else if (Mnem.find("B")==0&&Mnem.find("BIC")==-1 &&Mnem.find("BFC") == -1 && Mnem.find("BFI") == -1 && operand0.find("loc_")==-1&&\
			op0_type != 1) 
			{ ARM_sub_IR(2, ea, func); }//unconditionally calling sub function with function mame a label
		else if(Mnem.find('B')==0 && op0_type==1 &&Mnem.find("BIC")==-1&& Mnem.find("BFC") == -1 && Mnem.find("BFI") == -1 && \
			operand0.find("loc_") == -1) 
			{ ARM_sub_IR(5, ea, func); }//unconditionally calling sub function with function mame a register
	}

}

void ARM_sub_IR(int num, ea_t ea, func_t* func) {
 	if (ea == 0x11bd08)
		int bp = 1;
	if (num == 0)//STR
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += ARM_my_insn[ea2ARM_my_insn[ea]].operand1+";";
	}
	else if (num == 8)//STRD
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += ARM_my_insn[ea2ARM_my_insn[ea]].operand2 + ";";
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters2)
			if (each_pair.first.find('[') != -1)//looking for the second []
				ARM_my_insn_IR[ea2ARM_my_insn[ea]] += each_pair.first + "=" + each_pair.second;

	}
	else if (num == 6)//STREX
	{
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += ARM_my_insn[ea2ARM_my_insn[ea]].operand2+";";
	}
	else if (num == 1||num==7)//If the instruction is a conditional jump instruction. Or Instruction is like MOVEEQ, MOVNE 
	{
		qstring Mnemq;
		std::string Mnem;
		ea_t last_cmp_insn = ARM_find_backward4cmp(ea, func);
		print_insn_mnem(&Mnemq, last_cmp_insn);
		Mnem = Mnemq.c_str();
		//Now we need to process differently for test rax, 8 and test rax, rbx
		std::string operand1_;
		std::string operand1 = ARM_get_operand(last_cmp_insn, 1);
		int op1_type = get_optype(last_cmp_insn, 1);
		if (op1_type == 5)//constant
			operand1_ = operand1;
		else
			operand1_ = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand1;
		if (Mnem.find("CMP") != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " cmp ", func);
		else if (Mnem.find("SUBS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " sub ", func);
		else if (Mnem.find("SBCS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " sbb ", func);
		else if(Mnem.find("RSBS") != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " rsb ", func);
		else if (Mnem.find("TST") != -1)
		{
			if (ARM_get_operand(last_cmp_insn, 1) == ARM_get_operand(last_cmp_insn, 0))//Case likt test rax,rax
				ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = "("+ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0 + " cmp 0)";
			else//Case like test rax, rbx
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " and ", func);
		}
		else if(Mnem.find("CMN")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " add ", func);
		else if(Mnem.find("AND") != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " and ", func);
		//For some instance, 'or' as the last comparison instruction, can be testing if two conditions are all true. e.g.,
		//cmp edx,5
		//setnz al
		//cmp eax,6
		//setz cl
		//and al, cl 
		else if(Mnem.find("ORRS") != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_further_investigate_this_branch(last_cmp_insn, func);
		else if (Mnem.find("TEQ")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " xor ", func);
		else if(Mnem.find("EORS") != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " xor ", func);
		else if(Mnem.find("ADDS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " add ", func);
		else if (Mnem.find("ADCS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " adc ", func);
		else if(Mnem.find("MULS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0;
		else if(Mnem.find("RSBS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " rsb ", func);
		else if ( Mnem.find("RSCS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_check_for_last_last_and_or(last_cmp_insn, " rsc ", func);
		else if(Mnem.find("BICS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0;
		else if(Mnem.find("ORNS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_further_investigate_this_branch(last_cmp_insn, func);
		else if(Mnem.find("ASRS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0;
		else if(Mnem.find("LSRS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0;
		else if(Mnem.find("LSLS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0;
		else if(Mnem.find("RRXS")!=-1)
			ARM_my_insn_IR[ea2ARM_my_insn[last_cmp_insn]] = ARM_my_insn[ea2ARM_my_insn[last_cmp_insn]].operand0;

	}
	else if (num == 2)//BL
	{
		std::vector <std::string> parameters;
		std::string function_name = "RETURN_" + dec2hex(ea);
		parameters = ARM_look_for_parameters(ea, func);
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += function_name + " (";
		for (int i = 0;i < parameters.size();i++)
		{
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] += parameters[i] + ",";
		}
		int last_comma = ARM_my_insn_IR[ea2ARM_my_insn[ea]].rfind(',');
		if (last_comma != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[ea]][last_comma] = ' ';
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += ");";
	}
	else if (num == 5)//B reg
	{
		std::vector <std::string> parameters;
		std::string function_name = ARM_my_insn[ea2ARM_my_insn[ea]].operand0;
		parameters = ARM_look_for_parameters(ea, func);
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += function_name + " (";
		for (int i = 0;i < parameters.size();i++)
		{
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] += parameters[i] + ",";
		}
		int last_comma = ARM_my_insn_IR[ea2ARM_my_insn[ea]].rfind(',');
		if (last_comma != -1)
			ARM_my_insn_IR[ea2ARM_my_insn[ea]][last_comma] = ' ';
		ARM_my_insn_IR[ea2ARM_my_insn[ea]] += ");";
	}
	else if (num == 3)//iterator
	{
		//ARM_iterator_handler_v1(ea, Mnem, op0_type, op1_type, op2_type);
	}
	else if (num == 4)//STM
	{
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters0)
			ARM_my_insn_IR[ea2ARM_my_insn[ea]] += "["+each_pair.first + "]=" + each_pair.second+";";
	}
}


void ARM_print_to_file(ea_t ea, std::string working_path,func_t* func)
{
	std::string filename = working_path+ "\\" + std::to_string(file_num) + "_output.txt";
	//std::string filename = "C:\\Users\\nuc\\Desktop\\" + std::to_string(file_num) + "_output.txt";
	std::string each_insn;
	std::vector <std::string> content;
	qstring disasm;
	FILE* MyFile = qfopen(filename.c_str(), "wb");
	if (file_num == 31)
		int i = 2;
	if (MyFile == NULL)
		warning("qfopen fail!");
	for (ea_t index = func->start_ea;index < func->end_ea;index = find_code(index, SEARCH_DOWN | SEARCH_NEXT))
	{

		generate_disasm_line(&disasm, index, GENDSM_REMOVE_TAGS);
		each_insn = dec2hex(index) + ";;	" + disasm.c_str() + "		" + ARM_my_insn[ea2ARM_my_insn[index]].operand0 + ", " + ARM_my_insn[ea2ARM_my_insn[index]].operand1;
		//each_insn += "		" + IR_reserve_insns[ea2x64_my_insn[index]];
		each_insn += "		;;";
		//if (ARM_iterate_mark[ea2ARM_my_insn[ea]] == '{')
			//each_insn += '{';
		each_insn += ARM_my_insn_IR[ea2ARM_my_insn[index]];
		//if (ARM_iterate_mark[ea2ARM_my_insn[ea]] == '}')
			//each_insn += '}';
		each_insn+="\n";
		content.push_back(each_insn);

	}
	//std::reverse(content.begin(), content.end());
	for (ea_t index = 0;index < content.size();index++)
		if (qfwrite(MyFile, content[index].c_str(), content[index].size()) != content[index].size())
			warning("qfwrite failed!");

	qfclose(MyFile);
	//file_num++;
	ARM_clear_each_random_run();
}

void ARM_clear_each_random_run()
{
	ARM_my_insn.clear();
	insn_last_insn.clear();
	ea2ARM_my_insn.clear();
	ARM_my_insn_IR.clear();
}

void ARM_print_IR_file(std::string working_path,func_t* func)
{
	ea_t next_ea, next_ea1;
	std::string next_ea_s, next_ea1_s;
	std::string filename = working_path+"\\IR_output.txt";
	FILE* MyFile = qfopen(filename.c_str(), "wb");
	if (MyFile == NULL)
		warning("qfopen fail!");
	std::string tmp;
	for (ea_t ea = func->start_ea;ea < func->end_ea;ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		next_ea = get_first_cref_from(ea);
		next_ea1 = get_next_cref_from(ea, next_ea);
		if (next_ea > func->end_ea || next_ea < func->start_ea)
			next_ea = -1;
		if (next_ea1 > func->end_ea || next_ea1 < func->start_ea)
			next_ea1 = -1;
		if (next_ea != -1)
			next_ea_s = dec2hex(next_ea);
		else
			next_ea_s = "";
		if (next_ea1 != -1)
			next_ea1_s = dec2hex(next_ea1);
		else
			next_ea1_s = "";
		tmp = dec2hex(ea) +"-->"+next_ea_s+","+next_ea1_s+ "\n"; 
		if (qfwrite(MyFile, tmp.c_str(), tmp.size()) != tmp.size())
			warning("qfwrite failed!");

	}
	qfclose(MyFile);
}

void ARM_delete_all_hash_tag(func_t* func)
{
	int hash_tag_index;
	for (ea_t index = func->start_ea;index <= func->end_ea;index = find_code(index, SEARCH_DOWN | SEARCH_NEXT))
	{
		hash_tag_index = ARM_my_insn[ea2ARM_my_insn[index]].operand0.find('#');
		while (hash_tag_index != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[index]].operand0 = ARM_my_insn[ea2ARM_my_insn[index]].operand0.replace(hash_tag_index, 1, "");
			hash_tag_index = ARM_my_insn[ea2ARM_my_insn[index]].operand0.find('#');
		}
		hash_tag_index = ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('#');
		while (hash_tag_index != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[index]].operand1 = ARM_my_insn[ea2ARM_my_insn[index]].operand1.replace(hash_tag_index, 1, "");
			hash_tag_index = ARM_my_insn[ea2ARM_my_insn[index]].operand1.find('#');
		}
	}
	for (ea_t index = func->start_ea;index <= func->end_ea;index = find_code(index, SEARCH_DOWN | SEARCH_NEXT))
	{
		hash_tag_index = ARM_my_insn_IR[ea2ARM_my_insn[index]].find('#');
		while (hash_tag_index != -1)
		{
			ARM_my_insn_IR[ea2ARM_my_insn[index]] = ARM_my_insn_IR[ea2ARM_my_insn[index]].replace(hash_tag_index, 1, "");
			hash_tag_index = ARM_my_insn_IR[ea2ARM_my_insn[index]].find('#');
		}
	}
}

void ARM_display_translate_result(func_t* func) {
	for (ea_t i = func->start_ea;i < func->end_ea;i = find_code(i, SEARCH_DOWN | SEARCH_NEXT))
	{
		//if (ARM_my_insn_IR[ea2ARM_my_insn[i]] != "")
			set_cmt(i, ARM_my_insn_IR[ea2ARM_my_insn[i]].c_str(), false);
	}
}

void ARM_translate_one_insn(ea_t ea,func_t* func)
{
	qstring Mnemq;
	std::string Mnem;
	int ea_operand_num;
	int op0_type = 0, op1_type = 0, op2_type = 0, op3_type;
	std::string operand0, operand1, operand2, operand3;


	
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	ea_operand_num = count_ea_operands(ea);
	if (ea == 0x1204)
		int bp = 0;
	if (ea_operand_num == 1)
	{
		operand0 = ARM_get_operand(ea, 0);
		op0_type = get_optype(ea, 0);

	}
	else if (ea_operand_num == 2)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);

	}
	else if (ea_operand_num == 3)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = ARM_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
	}

	else if (ea_operand_num == 4)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = ARM_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
		operand3 = ARM_get_operand(ea, 3);
		op3_type = get_optype(ea, 3);
	}

	if (Mnem.find("STREX") != -1) { ARM_sub_IR(6, ea, func); }
	else if (Mnem.find("STR") != -1) { ARM_sub_IR(0, ea, func); }
	else if (Mnem.find("STM") != -1) { ARM_sub_IR(4, ea, func); }
	else if (Mnem.find("TST") != -1 || Mnem.find("CMP") != -1) { ARM_sub_IR(1, ea, func); }
	else if (Mnem == "BL") { ARM_sub_IR(2, ea, func); }
	else if (Mnem.find('B') == 0 && op0_type == 1) { ARM_sub_IR(5, ea, func); }
	

}

//If the instruction is like MOVEQ, MOVNE etc but not a brunch instruction such as BNE
bool ARM_is_conditional_insn(ea_t ea)
{
	if (ea == 0x9f7e8)
		int breakp = 1;
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	std::string cc;//Last two suffix
	cc[0] = Mnem[Mnem.size() - 2];
	cc[1] = Mnem[Mnem.size() - 1];
	if (Mnem.find("B") != 0 && ((cc=="EQ"&& Mnem!="TEQ") || cc=="NE" ||cc=="CS"|| cc=="HS"||cc=="CC"|| cc=="LO" \
		||cc=="MI"||cc=="PL"|| cc=="VS"|| cc=="VC"|| cc=="HI"|| cc=="LS" \
		||cc=="GE"|| cc=="LT"|| cc=="GT"|| cc=="LE"))
		return true;
	else
		return false;
}

//If the instruction is like MOVEQ, MOVNE etc but not a brunch instruction such as BNE
bool ARM_contains_conditional_compare(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	std::string cc;//Last two suffix
	std::string root;
	if (Mnem.size() >= 2)
	{
		cc = Mnem.substr(Mnem.size() - 2, 2);
		root= Mnem.substr(0,Mnem.size()-2);
	}
	else
		cc = "";
	if ((cc == "EQ" && Mnem != "TEQ") || cc == "NE" || cc == "CS" || cc == "HS" || cc == "CC" || cc == "LO" \
		|| cc == "MI" || cc == "PL" || cc == "VS" || cc == "VC" || cc == "HI" || cc == "LS"\
		|| cc == "GE" || cc == "LT" || cc == "GT" || cc == "LE")
	{
		if (ARM_is_common_Mnem(root))//This is to prevent case like ADCS
			return true;
		else//This is to prevent case like ADCS
			return false;
	}
	else
		return false;
}

//test whether this instruction is like ADD PC,PC ... If so, there are more than 2 branches after this instruction
bool ARM_is_add_pc_insn(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (Mnem.find("ADD") != -1 && ARM_get_operand(ea, 0) == "PC")
		return true;
	return false;
}

ea_t ARM_find_forward4key_IR(ea_t ea, func_t* func)
{
	for (ea_t index = ea;index < func->end_ea && ea != BADADDR; index = get_first_cref_from(index))
	{
		if (ARM_my_insn_IR[ea2ARM_my_insn[index]] != "")
			return index;
	}
}

ea_t ARM_find_backward4cmp(ea_t ea, func_t* func)
{
	qstring Mnemq;
	std::string Mnem;
	for (ea_t index = insn_last_insn[ea];index >= func->start_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		if (Mnem.find("CMP") != -1 || Mnem.find("TST") != -1 || Mnem.find("AND") != -1 || Mnem.find("ORRS") != -1 || Mnem.find("EORS") != -1\
			|| Mnem == "ADCS" || Mnem == "ADDS" || Mnem == "SUBS" || Mnem == "SBCS" || Mnem == "MULS" || Mnem == "TEQ"  \
			|| Mnem == "RSBS" || Mnem == "RSCS" || Mnem == "TEQ" || Mnem == "BICS" || Mnem == "ORNS" || Mnem == "ASRS"\
			|| Mnem == "LSRS" || Mnem == "LSLS" || Mnem == "RRXS"||Mnem.find("CMN")!=-1||Mnem.find("TEQ")!=-1||Mnem=="MOVS")
			return index;
	}
	return 0;//If not found, return 0
}

//For cmp instruction, we need to further check its operands whether come from some logic instructions. In this case,
//This cmp can be actually comparing whether two conditions hold. Thus a braching-like instruction.
//Parameter 1: the comparison instruction before conditional instruction ,say cmp.
//Parameter 2: the comparison instruction Mnem, say cmp.
//Parameter 3: original comparison instruction operand0.
//Parameter 4: original comparison instruction oeprand1.
//Parameter 5: func.
//returns the correct IR string for this comparison instruction.
std::string ARM_check_for_last_last_and_or(ea_t last_insn, std::string Mnem, func_t* func)
{
	if (last_insn == 0x1956fc)
		int breakp = 1;
	std::string operand0_, operand1_,tmp;
	operand0_ = ARM_get_two_operands_original_value(last_insn,func)[0];
	operand1_ = ARM_get_two_operands_original_value(last_insn, func)[1];

	//If this comparison is a conditional instruction, e.g, cmpeq.
	if (ARM_contains_conditional_compare(last_insn))
		return  ARM_explain_cc(last_insn, func,true);
	//If this comparison instruction is not a braching-like instruction. i.e., not to test whether two conditions hold.
	else if (!ARM_look_backward_4_conditional(last_insn, func, true))
	{
		if (Mnem.find("rsb") != -1)
		{
			return  " (" + operand1_ + " sub " + operand0_ + ")";
		}
		else
			return  " (" + operand0_ + Mnem + operand1_ + ")";
	}
	//If this comparison instruction is a braching-like instruction. i.e., test whether two conditions hold.
	else
	{
		int ea_operand_num = count_ea_operands(last_insn);
		if (ea_operand_num == 2)
		{
			operand0_ = ARM_get_operand(last_insn,0);
			operand1_= ARM_get_operand(last_insn, 1);
		}
		else if (ea_operand_num == 3)
		{
			operand0_ = ARM_get_operand(last_insn, 1);
			operand1_ = ARM_get_operand(last_insn, 2);
		}
		if (Mnem.find("rsb") != -1)
		{
			tmp = operand0_;
			operand0_ = operand1_;
			operand1_ = tmp;
			Mnem = " sub ";
		}
		ea_t last_last_and_or_insn = ARM_find_backward4define(operand0_, last_insn, func);
		if (last_last_and_or_insn!=-1)
			operand0_ = ARM_translate_branching_insn(last_last_and_or_insn, func,true, operand0_);
		last_last_and_or_insn = ARM_find_backward4define(operand1_, last_insn, func);
		if (last_last_and_or_insn!=-1)
			operand1_ = ARM_translate_branching_insn(last_last_and_or_insn, func,true, operand0_);
		return "(" + operand0_ + Mnem + operand1_ + ")";
	}
}

//Despite two or three operands this address has, it will return the two operands. Since we only focus on comparing and arithmatic instructions,
//there should only be 2-3 operands in the instruction.
std::vector <std::string> ARM_get_two_operands_original_value(ea_t ea,func_t* func)
{
	if (ea == 0x17c04)
		int breakp = 1;
	int op0_type, op1_type,op2_type;
	std::string operand0, operand1, operand2;
	op0_type = get_optype(ea, 0);
	op1_type = get_optype(ea, 1);
	op2_type = get_optype(ea, 2);
	operand0 = ARM_get_operand(ea, 0);
	operand1 = ARM_get_operand(ea, 1);
	operand2 = ARM_get_operand(ea, 2);
	std::vector <std::string> result_operands;
	int ea_operand_num = count_ea_operands(ea);
	qstring Mnemq;
	std::string Mnem;
	if (ea_operand_num == 3)
	{
		//add operand1
		if (op1_type == 5)
			result_operands.push_back(operand1);
		else if(op1_type==1||op1_type==8|| op1_type == 3 || op1_type == 4)
			result_operands.push_back(ARM_my_insn[ea2ARM_my_insn[ea]].operand1);
		//add operand2
		if(op2_type==5)
			result_operands.push_back(operand2);
		else if (op2_type == 1 || op2_type == 8||op2_type == 3 || op2_type == 4)
			result_operands.push_back(ARM_my_insn[ea2ARM_my_insn[ea]].operand2);
		return result_operands;
	}
	else if (ea_operand_num == 2)
	{
		//add operand1
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("LDM") != -1|| Mnem.find("LDR") != -1)
		{
			result_operands.push_back("");
		}
		else if (Mnem.find("TST")!=-1 || Mnem.find("CMP")!=-1 || Mnem.find("TEQ")!=-1 || Mnem.find("CMN")!=-1)//If Mnem are testing, we can directly aquire from their .operand0
			result_operands.push_back(ARM_my_insn[ea2ARM_my_insn[ea]].operand0);
		else if (op0_type == 1)//If Mnem not testing, we need to get original value before calculating by this Mnem. The value should be stored in their "origiinal" key
		{
				result_operands.push_back(ARM_my_insn[ea2ARM_my_insn[ea]].parameters0["original"]);
		}
		else
		{
			result_operands.push_back("");
		}
		//add operand2
		if(Mnem.find("LDM")!=-1|| Mnem.find("LDR") != -1)
			result_operands.push_back("");
		else if (op1_type == 5)//operand1 is a number
			result_operands.push_back(operand1);
		else if (op1_type == 1 || op1_type == 8 || op1_type == 3 || op1_type == 4)//operand1 is reg, disp or shift
		{
			if(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=")!=-1)
				result_operands.push_back(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=")));
			else
				result_operands.push_back(ARM_my_insn[ea2ARM_my_insn[ea]].operand1);
		}
		else
		{
			result_operands.push_back("");
		}
		/*else if (op1_type == 9)//operand1 is {reg1,reg2...}
		{
			for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters1)
				result_operands.push_back("[" + each_pair.first + "]=" + each_pair.second + ";");
		}*/
		return result_operands;
	}
	else if (ea_operand_num == 1)
	{
		result_operands.push_back("");
		result_operands.push_back("");
		return result_operands;
	}
}

//For an address ea and its number 'index' operand, if the operand comes from a 'and' or 'or' instruction,
//return the address of that 'and' or 'or' instruction. Return -1 if not from 'and' or 'or' instruction.
/*ea_t ARM_operand_from_and_or_insn(int index, ea_t ea, func_t* func)
{
	int op_type;
	std::string operand, tmp;
	qstring Mnemq;
	std::string Mnem;
	op_type = get_optype(ea, index);
	if (op_type != 1)//not register
		return -1;
	operand = ARM_get_operand(ea, index);
	for (ea_t index1 = insn_last_insn[ea];index1 != func->start_ea;index1 = insn_last_insn[index1])
	{
		print_insn_mnem(&Mnemq, index1);
		Mnem = Mnemq.c_str();
		tmp = ARM_get_operand(index1, 0);
		if (tmp == operand)
			if (Mnem.find("AND")!=-1 || Mnem.find("ORR") != -1||Mnem.find("ORN")!=-1)
				return index;
			else
				return -1;
	}
	return -1;
}*/

// For branching - like 'and' or 'or' instructions, we translate them into more comprehensive format to facilitate similarity compare.
std::string ARM_translate_branching_insn(ea_t ea, func_t* func,bool ea_is_last_cmp,std::string operand)
{
	if (ea == 0x9f7e8)
		int breakp = 1;
	qstring Mnemq;
	std::string Mnem, result;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string left, right;
	ea_t last_define_ea;
	std::string operand0, operand1;
	int op0_type = get_optype(ea, 0);
	int op1_type = get_optype(ea, 1);
	operand0 = ARM_get_two_operands_original_value(ea,func)[0];
	operand1 = ARM_get_two_operands_original_value(ea,func)[1];
	if ((Mnem.find("AND")!=-1 || Mnem.find("ORR")!=-1|| Mnem.find("ORN") != -1) && ARM_look_backward_4_conditional(ea, func, ea_is_last_cmp))//if current address contain conditional value
	{
		last_define_ea = ARM_find_backward4define(operand0, ea, func);
		if ((op0_type==1|| op0_type==8)&& last_define_ea!=-1)
			left = ARM_translate_branching_insn(last_define_ea, func,false, operand0);
		else
			left = operand0;
		last_define_ea = ARM_find_backward4define(operand1, ea, func);
		if ((op1_type == 1 || op1_type == 8)&& last_define_ea!=-1)
			right = ARM_translate_branching_insn(last_define_ea, func,false, operand1);
		else
			right = operand1;
		if (Mnem.find("AND")!=-1)
			result = "(" + left + " and " + right + ")";
		else if (Mnem.find("ORR")!=-1)
			result = "(" + left + " or " + right + ")";
		else if (Mnem.find("ORN") != -1)
			result = "(" + left + " or !(" + right + "))";
		return result;
	}
	else if (Mnem.find("MOV")!=-1)
	{
		if (op1_type == 1)
		{
			last_define_ea = ARM_find_backward4define(operand1, ea, func);
			if (last_define_ea != -1)
				return ARM_translate_branching_insn(last_define_ea, func, false, operand1);
			else
				return operand1;
		}
		else if (op1_type == 5)
			return operand1;
		else if (op1_type == 8)
			return operand0;
	}
	else if (Mnem.find("MVN")!=-1)
	{
		return operand0;
	}
	else if (Mnem.find("LDR")!=-1|| Mnem.find("LDRD")==-1)
	{
		/*if (op1_type == 1)
		{
			last_define_ea = ARM_find_backward4define(operand1, ea, func);
			if (last_define_ea != -1)
				return ARM_translate_branching_insn(last_define_ea, func, false, operand1);
			else
				return operand1;
		}
		else if (op1_type == 3 || op1_type == 4 || op1_type == 2)*/
			return ARM_my_insn[ea2ARM_my_insn[ea]].operand0;
	}
	else if (Mnem.find("LDM")!=-1)
	{
		for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[ea]].parameters1)//for each key value pair stored in .parameters1
			if (each_pair.first == operand)//if there is some register we are looking for
			{
				result = each_pair.second;
				return result;
			}
	}
	else if (Mnem.find("LDRD")!=-1)
	{
		if (operand0 == operand)
		{
			return ARM_my_insn[ea2ARM_my_insn[ea]].operand0;
		}
		else if (operand1 == operand)
		{
			return ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
		}
	}
	//since it is not possible to return a STR or STRD insn in a ARM_find_backward4define function, it is not possible to meet them in thins function thus we \
	do not need to process them.
	/*else if (Mnem.find("STR")!=-1)
	{
		last_define_ea = ARM_find_backward4define(operand0, ea, func);
		if (last_define_ea != -1)
			return ARM_translate_branching_insn(last_define_ea, func,false, operand0);
		else
			return operand0;
	}
	else if (Mnem == "STRD")
	{
		if (operand0 == operand)
		{
			last_define_ea = ARM_find_backward4define(operand0, ea, func);
			if (last_define_ea != -1)
				return ARM_translate_branching_insn(last_define_ea, func, false, operand0);
			else
				return operand0;
		}
		else if (operand1 == operand)
		{
			last_define_ea = ARM_find_backward4define(operand1, ea, func);
			if (last_define_ea != -1)
				return ARM_translate_branching_insn(last_define_ea, func, false, operand1);
			else
				return operand1;
		}
	}*/
	else//if current address is source instruction of conditional value.
	{
		operand0 = ARM_get_two_operands_original_value(ea,func)[0];
		operand1 = ARM_get_two_operands_original_value(ea, func)[1];
		if (Mnem.find("EOR") != -1)
		{
			if (ARM_get_operand(ea, 1) != ARM_get_operand(ea, 2))//EOR r3,r0,r1
				result = "(" + operand0 + Mnem + operand1 + ")";
			else//EOR r1,r0,r0
				result = "0";
		}
		else if (Mnem.find("ADD")!=-1)
			result = "(" + operand0 + " add " + operand1 + ")";
		else if (Mnem.find("ADC")!=-1)
			result = "(" + operand0 +  " adc " + operand1 + ")";
		else if (Mnem.find("SUB")!=-1)
			result = "(" + operand0 + " sub " + operand1 + ")";
		else if (Mnem.find("SDC")!=-1)
			result = "(" + operand0 + " sbb " + operand1 + ")";
		else if (Mnem.find("RSB")!=-1)
			result = "(" + operand1 + " sub " + operand0 + ")";
		else if (Mnem.find("RSC")!=-1)
			result = "(" + operand1 + " sbb " + operand0 + ")";
		else if (ARM_contains_conditional_compare(ea))
			result = ARM_explain_cc(ea, func, ea_is_last_cmp);
		return result;
	}
}

//Look backward to find out whether the 'and' or 'or' instruction is dependent on some conditional instructions.
//We assume a set of condition instructions are connected by multiple 'and' and 'or' instructions. The cases might be ensure all the conditions holds or only if one condition holds.
//Yhus the last instruction might be 'oring'/'anding' the n-1 th conditions with the last (n th) condition. The last instruction can also be comparing the n th conditions with some magic value.
//So we need to starting from this last comparing instruction and look up backward to find out whether its value comes from some conditional instructions such as moveq etc. Note that sub,eor 
//can also function like cmp... moveq thus sub, eor, add are also condidered as conditional instructions.
//Parameter 1: the address of 'and' or 'or' instruction.
//Parameter 2: function.
//Parameter 3: whether instruction ea is the starting checking instruction (i.e., the last comparing instruction )
bool ARM_look_backward_4_conditional(ea_t ea, func_t* func,bool ea_is_last_cmp_insn)
{
	if (ea == 0xb10)
		int breakp = 1;
	bool result;
	qstring Mnemq;
	std::string Mnem;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	ea_t last_define_ea;
	if (Mnem.find("ORR")!=-1||Mnem.find("ORN")!=-1|| (Mnem.find("AND") != -1 && ARM_get_operand(ea, 0) != ARM_get_operand(ea, 1)))
	{
		std::vector <std::string> operands_list = ARM_get_operands_list(ea);
		for (int index = 0;index < operands_list.size();index++)
		{
			last_define_ea = ARM_find_backward4define(operands_list[index], ea, func);
			if (last_define_ea == -1)//One operand's definition not found, skip to next operand
				continue;
			result = ARM_look_backward_4_conditional(last_define_ea, func,false);
			if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
				return true;
		}
	}

	else if (Mnem.find("SUB") != -1 || Mnem.find("ADD") != -1 || Mnem.find("EOR") != -1|| (Mnem.find("AND") != -1 && ARM_get_operand(ea, 0) == ARM_get_operand(ea, 1)))
	{
		if (ea_is_last_cmp_insn == true)//If this instruction's Mnem is sub, add or eor, and it is the first searching instruction (i.e., the last comparing instruction), then\
										 search all its operands.
		{
			std::vector <std::string> operands_list = ARM_get_operands_list(ea);
			for (int index = 0;index < operands_list.size();index++)
			{
				last_define_ea = ARM_find_backward4define(operands_list[index], ea, func);
				if (last_define_ea == -1)//One operand's definition not found, skip to next operand
					continue;
				result = ARM_look_backward_4_conditional(last_define_ea, func,false);
				if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
					return true;
			}
		}
		else if (ea_is_last_cmp_insn == false)//If this instruction is not the first searching instruciton (i.e., the last comparing instruction), then this is a conditional instruction.
		{
			return true;
		}
	}
	else if (Mnem.find("MOV")!=-1)
	{
		int op1_type = get_optype(ea, 1);
		if (op1_type == 5)
			return false;
		else if (op1_type == 1)
		{
			last_define_ea = ARM_find_backward4define(ARM_get_operand(ea, 1), ea, func);
			if (last_define_ea == -1)//One operand's definition not found, skip to next operand
				return false;
			result = ARM_look_backward_4_conditional(last_define_ea, func,false);
			if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
				return true;
		}
	}
	/*else if (Mnem.find("STR")!=-1)
	{
		last_define_ea = ARM_find_backward4define(ARM_get_operand(ea, 0), ea, func);
		if (last_define_ea == -1)//One operand's definition not found, skip to next operand
			return false;
		result = ARM_look_backward_4_conditional(last_define_ea, func,false);
		if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
			return true;
	}*/
	else if (Mnem.find("LDR")!=-1)//This includes LDRD
	{
		//last_define_ea = ARM_find_backward4define(ARM_get_operand(ea, 1), ea, func);
		//if (last_define_ea == -1)//One operand's definition not found, skip to next operand
			return false;
		//result = ARM_look_backward_4_conditional(last_define_ea, func,false);
		//if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
		//	return true;
	}
	//As to STR, STRD, and STM, since we can not find them in ARM_find_backward4define, it is not possible to meet them in this function thus we do not process them.
	else if (Mnem.find("CMP")!=-1 || Mnem.find("TST")!=-1)
	{
		std::string operand1 = ARM_get_operand(ea, 1);
		std::string operand0 = ARM_get_operand(ea, 0);
		int op0_type = get_optype(ea, 0);
		int op1_type = get_optype(ea, 1);
		if (op0_type == 1)
		{
			last_define_ea = ARM_find_backward4define(operand0, ea, func);
			if (last_define_ea != -1)
			{
				result = ARM_look_backward_4_conditional(last_define_ea, func,false);
				if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
					return true;
			}
		}
		if (op1_type == 1 || op1_type == 3 || op1_type == 4|| op1_type == 8)
		{
			last_define_ea = ARM_find_backward4define(operand1, ea, func);
			if (last_define_ea != -1)
			{
				result = ARM_look_backward_4_conditional(last_define_ea, func,false);
				if (result == true)//Once we find one value is dependent on conditional instruction, we return true.
					return true;
			}
		}
	}
	else if ((Mnem.find("EQ") != -1&&Mnem!="TEQ") || Mnem.find("NE") != -1 || Mnem.find("CS") != -1 || Mnem.find("HS") != -1\
		|| Mnem.find("CC") != -1 || Mnem.find("LO") != -1 || Mnem.find("MI") != -1 || Mnem.find("PL") != -1\
		|| Mnem.find("VS") != -1 || Mnem.find("VC") != -1 || Mnem.find("HI") != -1 || Mnem.find("LS") != -1\
		|| Mnem.find("GE") != -1 || Mnem.find("LT") != -1 || Mnem.find("GT") != -1 ||Mnem.find("LE") != -1)
		return true;
	return false;
}

//Given a operand at address ea, find from ea backward to find its defined address.
ea_t ARM_find_backward4define(std::string operand, ea_t ea, func_t* func)
{
	std::string operand0,operand1;
	qstring Mnemq;
	std::string Mnem;
	for (ea_t index = insn_last_insn[ea];index >= func->start_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		operand0 = ARM_get_operand(index,0);
		operand1 = ARM_get_operand(index, 1);
		if (Mnem.find("LDM") != -1)
		{
			for (const auto each_pair : ARM_my_insn[ea2ARM_my_insn[index]].parameters1)//for each key value pair stored in .parameters1
				if (each_pair.first == operand)//if there is some register we are looking for
				{
					return index;
				}
		}
		else if (Mnem.find("LDRD") != -1)
		{
			if (operand0 == operand|| operand1 == operand)
				return index;
		}
		else if (operand0 == operand&&Mnem.find("CMP")==-1&&Mnem.find("TST")==-1&&count_ea_operands(index)<4 && Mnem.find("STR")==-1 && Mnem.find("STM") == -1)
			return index;
	}
	return -1;
}


//Given an address, return a list of all its operands if the operand is register or disp. Because we are looking for operands coming from previous logic 'and' or
//'or' instructions. Thus we only check registers. Disp and num should be ignored.
std::vector<std::string> ARM_get_operands_list(ea_t ea)
{
	std::vector<std::string> operands_list;
	int ea_operand_num;
	std::string operand0, operand1, operand2;
	int op0_type, op1_type, op2_type;
	ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
	{
		operand0 = ARM_get_operand(ea, 0);
		op0_type = get_optype(ea, 0);
		if (op0_type == 1 || op0_type == 8 || op0_type == 3 || op0_type == 4)
			operands_list.push_back(operand0);
		else operands_list.push_back("");
		return operands_list;
	}
	else if (ea_operand_num == 2)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		if (op0_type == 1 || op0_type == 8 || op0_type == 3 || op0_type == 4)
			operands_list.push_back(operand0);
		else operands_list.push_back("");
		if (op1_type == 1 || op1_type == 8 || op1_type == 3 || op1_type == 4)
			operands_list.push_back(operand1);
		else operands_list.push_back("");
		return operands_list;
	}
	else if (ea_operand_num == 3)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = ARM_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
		if (op1_type == 1 || op1_type == 8 || op1_type == 3 || op1_type == 4)
			operands_list.push_back(operand1);
		else operands_list.push_back("");
		if (op2_type == 1 || op2_type == 8 || op2_type == 3 || op2_type == 4)
			operands_list.push_back(operand2);
		else operands_list.push_back("");
		return operands_list;
	}
}

//Translate conditional comparison instruction. e.g., moveq, addnz.
std::string ARM_explain_cc(ea_t ea, func_t* func,bool ea_is_last_cmp)
{
	qstring Mnemq;
	std::string Mnem, result;
	ea_t last_cmp = ARM_find_backward4cmp(ea, func);
	print_insn_mnem(&Mnemq, last_cmp);
	Mnem = Mnemq.c_str();

	//We firstly get operand0 and operand1 correctly.
	std::string operand0 = ARM_get_two_operands_original_value(last_cmp, func)[0];
	std::string operand1 = ARM_get_two_operands_original_value(last_cmp, func)[1];

 	if (Mnem.find("EOR") != -1)
	{
		if (ARM_get_operand(last_cmp, 1) != ARM_get_operand(last_cmp, 2))//EOR r2,r0,r1
			result = "(" + operand0 + " xor " + operand1 + ")";
		else if (ARM_get_operand(last_cmp, 1) == ARM_get_operand(last_cmp, 2))//EOR r3.r1,r1
			return "0";
	}
	else if (Mnem.find("ADD") != -1 || Mnem.find("CMN") != -1)
		result = "(" + operand0 + " add " + operand1 + ")";
	else if (Mnem.find("SUB") != -1)
		result = "(" + operand0 + " sub " + operand1 + ")";
	else if (Mnem.find("RSB") != -1)
		result = "(" + operand1 + " sub " + operand0 + ")";
	else if (Mnem.find("TST") != -1)
	{
		if (ARM_get_operand(last_cmp, 0) == ARM_get_operand(last_cmp, 1))//Case like test rax,rax
			result = "(" + operand0 + " cmp 0" + ")";
		else//Case like test rax,rbx
			result = "(" + operand0 + " test " + operand1 + ")";
	}
	else if (Mnem.find("CMP")!=-1)
		result = "(" + operand0 + " cmp " + operand1 + ")";
	else if(Mnem.find("TEQ") != -1)
		result = "(" + operand0 + " xor " + operand1 + ")";
	else if (Mnem == "MULS")
		result = "(" + operand0 + " mul " + operand1 + ")";
	else if (Mnem == "RSBS")
		result = "(" + operand1 + " sub " + operand0 + ")";
	else if (Mnem == "RSCS")
		result = "(" + operand1 + " sub " + operand0 + "-CF)";
	else if (Mnem == "BICS")
		result = "(" + operand0 + " and !(" + operand1 + "))";
	else if (Mnem == "ORNS")
		result = "(" + operand0 + " or !(" + operand1 + "))";
	else if (Mnem == "ASRS")
		result = "(" + operand0 + " >> " + operand1 + ")";
	else if (Mnem == "LSRS")
		result = "(" + operand0 + " >> " + operand1 + ")";
	else if (Mnem == "LSLS")
		result = "(" + operand0 + " << " + operand1 + ")";
	else if (Mnem == "RRXS")
		result = "(" + operand0 + " >> "+ "1)";
	else if (Mnem.find("ORR")!=-1 || Mnem.find("AND")!=-1||Mnem.find("ORN")!=-1)
		result = ARM_translate_branching_insn(last_cmp, func, ea_is_last_cmp,"");
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	operand0 = ARM_get_two_operands_original_value(ea, func)[0];
	operand1 = ARM_get_two_operands_original_value(ea, func)[1];
	result += ' '+Mnem+" "+operand1;
	result = "(" + result + ")";
	return result;
}

//This is to handle when last comparison instruction is 'and' or 'or'. This function will look backward for 'and' or 'or''s
//operands. If it turns out that some operand is dependent on some conditional instruction, this means this 'and' or 'or' 
//instruction is a branching-like instruction that connect conditions.
std::string ARM_further_investigate_this_branch(ea_t ea, func_t* func)
{
	bool result = ARM_look_backward_4_conditional(ea, func,true);
	if (result == true)
	{
		return ARM_translate_branching_insn(ea, func,true,"");
	}
	else
		return ARM_my_insn[ea2ARM_my_insn[ea]].operand0;

}

bool ARM_is_common_Mnem(std::string root)
{
	std::vector <std::string >ARM_common_Mnem= { "BIC" ,"BFC" ,"BFI","MOVT","MOVW","MOV","MVN","MVT","LDR","LDRD","ADR","ADD","ADC","STREX","STR","STRD"\
		,"LDM" , "STM","SWP","TST","TEQ","CMP","CMN","SUB","SBC","RSB","RSC","AND","ORR","EOR","ORN","RBIT","REV16","REVSH","REV","ASR"\
		,"LSR","LSL","RRX","MUL","MLA","MLS","UMULL","SMULL","UMLAL","SMLAL","SMULT","SMULB","SMLAT","SMLAB","SMULW","SMLAW","SMLALT"\
		, "SMLALT","SMLALB","SMUAD","SMUSD","SMMUL","SMMLA","SMMLS","SMLAD","SMLSD","SMLALD","SMLSLD","UMAAL","ROR","CLZ","CTZ","UXT","B" };
	for (int i = 0; i < ARM_common_Mnem.size(); i++)
		if (ARM_common_Mnem[i] == root)
			return true;
	return false;
}