#include "../../Headers/value_calculate/x64_while_handler.h"
std::vector <ea_t> tmp_x64_insn_record;
std::vector <x64_my_instruction> tmp_x64_my_insn;
std::vector<std::string> x64_debug_iter_sinsn;
int x64_iterator_variable;
void x64_init_iterator_var()
{
	x64_iterator_variable = 0;
}

std::string x64_allocate_iterator_var() {
	x64_iterator_variable++;
	return "ITERATOR" + std::to_string(x64_iterator_variable);
}

/*For each loop, there must be a "source" of iteration. However complicated some instruction
might be after each iteration, there must be some very simple, single instruction that is the
source of iteration. This can be as simple as add some const in each iteration.*/
void x64_recalculate_for_while(ea_t ea, ea_t next_ea, func_t* func)
{
	if (ea == 0x1558)
		int bp = 1;
	qstring disasm;
	std::string diff;
	int loop_block_insn_num;
	x64_init_tmp_x64_insn_record(ea,next_ea);
	x64_init_tmp_x64_my_insn(ea, next_ea);
	loop_block_insn_num = tmp_x64_my_insn.size();
	//tmp_x64_insn_record.push_back(next_ea);
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(),forward_insn_last_insn.end());
	x64_iterate_mark[ea2x64_my_insn[next_ea]] = '{';
	x64_iterate_mark[ea2x64_my_insn[ea]] = '}';
	for (int index = 0;index < forward_insn_last_insn.size();index++)//second time execute the loop block to identify iterators
	{
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		x64_debug_iter_sinsn.push_back(disasm.c_str());
		tmp_x64_insn_record.push_back(forward_insn_last_insn[index]);
		x64_re_update_each_insn(forward_insn_last_insn[index], func);
		diff = x64_is_iter_source(loop_block_insn_num);
		if (diff!="") 
		{
			//iter_source.push_back(index);
			x64_replace_element_with_iterator(forward_insn_last_insn[index],diff);
		} 
		

	}
	//tmp_x64_insn_record.push_back(next_ea);
	for (int index = 0;index < forward_insn_last_insn.size();index++)//third time execute to translate all iterators
	{
		
		tmp_x64_insn_record.push_back(forward_insn_last_insn[index]);
		x64_re_update_each_insn(forward_insn_last_insn[index], func);
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		x64_debug_iter_sinsn.push_back(disasm.c_str());
		//if (x64_contain_iterators())
		//{
		//	x64_reserve_IR(index);
		//}
		
	}
	x64_tmp_copy_to_my_insn(next_ea,ea, loop_block_insn_num);
	x64_clean_tmp();
}   

/*We symbolically execute the loop for twice so that we can identify tbe invariant instructions
and the updating instructions. For invariant instructions, we just leave their constant value/expression
there. For updating expression/value,we write them in this form: ITER(...). We write their value in the
first loop in the bracket*/
void x64_recalculate_for_while_v1(ea_t ea, ea_t next_ea, func_t* func)
{
	if (ea == 0x401682)
		int breakp = 1;
	qstring disasm;
	int is_updated;
	int loop_block_insn_num;
	x64_init_tmp_x64_insn_record(ea, next_ea);
	x64_init_tmp_x64_my_insn(ea, next_ea);
	loop_block_insn_num = tmp_x64_my_insn.size();
	//tmp_x64_insn_record.push_back(next_ea);
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])//put the loop instructions in an forward array
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());//put the loop instructions in an forward array
	x64_iterate_mark[ea2x64_my_insn[next_ea]] = '{';
	x64_iterate_mark[ea2x64_my_insn[ea]] = '}';
	for (int index = 0;index < forward_insn_last_insn.size();index++)//second time execute the loop block to identify updating and invatiant instructions
	{
		if (forward_insn_last_insn[index] == 0x46cd73)
			int breakp = 1;
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		x64_debug_iter_sinsn.push_back(disasm.c_str());
		tmp_x64_insn_record.push_back(forward_insn_last_insn[index]);
		x64_re_update_each_insn(forward_insn_last_insn[index], func);
		if (tmp_x64_insn_record.size() != tmp_x64_my_insn.size())
			int breakp = 1;
		is_updated=x64_loop_updated(loop_block_insn_num);
		if (is_updated == 0)
		{
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
			std::string debug_string = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0;
			std::string debug_string1 = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1;
		}
		else if (is_updated == 1)
		{
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
			std::string debug_string1 = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1;
		}
		else if (is_updated == 2)
		{
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
			std::string debug_string = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0;
		}
		else if (is_updated == 4)//For memory write, the address and the content all get updated.
		{
			int equation_location = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.find("=");
			int len = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.length();
			std::string memory_address = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.substr(0, equation_location);
			std::string content = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.substr(equation_location + 1, len - 1 - equation_location);
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + memory_address + ")=ITER(" + content + ")";
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
		}
		else if (is_updated == 5)//For memory write, the address not change, the content get updated.)
		{
			int equation_location = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.find("=");
			int len = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.length();
			std::string memory_address = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.substr(0, equation_location);
			std::string content = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.substr(equation_location + 1, len - 1 - equation_location);
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 = memory_address + "=ITER(" + content + ")";
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
		}
		else if (is_updated == 6)//For memory write, the address get updated, content not change.)
		{
			int equation_location = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.find("=");
			int len = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.length();
			std::string memory_address = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.substr(0, equation_location);
			std::string content = x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0.substr(equation_location + 1, len - 1 - equation_location);
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + memory_address + ")=" + content;
			x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
		}
	}
	x64_clean_tmp();
}

//We record the loop instruction addresses for debugging
void x64_init_tmp_x64_insn_record(ea_t ea, ea_t next_ea)
{
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea; index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());
	for (int index =0; index < forward_insn_last_insn.size();index++)
	{
		tmp_x64_insn_record.push_back(forward_insn_last_insn[index]);
	}
}
//For debugging, We record instructions in loop in x64_debug_iter_sinsn.
//and tmp_x64_my_insn contains addresses' corresponding tag.
void x64_init_tmp_x64_my_insn(ea_t ea, ea_t next_ea)
{
	qstring disasm;
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea; index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());
	for (int index = 0;index < forward_insn_last_insn.size();index++)
	{
		tmp_x64_my_insn.push_back(x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]]);
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		x64_debug_iter_sinsn.push_back(disasm.c_str());
	}
}

//Since we have an array of loop instructions for 3 times in the array, we are trying to 
//find the source of iterator for each instruction.
//The array looks like this: insn1,insn2....insn10,insn1,insn2...insn10,insn1,insn2...insn10
//Parameter1: The length of loop instructions for once i.e, length of insn1...insn10.
std::string x64_is_iter_source(int loop_block_insn_num)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, tmp_x64_insn_record[tmp_x64_insn_record.size() - 1]);
	std::string Mnem = Mnemq.c_str();
	if (Mnem.find("add") != -1 || Mnem.find("sub") != -1||Mnem.find("inc")!=-1||Mnem.find("dec")!=-1||Mnem.find("mov")!=-1)
	{
		std::string before = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1 - loop_block_insn_num].operand0;
		std::string after= tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
		if (after.find(before) == -1)
			return "";
		std::string diff = after.substr(after.find(before) + before.length(), after.length() - after.find(before) + before.length());
		if (before.find(diff) != -1)
			return diff;
		return "";
	}
	return "";
}
//Check whether the second time of execution is different from the first time in loop.
//Parameter1: loop instruction length for once.
int x64_loop_updated(int loop_block_insn_num)
{
	std::string before = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1 - loop_block_insn_num].operand0;
	std::string after = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
	std::string before1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1 - loop_block_insn_num].operand1;
	std::string after1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1;
	if (before.find("=") != -1)//We need to handle memory move separatedly. This is to check whether it is the memory location updated or the content.
	{
		std::string memory_address_before = before.substr(0, before.find("="));//Get left part of the equation, the address.
		std::string content_before = before.substr(before.find("=") + 1, before.length() - 1 - before.find("=") - 1);//Get the right part of the equation, the content.
		std::string memory_address_after = after.substr(0, after.find("="));//Get left part of the equation, the address.
		std::string content_after = after.substr(after.find("=") + 1, after.length() - 1 - after.find("=") - 1);//Get the right part of the equation, the content.
		if (memory_address_after != memory_address_before && is_loop_update(content_before,content_after))
			return 4;
		else if (memory_address_after == memory_address_before && is_loop_update(content_before,content_after))
			return 5;
		else if (is_loop_update(memory_address_after,memory_address_before) && content_before == content_after)
			return 6;
		else if (memory_address_after == memory_address_before && content_before == content_after)
			return 7;
		return -1;
	}
	else
	{
		if (is_loop_update(after,before) && is_loop_update(after1,before1))
			return 0;
		else if ((after==before) && is_loop_update(after1,before1))
			return 1;
		else if (is_loop_update(after,before) && (after1==before1))
			return 2;
		else if ((after == before) && (after1 == before1))
			return 3;
		return -1;
	}
}

//For source of iterator, we rename to mark them source of iterator.
void x64_replace_element_with_iterator(ea_t ea,std::string diff)
{
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = x64_allocate_iterator_var();
	//x64_my_insn_IR[ea] = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 + diff;
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0,tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 + diff });

}

/*bool x64_contain_iterators()
{
	if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find("ITERATOR") != -1)
		return true;
	if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find("ITERATOR") != -1)
		return true;

	return false;
}*/



void x64_reserve_IR(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, tmp_x64_insn_record[tmp_x64_insn_record.size() - 1]);
	x64_my_insn_IR[ea] = x64_get_operand(ea,0)+"="+tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;

}

void x64_clean_tmp()
{
	
	tmp_x64_insn_record.clear();
	tmp_x64_my_insn.clear();
	x64_debug_iter_sinsn.clear();
}

//At this step, the loop instructions has been modified so that the source of iterator is identified
//and has been renamed. Also, their usage in other loop instructions has changed their symbolic value.
//So we can copy these loop symbolic values back into normal symboloc records.
void x64_tmp_copy_to_my_insn(ea_t start,ea_t end, int loop_block_insn_num)
{
	int i = 0;
	for (ea_t index = end;index != insn_last_insn[start];index = insn_last_insn[index])
	{
		x64_my_insn[ea2x64_my_insn[index]] = tmp_x64_my_insn[tmp_x64_my_insn.size()-1-i];
		//ea_t test = tmp_x64_insn_record[tmp_x64_my_insn.size()-i];
		i++;
	} 
}

//In the loop blocks, we reset the operands being modified by the loop with new varaible names,
//and leave the unmodified operands alone.
void x64_process_loop(ea_t ea, ea_t next_ea, func_t *func)
{
	int modified_operand_index;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
	{
		//x64_change_operand_if_modified(index);
		x64_findUpdate(index, func);
	}
}
//For each instructions in the loop block, we turn its symbolic value into ITER(...).
//This is not good since it assumes all the instructions to be updated. But there are
//many invariant instructions.
void x64_iteralize_operands(ea_t ea, ea_t next_ea, func_t* func)
{
	
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
	{
		if (x64_my_insn[ea2x64_my_insn[index]].parameters0.find("iteralized") == x64_my_insn[ea2x64_my_insn[index]].parameters0.end())
		{
			if (x64_my_insn[ea2x64_my_insn[index]].operand0 != "")
				x64_my_insn[ea2x64_my_insn[index]].operand0 = "ITER(" + x64_my_insn[ea2x64_my_insn[index]].operand0 + ")";
			if (x64_my_insn[ea2x64_my_insn[index]].operand1 != "")
				x64_my_insn[ea2x64_my_insn[index]].operand1 = "ITER(" + x64_my_insn[ea2x64_my_insn[index]].operand1 + ")";
			x64_my_insn[ea2x64_my_insn[index]].parameters0.insert({ "iteralized","yes" });
		}

	}
}

//For each instruction in the loop. for each operand, we check wherher it was propagated
//from the previous instruction in the same loop block. If yes, we mark the source of the 
//propagation as redundant instruction.
void x64_mark_redundant_insns(ea_t ea, ea_t next_ea, func_t* func)
{
	qstring Mnemq;
	std::string Mnem;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		x64_go_back_mark_if_cite(Mnem, next_ea,ea,index);
	}
}

//If we meet loop instruction, we simply re-symbolically run this loop. So that loop with
//multiple branches (e.g.. a->b,c->a) can all be correctly executed
void x64_recalculate_loop(ea_t ea, ea_t next_ea, func_t* func)
{
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])//put the loop instructions in an forward array
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());//put the loop instructions in an forward array
	for (int index = 0;index < forward_insn_last_insn.size();index++)//second time execute the loop block to identify iterators
	{
		x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand0 = "";
		x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].operand1 = "";
		x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].parameters0.clear();
		x64_my_insn[ea2x64_my_insn[forward_insn_last_insn[index]]].parameters1.clear();
		x64_findUpdate(forward_insn_last_insn[index], func);
	}
}

//From loop beginning to check whether some instruction modified the value.
//If yes, mark that instruction as redundant.
//Depending on the Mnem, there might be one or more operands to check whether
//it/they is/are contained in other instructions in this loop.
//Parameter1: Mnem
//Parameter2: loop starting index
//Parameter3: loop ending index
//Parameter4: current index
void x64_go_back_mark_if_cite(std::string Mnem, ea_t start_index, ea_t end_index,ea_t current_index)
{
	std::vector <std::string> operand_to_check = x64_operand_to_check(Mnem, current_index);
	for (ea_t index = end_index;index != insn_last_insn[start_index];index = insn_last_insn[index])
	{
		if (index == current_index)
			continue;
		else
		x64_mark_if_cite(operand_to_check,index);
	}
}

//Depending on the Mnem, there might be one or more operands to check whether
//it/they is/are contained in other instructions in this loop.
std::vector<std::string> x64_operand_to_check(std::string Mnem, ea_t current_index)
{
	std::vector<std::string> operand_to_check;
	if (x64_my_insn[ea2x64_my_insn[current_index]].operand0 != "")
		operand_to_check.push_back(x64_my_insn[ea2x64_my_insn[current_index]].operand0);
	if (x64_my_insn[ea2x64_my_insn[current_index]].operand1 != "")
		operand_to_check.push_back(x64_my_insn[ea2x64_my_insn[current_index]].operand1);
	return operand_to_check;
	/*std::vector<std::string> operand_to_check;
	if (count_ea_operands(current_index) == 1)
	{
	operand_to_check.push_back(x64_get_operand(current_index, 0));
	return operand_to_check;
	}
	else if (count_ea_operands(current_index) == 2)
	{
		if (Mnem == "test" || Mnem == "cmp")
		{
			if (get_optype(current_index, 0) == 3 || get_optype(current_index, 0) == 4 || get_optype(current_index, 0) == 1)
				operand_to_check.push_back(x64_get_operand(current_index, 0));
			if (get_optype(current_index, 1) == 3 || get_optype(current_index, 1) == 4 || get_optype(current_index, 1) == 1)
				operand_to_check.push_back(x64_get_operand(current_index, 1));
			return operand_to_check;
		}
		else if (Mnem == "mov" || Mnem == "lea"||Mnem=="movq")
		{
			if (get_optype(current_index, 1) == 3 || get_optype(current_index, 1) == 4 || get_optype(current_index, 1) == 1)
				operand_to_check.push_back(x64_get_operand(current_index, 1));
			return operand_to_check;
		}
		else if (Mnem == "xor" || Mnem == "add" || Mnem == "sub" || Mnem == "rol" || Mnem == "ror" || Mnem == "and" || Mnem == "or" || Mnem == "shr" || Mnem == "shl" || \
			Mnem == "cmov" || Mnem == "sbb" || Mnem == "adc" || Mnem == "xchg")
		{
			operand_to_check.push_back(x64_get_operand(current_index, 0));
			if (get_optype(current_index, 1) == 3 || get_optype(current_index, 1) == 4 || get_optype(current_index, 1) == 1)
				operand_to_check.push_back(x64_get_operand(current_index, 1));
			return operand_to_check;
		}
		else if(Mnem=="movd")
		{
			operand_to_check.push_back(x64_get_operand(current_index, 0));
			if (get_optype(current_index, 1) == 3 || get_optype(current_index, 1) == 4 || get_optype(current_index, 1) == 1)
				operand_to_check.push_back(x64_get_operand(current_index, 1));
			return operand_to_check;
		}
		else
		{
			operand_to_check.push_back(x64_get_operand(current_index, 0));
			if (get_optype(current_index, 1) == 3 || get_optype(current_index, 1) == 4 || get_optype(current_index, 1) == 1)
				operand_to_check.push_back(x64_get_operand(current_index, 1));
			return operand_to_check;
		}
	}
	else if (count_ea_operands(current_index) == 3)
	{
		operand_to_check.push_back(x64_get_operand(current_index, 1));
		if (get_optype(current_index, 2) == 3 || get_optype(current_index, 2) == 4 || get_optype(current_index, 2) == 1)
			operand_to_check.push_back(x64_get_operand(current_index, 2));
		return operand_to_check;
	}*/
	
}

//Check if operands in ea in operand_to_check and is a modified value in this instruction
void x64_mark_if_cite(std::vector<std::string> operand_to_check, ea_t ea)
{
	if (ea == 0x1540)
		int break1 = 0;
	qstring Mnemq;
	std::string Mnem;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	if (Mnem != "xchg")
	{
		std::string operand = x64_my_insn[ea2x64_my_insn[ea]].operand0;
		if(operand!="")
		for (int i = 0;i < operand_to_check.size();i++)
		{
			if (operand_to_check[i].find(operand)!=-1)
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "redundant","yes" });
		}
	}
	else {
		std::string operand = x64_my_insn[ea2x64_my_insn[ea]].operand0;
		std::string operand1= x64_my_insn[ea2x64_my_insn[ea]].operand1;
		if(operand!=""||operand1!="")
		for (int i = 0;i < operand_to_check.size();i++)
		{
			if (operand_to_check[i].find(operand) != -1)
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "redundant","yes" });
			else if (operand_to_check[i].find(operand1) != -1)
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "redundant","yes" });
		}
	}
}

//This is not a good implementation of detecting updating instructions in loop.
//It only considers the Mnem of the instructions. This is not accurate. We shoud
//really execute the loop twice to see which one is updated.
void x64_change_operand_if_modified(ea_t ea)
{
	if (ea == 0x1cc1 || ea == 0x1fce)
		int bizaizi = 1;
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (/*Mnem.find("mov") != -1 || Mnem.find("lea") != -1 || */Mnem.find("xor") != -1 || Mnem.find("add") != -1 || Mnem.find("sub") != -1\
		|| Mnem.find("adc") != -1 || Mnem.find("sbb") != -1 || Mnem.find("mul") != -1 || Mnem.find("div") != -1 || Mnem.find("and") != -1\
		|| Mnem.find("or") != -1 || Mnem.find("rol") != -1 || Mnem.find("ror") != -1 || Mnem.find("shr") != -1 || Mnem.find("shl") != -1\
		|| Mnem.find("sar") != -1 || Mnem.find("sal") != -1 || Mnem.find("inc") != -1 || Mnem.find("dec") != -1 || Mnem.find("neg") != -1\
		|| Mnem.find("not") != -1)
	{
		std::string operand0 = x64_get_operand(ea, 0);
		if (operand0.find("[") == -1)//operand0 is a register
		{
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITVAR") == -1)//never been given new variable name for iteration
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"loop_origin",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = "IT"+x64_allocate_new_variable(operand0);
		}
		else if (operand0.find("[") != -1)//operand0 is a []
		{
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITVAR") == -1)//never been given new variable name for iteration
			{
				qstring disasm;
				std::string disasms;
				generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
				disasms = disasm.c_str();
				std::string new_var;
				if (disasms.find("qword") != -1)//rx
				{
					new_var = x64_allocate_new_variable("rax");
				}
				else if (disasms.find("dword") != -1)//ex
				{
					new_var = x64_allocate_new_variable("eax");
				}
				else if (disasms.find(" word") != -1)//x
				{
					new_var = x64_allocate_new_variable("ax");
				}
				else if (disasms.find("byte") != -1)//al
				{
					new_var = x64_allocate_new_variable("al");
				}
				else
				{
					new_var = x64_allocate_new_variable("rax");
				}
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"loop_origin",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") + 1) + "IT" + new_var;
			}
		}
	}
}
/*void recalculate_for_while(ea_t ea, ea_t next_ea, func_t * func)
{
	qstring Mnem;
	ea_t last_compare_insn;
	std::vector <std::string> iterate_variables;
	print_insn_mnem(&Mnem, ea);
	 
	std::map <std::string,std::string> iterate_variable_map;
	std::map <std::string, std::pair<ea_t,int>> iterators_first_occur;
	std::map<ea_t, ea_t>::iterator recalculate_start1;
	
	
	if (Mnem[0] == 'j' && Mnem != "jmp")
		last_compare_insn = find_last_compare(ea, next_ea, func);

	else return;
	identify_iterator(last_compare_insn, next_ea, iterate_variable_map);

	recalculate_start1 = insn_last_insn.begin();
	for (;recalculate_start1!=insn_last_insn.end();recalculate_start1++)//find the loop starting insn
		if (recalculate_start1->first == next_ea)
			break;

	for(;recalculate_start1!=insn_last_insn.end();recalculate_start1++)//find the loop iterator first occuring insn
		if (contain_iterator(recalculate_start1->first, iterate_variable_map))
			break;
	for (const auto & each_pair : iterate_variable_map)
	{
		iterate_variables.push_back(each_pair.first);
	}
	clear_x64_my_insn(recalculate_start1, ea);

	find_iterator_first_occur(recalculate_start1,ea,iterators_first_occur, iterate_variables);
	for (;recalculate_start1->first<ea;recalculate_start1++)
	{
 		x64_recalculate_each_insn(recalculate_start1->first, iterate_variable_map, iterators_first_occur,func);
	}
}

ea_t find_last_compare(ea_t ea, ea_t next_ea, func_t* func)
{
	ea_t index;
	qstring Mnem;

	for (index = insn_last_insn[ea];index != next_ea;index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnem, index);
		if (Mnem == "test" || Mnem == "cmp")
			return index;
	}
	return -1;
}


bool is_iterator(ea_t ea, ea_t next_ea,int op_index)
{
	qstring Mnem;
	std::string operand;
	operand = x64_get_operand(ea, op_index);
	std::string tmp_operand0, tmp_operand1;
	
	std::string iterator_var;
	std::string to_replace;
	for (ea_t index = insn_last_insn[ea];index != insn_last_insn[next_ea];index = insn_last_insn[index])
	{
		print_insn_mnem(&Mnem, index);
		tmp_operand0 = x64_get_operand(index, 0);
		tmp_operand1 = x64_get_operand(index, 1);
		if (Mnem != "cmp" && Mnem != "test")
			if (tmp_operand0.find(operand) != -1||tmp_operand1.find(operand)!=-1)
			{
				return true;
			}
			
		
	}
	return false;
}

void identify_iterator(ea_t last_compare_insn, ea_t next_ea, std::map<std::string,std::string> &map)
{
	std::string iterator;
	if (is_iterator(last_compare_insn, next_ea, 0))
	{
		iterator = allocate_iterator_var();
		map.insert({ x64_get_operand(last_compare_insn,0),iterator });
	}
	if (is_iterator(last_compare_insn, next_ea, 1))
	{
		iterator = allocate_iterator_var();
		map.insert({ x64_get_operand(last_compare_insn,1),iterator });
	}

}

bool contain_iterator(ea_t ea, std::map<std::string,std::string> &map)
{
	std::string operand0, operand1,map_key,key;
	operand0 = x64_get_operand(ea, 0);
	operand1 = x64_get_operand(ea, 1);
	for (const auto& each_pair : map)
	{
		if (operand0.find(each_pair.first) != -1 || operand1.find(each_pair.first) != -1)
		{
			return true;
		}
	}
	return false;
}

void x64_recalculate_each_insn(ea_t ea, std::map<std::string,std::string> &var_map, std::map<std::string,std::pair<ea_t,int>>line_map,func_t * func)
{
	for (const auto& each_line : line_map)
	{
		if (ea == each_line.second.first)
		{
			iterator_first_time_propagate_handler(ea,func,each_line.second.second, each_line.first,var_map[each_line.first]);
			return;
		}

	}
	
		x64_findUpdate(ea, func);
	

}

void clear_x64_my_insn(std::map<ea_t,ea_t>::iterator it, ea_t end)
{
	for (;it->first < end;it++ )
	{
		x64_my_insn[ea2x64_my_insn[it->first]].operand0 = "";
		x64_my_insn[ea2x64_my_insn[it->first]].operand1 = "";
		x64_my_insn[ea2x64_my_insn[it->first]].parameters0.clear();
		x64_my_insn[ea2x64_my_insn[it->first]].parameters1.clear();
	}
}

void find_iterator_first_occur(std::map<ea_t,ea_t>::iterator it,ea_t end,std::map<std::string,std::pair<ea_t,int>> &line_map,std::vector <std::string> vector)
{
	std::string operand0, operand1;
	for (;it->first< end;it++)
	{
		operand0 = x64_get_operand(it->first, 0);
		operand1 = x64_get_operand(it->first, 1);
		for (int i=0;i<vector.size();i++)
		{
			if (operand0.find(vector[i])!=-1)
			{
				line_map.insert({ vector[i],{it->first,0} });
				vector.erase(vector.begin()+i);
			}
			else if (operand1.find(vector[i])!=-1)
			{
				line_map.insert({ vector[i],{it->first,1} });
				vector.erase(vector.begin() + i);
			}
		}
	}
}
*/

