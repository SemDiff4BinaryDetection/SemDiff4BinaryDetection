#include "../../Headers/value_calculate/ARM_while_handler.h"
std::vector <ea_t> tmp_ARM_insn_record;
std::vector <ARM_my_instruction> tmp_ARM_my_insn;
std::vector<std::string> debug_iter_sinsn;
int ARM_iterator_variable;
void ARM_init_iterator_var()
{
	ARM_iterator_variable = 0;
}

/*We symbolically execute the loop for twice so that we can identify tbe invariant instructions
and the updating instructions. For invariant instructions, we just leave their constant value/expression
there. For updating expression/value,we write them in this form: ITER(...). We write their value in the
first loop in the bracket*/
void ARM_recalculate_for_while_v1(ea_t ea, ea_t next_ea, func_t *func)
{
	if (ea == 0xa3b44)
		int bp = 1;
	std::string diff;
	int is_updated;
	int loop_block_insn_num;
	ARM_init_tmp_ARM_insn_record(ea, next_ea);
	ARM_init_tmp_ARM_my_insn(ea, next_ea);
	loop_block_insn_num = tmp_ARM_my_insn.size();
	//tmp_ARM_insn_record.push_back(next_ea);
	std::vector<ea_t> forward_insn_last_insn;//forward_insn_last_insn stores the loop instructions in forward order for once. It is temporily used.
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());
	ARM_iterate_mark[ea2ARM_my_insn[next_ea]] = '{';
	ARM_iterate_mark[ea2ARM_my_insn[ea]] = '}';
	qstring disasm;
	for (int index = 0;index < forward_insn_last_insn.size();index++)//second time execute the loop block to identify iterators
	{
		if (forward_insn_last_insn[index] == 0x1ec674)
			int breakp = 1;
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		debug_iter_sinsn.push_back(disasm.c_str());
		tmp_ARM_insn_record.push_back(forward_insn_last_insn[index]);//tmp_ARM_insn_record stores the loop instructions in forward order for twice. The second time is to find out iterators.
		ARM_re_update_each_insn(forward_insn_last_insn[index], func);
		is_updated = ARM_loop_updated(loop_block_insn_num);
		if (is_updated == 0)
		{
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
		}
		else if (is_updated == 1)
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 + ")";
		else if (is_updated == 2)
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
		else if (is_updated == 4)//For memory write, the address and the content all get updated.
		{
			int equation_location = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.find("=");
			int len = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.length();
			std::string memory_address = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.substr(0, equation_location);
			std::string content= ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.substr(equation_location + 1,len-1- equation_location);
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER(" + memory_address + ")=ITER(" + content + ")";
		}
		else if (is_updated == 5)//For memory write, the address not change, the content get updated.)
		{
			int equation_location = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.find("=");
			int len = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.length();
			std::string memory_address = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.substr(0, equation_location);
			std::string content = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.substr(equation_location + 1, len - 1 - equation_location);
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 = memory_address + "=ITER(" + content + ")";
		}
		else if (is_updated == 6)//For memory write, the address get updated, content not change.)
		{
			int equation_location = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.find("=");
			int len = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.length();
			std::string memory_address = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.substr(0, equation_location);
			std::string content = ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1.substr(equation_location + 1, len - 1 - equation_location);
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 = "ITER(" + ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 + ")";
			ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 = "ITER("+memory_address + ")="+ content ;
		}

	}
	
	ARM_clean_tmp();
}

void ARM_recalculate_for_while(ea_t ea, ea_t next_ea, func_t* func)
{
	if (ea == 0x13170)
		int bp = 1;
	std::string diff;
	int loop_block_insn_num;
	ARM_init_tmp_ARM_insn_record(ea, next_ea);
	ARM_init_tmp_ARM_my_insn(ea, next_ea);
	loop_block_insn_num = tmp_ARM_my_insn.size();
	//tmp_ARM_insn_record.push_back(next_ea);
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());
	ARM_iterate_mark[ea2ARM_my_insn[next_ea]] = '{';
	ARM_iterate_mark[ea2ARM_my_insn[ea]] = '}';
	qstring disasm;
	for (int index = 0;index < forward_insn_last_insn.size();index++)//second time execute the loop block to identify iterators
	{
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		debug_iter_sinsn.push_back(disasm.c_str());
		tmp_ARM_insn_record.push_back(forward_insn_last_insn[index]);
		ARM_re_update_each_insn(forward_insn_last_insn[index], func);
		ARM_is_iter_source(forward_insn_last_insn[index], loop_block_insn_num);
	}
	//tmp_ARM_insn_record.push_back(next_ea);
	for (int index = 0;index < forward_insn_last_insn.size();index++)//third time execute to translate all iterators
	{
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		debug_iter_sinsn.push_back(disasm.c_str());
		tmp_ARM_insn_record.push_back(forward_insn_last_insn[index]);
		ARM_re_update_each_insn(forward_insn_last_insn[index], func);
		//if (ARM_contain_iterators())
		//{
		//	ARM_reserve_IR(index);
		//}

	}
	ARM_tmp_copy_to_my_insn(next_ea, ea, loop_block_insn_num);
	ARM_clean_tmp();
}

void ARM_init_tmp_ARM_insn_record(ea_t ea, ea_t next_ea)
{
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea; index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());
	for (int index = 0; index < forward_insn_last_insn.size();index++)
	{
		tmp_ARM_insn_record.push_back(forward_insn_last_insn[index]);
	}
}

void ARM_init_tmp_ARM_my_insn(ea_t ea, ea_t next_ea)
{
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea; index != insn_last_insn[next_ea];index = insn_last_insn[index])
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());
	qstring disasm;
	for (int index = 0;index < forward_insn_last_insn.size();index++)
	{
		tmp_ARM_my_insn.push_back(ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]]);
		generate_disasm_line(&disasm, forward_insn_last_insn[index], GENDSM_REMOVE_TAGS);
		debug_iter_sinsn.push_back(disasm.c_str());
	}
}

void ARM_is_iter_source(ea_t ea, int loop_block_insn_num)
{
	if (ea == 0x200c||ea==0x247c)
		int bp = 1;
	qstring Mnemq;
	print_insn_mnem(&Mnemq, tmp_ARM_insn_record[tmp_ARM_insn_record.size() - 1]);
	std::string diff;
	std::string Mnem = Mnemq.c_str();
	if (Mnem.find("ADD") != -1 || Mnem.find("SUB") != -1 || Mnem.find("ADC") != -1 || Mnem.find("SBC") != -1)
	{
		std::string before = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1 - loop_block_insn_num].operand0;
		std::string after = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0;
		//deal with add rax, 7 in iteration
		
			if (after.find(before) == -1)
				return;
			diff = after.substr(after.find(before) + before.length(), after.length() - after.find(before) + before.length());
			if (before.find(diff) != -1)
				ARM_replace_element_with_iterator(ea, diff);
			return;
		
	}
	else if(Mnem.find("LDR") != -1 || Mnem.find("STR") != -1)//deal with LDR rax, [r0], #4
	{
		std::string before, after;
		if (Mnem.find("LDR") != -1)
		{
			before = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1 - loop_block_insn_num].operand0;
			after = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0;
		}
		else if (Mnem.find("STR") != -1)
		{
			before = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1 - loop_block_insn_num].operand1;
			after = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
		}
		if (before.find('[') != -1 && after.find('[')!=-1)
		{
			before = before.replace(before.find('['), 1, "");
			before = before.replace(before.rfind(']'), 1, "");
			after = after.replace(after.find('['), 1, "");
			after = after.replace(after.rfind(']'), 1, "");
			if (after.find(before) != -1)
				diff = after.substr(after.find(before) + before.length(), after.length() - after.find(before) + before.length());
			else
				return;
			if (diff != "")
			{
				std::string tmp = ARM_extract_bracket_base(ARM_get_operand(ea, 1));
				tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters1[tmp] = ARM_allocate_iterator_var();
				tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters1[tmp] + diff;
				return;
			}

		}
	}
	
}

void ARM_replace_element_with_iterator(ea_t ea, std::string diff)
{
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = ARM_allocate_iterator_var();

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters0.insert({ ARM_get_operand(ea,0),tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 + diff });

}

std::string ARM_allocate_iterator_var() {
	ARM_iterator_variable++;
	return "ITERATOR" + std::to_string(ARM_iterator_variable);
}

void ARM_tmp_copy_to_my_insn(ea_t start, ea_t end, int loop_block_insn_num)
{
	int i = 0;
	for (ea_t index = end;index != insn_last_insn[start];index = insn_last_insn[index])
	{
		ARM_my_insn[ea2ARM_my_insn[index]] = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1 - i];
		
		i++;
	}
}

void ARM_clean_tmp()
{

	tmp_ARM_insn_record.clear();
	tmp_ARM_my_insn.clear();
	debug_iter_sinsn.clear();
}

int find_bracket_level(std::string after)
{
	int level = 0;
	for (int i = 0;i < after.size();i++)
		if (after[i] == '[')
			level += 1;
	return level;
}

//In the loop blocks, we reset the operands being modified by the loop with new varaible names,
//and leave the unmodified operands alone.
/*void ARM_process_loop(ea_t ea, ea_t next_ea, func_t* func)
{
	int modified_operand_index;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])
	{
		ARM_change_operand_if_modified(index);

	}
}*/

/*void ARM_change_operand_if_modified(ea_t ea)
{
	if (ea == 0x1cc1 || ea == 0x1fce)
		int bizaizi = 1;
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (Mnem.find("xor") != -1 || Mnem.find("ADD") != -1 || Mnem.find("SUB") != -1\
		|| Mnem.find("RSB") != -1 || Mnem.find("AND") != -1 || Mnem.find("ORR") != -1 || Mnem.find("EOR") != -1 || Mnem.find("ORN") != -1\
		|| Mnem.find("REV") != -1 || Mnem.find("LSL") != -1 || Mnem.find("RRX") != -1 || Mnem.find("MUL") != -1 || Mnem.find("MLA") != -1\
		|| Mnem.find("MLS") != -1 || Mnem.find("BIC") != -1)
	{
		std::string operand0 = ARM_get_operand(ea, 0);
		if (operand0.find("[") == -1)//operand0 is a register
		{
			if (ARM_my_insn[ea2ARM_my_insn[ea]].operand0.find("ITVAR") == -1)//never been given new variable name for iteration
				ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "loop_origin",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = "IT" + arm_allocate_new_variable(operand0);
		}
		else if (operand0.find("[") != -1)//operand0 is a []
		{
			if (ARM_my_insn[ea2ARM_my_insn[ea]].operand0.find("ITVAR") == -1)//never been given new variable name for iteration
			{
				qstring disasm;
				std::string disasms;
				generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
				disasms = disasm.c_str();
				std::string new_var;
				if (disasms.find("qword") != -1)//rx
				{
					new_var = arm_allocate_new_variable();
				}
				else if (disasms.find("dword") != -1)//ex
				{
					new_var = allocate_new_variable();
				}
				else if (disasms.find(" word") != -1)//x
				{
					new_var = allocate_new_variable();
				}
				else if (disasms.find("byte") != -1)//al
				{
					new_var = allocate_new_variable();
				}
				else
				{
					new_var = allocate_new_variable();
				}
				ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "loop_origin",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
				ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.find("=") + 1) + "IT" + new_var;
			}
		}
	}
}*/

//If we meet loop instruction, we simply re-symbolically run this loop. So that loop with
//multiple branches (e.g.. a->b,c->a) can all be correctly executed
void ARM_recalculate_loop(ea_t ea, ea_t next_ea, func_t* func)
{
	std::vector<ea_t> forward_insn_last_insn;
	for (ea_t index = ea;index != insn_last_insn[next_ea];index = insn_last_insn[index])//put the loop instructions in an forward array
		forward_insn_last_insn.push_back(index);
	std::reverse(forward_insn_last_insn.begin(), forward_insn_last_insn.end());//put the loop instructions in an forward array
	for (int index = 0;index < forward_insn_last_insn.size();index++)//second time execute the loop block to identify iterators
	{
		ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand0 = "";
		ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].operand1 = "";
		ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].parameters0.clear();
		ARM_my_insn[ea2ARM_my_insn[forward_insn_last_insn[index]]].parameters1.clear();
		ARM_findUpdate(forward_insn_last_insn[index], func);
	}
}

//Check whether the second time of execution is different from the first time in loop.
//Parameter1: loop instruction length for once.
int ARM_loop_updated(int loop_block_insn_num)
{
	std::string before = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1 - loop_block_insn_num].operand0;
	std::string after = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0;
	std::string before1 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1 - loop_block_insn_num].operand1;
	std::string after1 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
	if (before1.find("=") != -1)//We need to handle memory move separatedly. This is to check whether it is the memory location updated or the content.
	{
		std::string memory_address_before = before1.substr(0, before1.find("="));//Get left part of the equation, the address.
		std::string content_before = before1.substr(before1.find("=") + 1, before1.length() - 1 - before1.find("=") - 1);//Get the right part of the equation, the content.
		std::string memory_address_after = after1.substr(0, after1.find("="));//Get left part of the equation, the address.
		std::string content_after = after1.substr(after1.find("=") + 1, after1.length() - 1 - after1.find("=") - 1);//Get the right part of the equation, the content.
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
	else //None memory move instructions.
	{
		
		if (is_loop_update(after,before) && is_loop_update(after1,before1))
			return 0;
		else if ((after == before) && is_loop_update(after1,before1))
			return 1;
		else if (is_loop_update(after, before) && (after1 == before1))
			return 2;
		else if ((after == before) && (after1 == before1))
			return 3;
		return -1;
	}
}