#include "../../Headers/value_calculate/ARM_mylibrary.h"

std::vector <ARM_my_instruction> ARM_my_insn;

std::map<int, int> ea2ARM_my_insn;
int DWORD_LEN = 8;

std::vector<char> ARM_iterate_mark;
/*void ARM_infer_this_insn_propagate_next(func_t* func, ea_t ea)
{
	if (ARM_is_pop_insn(ea))
	{
		//init_IR_reserve_insns(func);
		//translate_loop_insns(ea,func); 
		init_ARM_my_insn_IR(func);
		ARM_translate_return_value(ea, func);
		ARM_translate_each_insn(func);
		ARM_print_to_file(ea, func);
		//print_path(ea,func);
		return;
	}

	ARM_clear_ARM_my_insn(ea);
	ea_t next_ea, next_ea1;
	ARM_findUpdate(ea, func);
	next_ea = get_first_cref_from(ea);
	next_ea1 = get_next_cref_from(ea, next_ea);

	if (next_ea != -1 && is_in_loop(ea, next_ea, func))
	{


		//recalculate_for_while(ea, next_ea, func);
		next_ea = -1;
	}

	if (next_ea1 != -1 && is_in_loop(ea, next_ea1, func))
	{


		//recalculate_for_while(ea, next_ea1, func);
		next_ea1 = -1;

	}


	if (next_ea != -1 && next_ea != BADADDR && next_ea >= func->start_ea && next_ea <= func->end_ea)
	{

		insn_last_insn[next_ea] = ea;
		ARM_infer_this_insn_propagate_next(func, next_ea);


		if (next_ea1 != -1 && next_ea1 >= func->start_ea && next_ea1 <= func->end_ea)
		{

			insn_last_insn[next_ea1] = ea;
			ARM_infer_this_insn_propagate_next(func, next_ea1);
		}
	}
}*/

//Store all registers of the shift as parameters for the operand, and returns the expression result
std::string ARM_process_shift_operand(std::string operand, int index, ea_t ea, func_t * func)
{
	std::string defined_value2;
	std::string shift_mnem = ARM_extract_shift_mnem(operand);
	std::string tmp1 = ARM_extract_shift_base(operand,shift_mnem);
	std::string defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	if (index==1)
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,defined_value1 });//shift base
	else if(index==2)
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp1,defined_value1 });//shift base
	std::string tmp2 = ARM_extract_shift_offset(operand,shift_mnem);
	if (is_ARM_register(tmp2))
	{
		defined_value2 = ARM_lookForDefine(tmp2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(tmp2);
		if(index==1)
			ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });//shift offset
		else if(index==2)
			ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,defined_value2 });//shift offset
	}
	else
		defined_value2 = tmp2;
	return "("+defined_value1 + shift_mnem + defined_value2+")";
}


void ARM_arithmatic_propagate_reg_reg_reg(std::string operand1, std::string operand2, ea_t ea, func_t * func, std::string Mnem)
{
	std::string defined_value1, defined_value2;
	defined_value1 = ARM_lookForDefine(operand1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(operand1);
	ARM_propagate_to_operand(ea, defined_value1, 1);
	defined_value2 = ARM_lookForDefine(operand2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(operand2);
	ARM_propagate_to_operand(ea, defined_value2, 2);
	ARM_propagate_to_operand(ea, "("+defined_value1 + Mnem + defined_value2+")", 0);
}

void ARM_arithmatic_propagate_reg_reg_num(std::string operand1, std::string operand2, ea_t ea, func_t* func, std::string Mnem)
{
	std::string defined_value1;
	defined_value1 = ARM_lookForDefine(operand1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(operand1);
	ARM_propagate_to_operand(ea, defined_value1, 1);
	ARM_propagate_to_operand(ea, "("+defined_value1 + Mnem + operand2+")", 0);

}

void ARM_arithmatic_propagate_reg_reg_shift(std::string operand1, std::string operand2, ea_t ea, func_t* func, std::string Mnem)
{
	std::string defined_value1, defined_value2;
	defined_value2 = ARM_process_shift_operand(operand2, 2, ea, func);
	defined_value1 = ARM_lookForDefine(operand1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(operand1);
	ARM_propagate_to_operand(ea, defined_value2, 2);
	ARM_propagate_to_operand(ea, defined_value1, 1);
	ARM_propagate_to_operand(ea, "("+defined_value1 + Mnem + defined_value2+")", 0);

}

void ARM_arithmatic_propagate_reg_reg(std::string operand0, std::string operand1, ea_t ea, func_t* func, std::string Mnem)
{
	std::string defined_value, defined_value1;
	defined_value1 = ARM_lookForDefine(operand1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(operand1);
	ARM_propagate_to_operand(ea, defined_value1, 1);
	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({"original",ARM_my_insn[ea2ARM_my_insn[ea]].operand0});
	ARM_propagate_to_operand(ea, "("+defined_value + Mnem + defined_value1+")", 0);
}

void ARM_arithmatic_propagate_reg_shift(std::string operand0, std::string operand1, ea_t ea, func_t* func, std::string Mnem)
{
	std::string defined_value1, defined_value;
	defined_value1 = ARM_process_shift_operand(operand1, 1, ea, func);
	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "original",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
	if(Mnem=="+"||Mnem=="-")
		ARM_propagate_to_operand(ea, "("+defined_value + Mnem + defined_value1+")", 0);
	else
		ARM_propagate_to_operand(ea, defined_value + Mnem + defined_value1, 0);
	ARM_propagate_to_operand(ea, defined_value1, 1);
}

void ARM_arithmatic_propagate_reg_num(std::string operand0, std::string operand1, ea_t ea, func_t* func, std::string Mnem)
{
	std::string defined_value;
	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "original",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
		ARM_propagate_to_operand(ea, "("+defined_value + Mnem + operand1+")", 0);

}

void ARM_clear_ARM_my_insn(ea_t ea)
{
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = "";
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.clear();
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "";
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.clear();
	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "";
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.clear();
	ARM_my_insn[ea2ARM_my_insn[ea]].operand3 = "";
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters3.clear();
}

void ARM_init_ARM_my_instruction(func_t* func) {

	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		struct ARM_my_instruction new_one;
		ARM_my_insn.push_back(new_one);
		ea2ARM_my_insn.insert(std::pair<int, int>(ea, ARM_my_insn.size() - 1));
		insn_last_insn.insert(std::pair<ea_t, ea_t>(ea, -1));
		ARM_iterate_mark.push_back(' ');
	}
}


std::string ARM_translate_type4_bracket(std::string operand)
{
	int comma_index,hash_index;
	comma_index = operand.find(',');
	if (comma_index != -1)
	{
		hash_index = operand.find('#');
		operand.replace(comma_index, hash_index - comma_index + 1, "+");
	}
	return operand;
}

void ARM_LDR_type4_register_offset(std::string operand1, ea_t ea, func_t * func)//LDR, reg, [reg {,num}] 
{
	std::string tmp1, defined_value1,tmp;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,defined_value1 });
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]";
	ARM_look_for_displ(ea, func,1);
	if(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=")==-1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=")+1,\
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size()- ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("="));
}

void ARM_LDR_type4_pre_indexed(std::string operand1, ea_t ea, func_t * func)// LDR, reg, [reg {,num}]! 
{
	std::string tmp1, defined_value1, tmp;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp = ARM_translate_type4_register_offset(operand1,defined_value1);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]";
	ARM_look_for_displ(ea, func, 1);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("="));
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp});
}

void ARM_LDR_type4_post_indexed(std::string operand1, ea_t ea, func_t * func)//LDR, reg, [reg], num   
{
	std::string tmp1, defined_value1, tmp;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "[" + defined_value1 + "]";
	ARM_look_for_displ(ea, func, 1);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("="));
	tmp= ARM_translate_type4_register_offset(operand1, defined_value1);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
}

void ARM_LDRD_type4_register_offset(std::string operand2, ea_t ea, func_t* func)//LDRD, reg, reg, [reg {,num}] 
{
	std::string tmp2, defined_value2, tmp;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,defined_value2 });
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);

	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = ARM_translate_LDRD_STRD_second_op(tmp);//Update the second operand's value
	ARM_look_for_displ(ea, func, 2);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("="));
	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "[" + tmp + "]";//Update the first operand's value
	ARM_look_for_displ(ea, func, 2);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("="));
	
}



void ARM_LDRD_type4_pre_indexed(std::string operand2, ea_t ea, func_t* func)// LDRD, reg, reg, [reg {,num}]! 
{
	std::string tmp2, defined_value2, tmp;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);

	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = ARM_translate_LDRD_STRD_second_op(tmp);;//Update the second operand's value
	ARM_look_for_displ(ea, func, 2);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("="));
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,tmp });

	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "[" + tmp + "]";//Update the first operand's value
	ARM_look_for_displ(ea, func, 2);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("="));

}

void ARM_LDRD_type4_post_indexed(std::string operand2, ea_t ea, func_t* func)//LDRD, reg, reg, [reg], num   
{
	std::string tmp2, defined_value2, tmp;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);

	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "[" + defined_value2  + "]";//Update the first operand's value
	ARM_look_for_displ(ea, func, 2);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("="));

	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = ARM_translate_LDRD_STRD_second_op(defined_value2);;//Update the second operand's value
	ARM_look_for_displ(ea, func, 2);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand2.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand2.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand2.find("="));

	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);//Update the third operand's value
	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = tmp;
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,tmp });
}

void ARM_LDR_type3_register_offset(std::string operand1, ea_t ea, func_t * func)  //LDR, reg, [reg, +/-reg {,shift}] 
{
	std::string tmp1, defined_value1,defined_value2, tmp, tmp2;
	bool minus;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp2 = ARM_extract_bracket_second_register(operand1,minus);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,defined_value1 });
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_translate_type3_register_offset(operand1, defined_value1,defined_value2,ea,func);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]";
	ARM_look_for_displ(ea, func, 1);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("="));
}

void ARM_LDR_type3_pre_indexed(std::string operand1, ea_t ea, func_t * func)  //LDR, reg, [reg, +/-reg {,shift}] !
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp2 = ARM_extract_bracket_second_register(operand1,minus);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_translate_type3_register_offset(operand1, defined_value1, defined_value2,ea,func);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]";
	ARM_look_for_displ(ea, func, 1);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("="));
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
}

void ARM_LDR_type3_post_indexed(std::string operand1, ea_t ea, func_t * func) // LDR, reg, [reg], +/-reg {,shift} 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_translate_type3_register_offset(operand1, defined_value1,  defined_value2, ea,func);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "[" + defined_value1 + "]";
	ARM_look_for_displ(ea, func, 1);
	if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") == -1)//If result not contain "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1;
	else if (ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") != -1)//If result contains "="
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand1.substr(ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("=") + 1, \
			ARM_my_insn[ea2ARM_my_insn[ea]].operand1.size() - ARM_my_insn[ea2ARM_my_insn[ea]].operand1.find("="));
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
}



void ARM_process_switch_case(ea_t ea, func_t * func, std::string operand0, std::string operand1, std::string operand2)
{
	int case_num;
	ea_t table_base = ea + DWORD_LEN;
	ea_t table_offset;
	case_num = strtol(ARM_find_last_compare_const(operand2,ea,func).c_str(),NULL,16);
	for (int i = 0;i <= case_num;i++)
	{
		table_offset = get_wide_dword(DWORD_LEN * i+table_base);
		add_cref(ea, table_base + table_offset, fl_JN);
	}
	ARM_convert_to_code(table_base + table_offset+DWORD_LEN+1);
}



void ARM_STR_type3_register_offset(std::string operand0, std::string operand1, ea_t ea, func_t * func) //STR, reg, [reg, +/-reg {,shift}] 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp = ARM_lookForDefine(operand0,ea,func);
	if (tmp == "")
		tmp = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = tmp;

	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,defined_value1});
	tmp2 = ARM_extract_bracket_second_register(operand1,minus);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-"+defined_value2;
	tmp = ARM_translate_type3_register_offset(operand1, defined_value1,defined_value2,ea,func);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1= "["+tmp+"]="+ARM_my_insn[ea2ARM_my_insn[ea]].operand0;
}

void ARM_STR_type3_pre_indexed(std::string operand0, std::string operand1, ea_t ea, func_t * func) // STR, reg, [reg, +/-reg {,shift}] ! 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp = ARM_lookForDefine(operand0, ea, func);
	if (tmp == "")
		tmp = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = tmp;

	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp2 = ARM_extract_bracket_second_register(operand1,minus);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_translate_type3_register_offset(operand1,defined_value1, defined_value2,ea,func);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]" + "=" + ARM_my_insn[ea2ARM_my_insn[ea]].operand0;
}

void ARM_STR_type3_post_indexed(std::string operand0, std::string operand1, ea_t ea, func_t * func)// STR, reg, [reg], +/-reg {,shift} 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp = ARM_lookForDefine(operand0,ea,func);
	if (tmp == "")
		tmp = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = tmp;

	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp2 = ARM_extract_bracket_second_register(operand1,minus);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp2,defined_value2 });
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp1+"]" + "=" + tmp;
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_translate_type3_register_offset(operand1, defined_value1, defined_value2,ea,func);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
}

void ARM_STR_type4_register_offset(std::string operand0, std::string operand1, ea_t ea, func_t * func)//STR, reg, [reg {,num}]  
{
	std::string tmp1, defined_value1, tmp,defined_value;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,defined_value1 });
	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
	tmp = ARM_translate_type4_register_offset(operand1,defined_value1);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]" + "=" + defined_value;
}

void ARM_STR_type4_pre_indexed(std::string operand0, std::string operand1, ea_t ea, func_t * func)// STR, reg, [reg {,num}]! 
{
	std::string tmp1, defined_value1, tmp,defined_value;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	defined_value = ARM_lookForDefine(operand0,ea,func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+tmp+"]" + "=" + defined_value;
}

void ARM_STR_type4_post_indexed(std::string operand0, std::string operand1, ea_t ea, func_t * func) //STR, reg, [reg], num
{
	std::string tmp1, defined_value1, tmp,defined_value;
	defined_value = ARM_lookForDefine(operand0,ea,func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_lookForDefine(tmp1, ea, func);
	if (defined_value1 == "")
		defined_value1 = arm_allocate_new_variable(tmp1);
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({ tmp1,tmp });
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "["+defined_value1+"]" + "=" + defined_value;
}

void ARM_STRD_type4_register_offset(std::string operand0, std::string operand1, std::string operand2, ea_t ea, func_t* func)//STRD reg, reg, [reg {,num}]  
{
	std::string tmp2, defined_value2, tmp, defined_value;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);

	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;//update operand0
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,defined_value2 });//update operand2
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "[" + tmp + "]" + "=" + defined_value;//update first operand2

	defined_value = ARM_lookForDefine(operand1, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand1);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value;//update operand1
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ ARM_translate_LDRD_STRD_second_op(tmp), defined_value });//update second operand2
}

void ARM_STRD_type4_pre_indexed(std::string operand0, std::string operand1, std::string operand2, ea_t ea, func_t* func)//STRD reg, reg [reg num]! 
{
	std::string tmp2, defined_value2, tmp, defined_value;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);

	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;//update operand0
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,tmp });//update operand2
	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "[" + tmp + "]" + "=" + defined_value;//update first operand2

	defined_value = ARM_lookForDefine(operand1, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand1);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value;//update operand1
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ ARM_translate_LDRD_STRD_second_op(tmp), defined_value });//update second operand2
}

void ARM_STRD_type4_post_indexed(std::string operand0, std::string operand1, std::string operand2, ea_t ea, func_t* func) //STRD reg, [reg], num
{
	std::string tmp2, defined_value2, tmp, defined_value;

	defined_value = ARM_lookForDefine(operand0, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand0);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;//update operand0
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_lookForDefine(tmp2, ea, func);
	if (defined_value2 == "")
		defined_value2 = arm_allocate_new_variable(tmp2);
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,tmp });//update operand2
	ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = "[" + defined_value2 + "]" + "=" + defined_value;//update first operand2

	defined_value = ARM_lookForDefine(operand1, ea, func);
	if (defined_value == "")
		defined_value = arm_allocate_new_variable(operand1);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value;//update operand1
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ ARM_translate_LDRD_STRD_second_op(defined_value2),defined_value });//update second operand2

}

void ARM_process_LDM(std::string operand0, std::string operand1, ea_t ea, func_t * func)
{
	std::vector <std::string> reg_list;
	std::string defined_value;
	int i;
	if (!ARM_is_pre_indexed(operand0))
	{
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
	}
	else if (ARM_is_pre_indexed(operand0))
	{
		operand0 = operand0.substr(0, operand0.find('!'));
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		reg_list = ARM_get_reg_list(operand1);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value + "+" + std::to_string(reg_list.size() * DWORD_LEN);
	}
	reg_list = ARM_get_reg_list(operand1);
	for (i = 0;i < reg_list.size();i++)
	{
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({reg_list[i],'['+defined_value+"+"+std::to_string(i*DWORD_LEN)+']'});
	}
}

void ARM_process_STM(std::string operand0, std::string operand1, ea_t ea, func_t * func)
{
	std::vector <std::string> reg_list;
	std::string defined_value,defined_value1;
	int i;
	if (!ARM_is_pre_indexed(operand0))
	{
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
	}
	else if (ARM_is_pre_indexed(operand0))
	{
		operand0 = operand0.substr(0, operand0.find('!'));
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		reg_list = ARM_get_reg_list(operand1);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value + "+" + std::to_string(reg_list.size() * DWORD_LEN);
	}
	reg_list = ARM_get_reg_list(operand1);
	for (i = 0;i < reg_list.size();i++)
	{
		defined_value1 = ARM_lookForDefine(reg_list[i],ea,func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(reg_list[i]);
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.insert({reg_list[i],defined_value1});
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ defined_value + "+" + std::to_string(i * DWORD_LEN),defined_value1 });
	}
	
}

//On ARM, we might encounter some cases when dealing with LDR.
//Case 1:
//      LDR reg, =(,offset_within_this_function)
//For case 1, we need to translate the label to string.
//
//Case 2:
//      LDR reg, =(,offset_out_of_this_function)
//For case 2, we need to translate the whole =(,) as a number (offset).
//
//Case 3:
//      LDR reg, =(function_pointer,offset_within_this_function)
//For case 3, we need to translate the function_pointer as [].
//
//Case 4:
//      LDR reg, =(string_pointer+some_offset,offset_within_this_function)
//For case 4, we need to translate the string_pointer+some_offset as a string.
//
//Case 5:
//      LDR reg, =(string_pointer)
std::string ARM_get_label_value(std::string operand,func_t *func)
{
	if(operand.find("=") == -1)
		warning("strange! LDR second operand is something we never seen before!");
	std::string label;
	std::string offset;
	std::string defined_value1;
	ea_t ea1;
	int offset_int;
	if (operand.find('-') == -1)//case 5
	{
		if (operand.find("=(") != -1)//if has =(
		{
			label = operand.substr(operand.find("=(") + 2, operand.find(')') - operand.find("=(") - 2);//Get the label of that string
			defined_value1 = get_label_value(label);
		}
		else//if does not has =(, instead only a =
		{
			label = operand.substr(operand.find('=') + 1, operand.size()-1 - operand.find('='));//Get the label of that string
			label = trim_begin_end_space(label);
			if (label.find("0x") == 0)//if the label is actually a number like ldr rax, =0xfff
				defined_value1 = label;
			else//if the label is not a number 
				defined_value1 = get_label_value(label);
		}
	}
	else//If the operand has '-'
	{
		label= operand.substr(operand.find('(') + 1, operand.find('-') - operand.find('(') - 1);//label, the string before '-'
		label = trim_begin_end_space(label);
		offset= operand.substr(operand.find('-') + 1, operand.find(')') - operand.find('-') - 1);//offset, the string after '-'
		offset_int = strtol(offset.c_str(),NULL,16);
		if (offset_int > func->end_ea || offset_int < func->start_ea)//case 2
		{
			ea1 = get_name_ea(BADADDR, label.c_str());//get label's address
			defined_value1 = dec2hex(ea1- offset_int);
		}
		else//offset is within in this function
		{
			ea1 = get_name_ea(BADADDR, label.c_str());//get label's address
			func_t* func1 = get_func(ea1); 
			if (func1 != NULL)//case 3, point to a function
				defined_value1 = arm_allocate_new_variable("R5");
			else if (func1 == NULL && label.find('+') != -1)//case 4
			{
				ea_t ea2 = stoi(label.substr(label.find('+') + 1, label.size() - 1 - label.find('+')));
				label = label.substr(0, label.find('+'));
				ea1 = get_name_ea(BADADDR, label.c_str());//get label's address
				qstring buffer;
				get_strlit_contents(&buffer, ea1+ea2, -1, STRTYPE_C);//get the string content
				defined_value1 = filter_specific_string(buffer.c_str());
				if (defined_value1.empty())
					defined_value1 = arm_allocate_new_variable("R5");
				else
					defined_value1 = '"' + defined_value1 + '"';
			}
			else if (func1 == NULL && label.find('+') == -1)//case 1
			{
				if (label.find("xmmword_") == 0 || label.find("qword_") == 0 || label.find("dword_") == 0 || \
					label.find("word_") == 0 || label.find("byte_") == 0 || label.find("byte3_") == 0)
				{
					ea_t ea1 = get_name_ea(BADADDR, label.c_str());
					defined_value1 = "0x" + dec2hex(ea1 - offset_int);
				}
				else
				defined_value1 = get_label_value(label);
			}
		}
	}
 	return defined_value1;
}

//if the offset is translated by IDA to #(label-offset), we need to translate it back to number
std::string ARM_numerize_offset(std::string operand)
{
	if (operand.find('-') != -1)//if is like #(label-offset)
	{
		std::string label = operand.substr(operand.find('(') + 1, operand.find('-') - operand.find('(') - 1);//label, the string before '-'
		label = trim_begin_end_space(label);
		std::string offset = operand.substr(operand.find('-') + 1, operand.find(')') - operand.find('-') - 1);//offset, the string after '-'
		ea_t offset_int = strtol(offset.c_str(), NULL, 16);
		ea_t ea1 = get_name_ea(BADADDR, label.c_str());//get label's address
		ea_t real_offset = ea1 - offset_int;
		operand = operand.substr(0, operand.find('#'));
		operand += "#0x" + dec2hex(real_offset)+']';
	}
	else if (operand.find('-') == -1)//if is like #(label)
	{
		std::string label = operand.substr(operand.find('(') + 1, operand.find(')') - operand.find('(')-1);//label, the string before '-'
		label = trim_begin_end_space(label);
		ea_t ea1 = get_name_ea(BADADDR, label.c_str());//get label's address
		operand = operand.substr(0, operand.find('#'));
		operand += "#0x" + dec2hex(ea1) + ']';
	}
	return operand;
}

//In ARM, there are cases when ADD PC have next_ea pointing to somewhere in this function but this address has not been disassembled by IDA Pro.
//Thus we need to identify this case.
bool ARM_is_code_ea(ea_t ea)
{
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (Mnem =="")
		return false;
	else
		return true;
}


void arm_convert_operand2offset_type(ea_t ea)
{
	bool success;
	int op0_type = -1, op1_type = -1, op2_type = -1;
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
		success = set_op_type(ea, num_flag(), 0);
	else if (op1_type == 3 || op1_type == 4)
		success = set_op_type(ea, num_flag(), 1);
	else if (op2_type == 3 || op2_type == 4)
		success = set_op_type(ea, num_flag(), 2);
	else if (op1_type == 5)
		success = set_op_type(ea, num_flag(), 1);
}