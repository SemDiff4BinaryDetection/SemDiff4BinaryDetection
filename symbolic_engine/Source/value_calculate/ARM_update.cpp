#include "../../Headers/value_calculate/ARM_update.h"

int ARM_BIT = 32;
int ARM_subfindupdate(ea_t ea, func_t* func, std::string operand0, std::string operand1, std::string operand2, int mode)
{
	std::string defined_value, defined_value1,defined_value2,defined_value3,shift_mnem,tmp,tmp1,tmp2,tmp3;
	std::string num;
	qstring Mnemq;
	std::string Mnem;
	qstring disasm,buffer;
	ea_t ea1;
	int strlen;
	int comma;
	char label[100];
	if (ea==0x12738)
		int breakp = 1;
	
	switch (mode) {
	case 0:/*"MOV reg,reg"*/
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "") 	defined_value1= arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, defined_value1, 0);
		return 0;
	case 1://MOV reg, reg,shift num/reg
		defined_value1 = ARM_process_shift_operand(operand1,1,ea,func);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, defined_value1, 0);
		return 0;
	case 2://MOV reg,num
		ARM_propagate_to_operand(ea, operand1, 0);
		return 0;
	case 3://MVN reg,reg
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "") 	defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "(!("+defined_value1+"))", 0);
		return 0;
	case 4://MVN reg, reg, shift num/reg
		defined_value1 = ARM_process_shift_operand(operand1,1,ea,func);
		ARM_propagate_to_operand(ea, "(!("+defined_value1+"))", 0);
		ARM_propagate_to_operand(ea, "(!(" + defined_value+"))", 1);
		return 0;
	case 5://MVN reg,num
		ARM_propagate_to_operand(ea, "(!("+operand1+"))", 0);
		return 0;
	case 6://MVT reg,num
		tmp= ARM_lookForDefine(operand0, ea, func);
		if (tmp == "")
			tmp = arm_allocate_new_variable(operand0);
		defined_value = operand1 + "<<16|" + tmp;
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 7://LDR, reg, [reg {,num}]        LDR, reg, [reg {,num}]!        LDR, reg, [reg], num   
		if (operand1.find("#(") != -1)//if the offset is translated by IDA to #(label-offset), we need to translate it back to number
		{
			operand1 = ARM_numerize_offset(operand1);
		}
		if (ARM_is_regiter_offset(operand1))
			ARM_LDR_type4_register_offset(operand1, ea,func);
		else if (ARM_is_pre_indexed(operand1))
			ARM_LDR_type4_pre_indexed(operand1, ea,func);
		else if (ARM_is_post_indexed(operand1))
			ARM_LDR_type4_post_indexed(operand1,ea,func);
		return 0;
	case 8://LDR, reg, [reg, +/-reg {,shift}]          LDR, reg, [reg, +/-reg {,shift}] !        LDR, reg, [reg], +/-reg {,shift} 
		if (ARM_is_regiter_offset(operand1))
			ARM_LDR_type3_register_offset(operand1, ea, func);
		else if (ARM_is_pre_indexed(operand1))
			ARM_LDR_type3_pre_indexed(operand1, ea, func);
		else if (ARM_is_post_indexed(operand1))
			ARM_LDR_type3_post_indexed(operand1, ea, func);
		return 0;
	case 9://LDR, reg, label
		//generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
		//tmp= operand1.substr(operand1.find("=(") + 2, operand1.find('-') - operand1.find("=(") - 2);//Get the label of that string
		//num= operand1.substr(operand1.find("=(") + 2, operand1.find('-') - operand1.find("=(") - 2);//Get the label of that string
		//qstrncpy(label,tmp.c_str(), tmp.size());
		//tmp = get_label_value(label,operand0);
		//tmp = ARM_get_label_value(operand1,func);
		set_op_type(ea, num_flag(), 1);
		operand1 = ARM_get_operand(ea, 1);
		operand1 = operand1.substr(operand1.find('=') + 1, operand1.size() - 1 - operand1.find('='));
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = operand1;
		return 0;
	case 10://LDRD, reg, reg, label 
		qstrncpy(label, operand2.c_str(), operand2.size());//get the string label
		tmp = get_label_value(label);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = tmp;//operand0
		ea1 = get_name_ea(BADADDR, label);//get the address of that string
		get_strlit_contents(&buffer, ea1+ DWORD_LEN, -1, STRTYPE_C);//get the string content
		tmp = buffer.c_str();
		if (tmp.empty())
			tmp = arm_allocate_new_variable("R5");
		else
			tmp = '"' + tmp + '"';
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = tmp;//operand1
		return 0;
	case 11://ADR, reg, label
		qstrncpy(label, operand1.c_str(), operand1.size()+1);//get the string label
		ea1 = get_name_ea(BADADDR, label);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = dec2hex(ea1);
		//if (!tmp.empty())//If we successfully got the string content
		//	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = '"'+tmp+'"';
		//else//If unsuccessful
		//	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = operand1;
		return 0;
	case 12://STR, reg, [reg {,num}]           STR, reg, [reg {,num}]!        STR, reg, [reg], num   
		if (operand1.find("#(") != -1)//if the offset is translated by IDA to #(label-offset), we need to translate it back to number
		{
			operand1 = ARM_numerize_offset(operand1);
		}
		if (ARM_is_regiter_offset(operand1))
			ARM_STR_type4_register_offset(operand0, operand1, ea, func);
		else if (ARM_is_pre_indexed(operand1))
			ARM_STR_type4_pre_indexed(operand0, operand1, ea, func);
		else if (ARM_is_post_indexed(operand1))
			ARM_STR_type4_post_indexed(operand0, operand1, ea, func);
		return 0;
	case 13://STR, reg, [reg, reg {,shift}]            STR, reg, [reg, +/-reg {,shift}] !        STR, reg, [reg], +/-reg {,shift} 
		if (ARM_is_regiter_offset(operand1))
			ARM_STR_type3_register_offset(operand0,operand1, ea, func);
		else if (ARM_is_pre_indexed(operand1))
			ARM_STR_type3_pre_indexed(operand0,operand1, ea, func);
		else if (ARM_is_post_indexed(operand1))
			ARM_STR_type3_post_indexed(operand0,operand1, ea, func);
		return 0;
		return 0;
	case 14://LDM reg, {reg-reg}
		ARM_process_LDM(operand0, operand1, ea,func);
		return 0;
	case 15://STM reg, {reg-reg}
		ARM_process_STM(operand0, operand1, ea, func);
		return 0;
	case 16://SWP reg, reg, [reg]
		tmp2= ARM_extract_bracket_base(operand2);
		defined_value2 = ARM_lookForDefine(tmp2,ea,func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(tmp2);
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2, defined_value2});
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = "[" + defined_value2 + "]";
		ARM_look_for_same_displ(0, ea, func);
		defined_value1 = ARM_lookForDefine(operand1,ea,func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value1;
		ARM_my_insn[ea2ARM_my_insn[ea]].operand2 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0 + "=" + defined_value1;
		return 0;
	case 17://ADD PC, table_reg, offset_reg
		ARM_process_switch_case(ea,func,operand0,operand1,operand2);
		return 0;
	case 18://CMP reg,reg
		defined_value1= ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value= ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 19://CMP reg,num
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 20://CMP reg, reg,shift num/reg
		defined_value1=ARM_process_shift_operand(operand1,1,ea,func);
		defined_value= ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, defined_value, 0);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		return 0;
	case 21://ADD reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "+");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("ADC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "+CF)";
		}
		return 0; 
	case 22://ADD reg, reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "+");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("ADC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "+CF)";
		}
		return 0;
	case 23://ADD reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "+");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("ADC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "+CF)";
		}
		return 0;
	case 24://ADD reg, reg
		ARM_arithmatic_propagate_reg_reg(operand0, operand1, ea, func, "+");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("ADC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "+CF)";
		}
		return 0;
	case 25://ADD reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_shift(operand0, operand1, ea, func, "+");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("ADC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "+CF)";
		}
		return 0;
	case 26://ADD reg, num
		ARM_arithmatic_propagate_reg_num(operand0, operand1, ea, func, "+");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("ADC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "+CF)";
		}
		return 0;
	case 27://SUB reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "-");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("SBC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "-CF)";
		}
		return 0;
	case 28://SUB reg, reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "-");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("SBC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "-CF)";
		}
		return 0;
	case 29://SUB reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "-");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("SBC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "-CF)";
		}
		return 0;
	case 30://SUB reg, reg
		ARM_arithmatic_propagate_reg_reg(operand0, operand1, ea, func, "-");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("SBC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "-CF)";
		}
		return 0;
	case 31://SUB reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_shift(operand0, operand1, ea, func, "-");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("SBC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "-CF)";
		}
		return 0;
	case 32://SUB reg, num
		ARM_arithmatic_propagate_reg_num(operand0, operand1, ea, func, "-");
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("SBC") != -1)
		{
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = ARM_my_insn[ea2ARM_my_insn[ea]].operand0.substr(0, ARM_my_insn[ea2ARM_my_insn[ea]].operand0.size() - 1);
			ARM_my_insn[ea2ARM_my_insn[ea]].operand0 += "-CF)";
		}
		return 0;
	case 33://RSB reg, reg, reg
		defined_value1 = ARM_lookForDefine(operand1,ea,func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea,defined_value1,1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		ARM_propagate_to_operand(ea, "("+defined_value2 + "-" + defined_value1+")",0);
		return 0;
	case 34://RSB reg, reg, reg,shift num/reg
		defined_value2 = ARM_process_shift_operand(operand2, 2, ea, func);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea,defined_value1,1);
		ARM_propagate_to_operand(ea,"("+defined_value2+"-"+defined_value1+")",0);
		return 0;
	case 35://RSB reg, reg, num
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "("+operand2 + "-" + defined_value1+")", 0);
		return 0;
	case 36://RSB reg, reg
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "original",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
		ARM_propagate_to_operand(ea, "("+defined_value1+"-"+defined_value+")", 0);
		return 0;
	case 37://RSB reg, reg,shift num/reg
		defined_value1 = ARM_process_shift_operand(operand1, 1, ea, func);
		defined_value = ARM_lookForDefine(operand0,ea,func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "original",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
		ARM_propagate_to_operand(ea, "("+defined_value1 + "-" + defined_value+")", 0);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		return 0;
	case 38://RSB reg, num
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.insert({ "original",ARM_my_insn[ea2ARM_my_insn[ea]].operand0 });
		ARM_propagate_to_operand(ea, "("+operand1 + "-" + defined_value+")", 0);
		return 0;
	case 39://AND reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "&");
		return 0;
	case 40://AND reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "&");
		return 0;
	case 41://AND reg, reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "&");
		return 0;
	case 42://ORR reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "|");
		return 0;
	case 43://ORR reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "|");
		return 0;
	case 44://ORR reg, reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "|");
		return 0;
	case 45://EOR reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "^");
		return 0;
	case 46://EOR reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "^");
		return 0;
	case 47://EOR reg, reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "^");
		return 0;
	case 48://BIC reg, reg, reg
		//ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "&!");
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		ARM_propagate_to_operand(ea, "(" + defined_value1 + "&(!("  + defined_value2 + ")))", 0);
		return 0;
	case 49://BIC reg, reg, num
		//ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "&!");
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "(" + defined_value1 + "&(!(" + operand2 + ")))", 0);
		return 0;
	case 50://BIC reg, reg, reg,shift num/reg
		//ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "&!");
		defined_value2 = ARM_process_shift_operand(operand2, 2, ea, func);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "(" + defined_value1 + "&(!(" + defined_value2 + ")))", 0);
		return 0;
	case 51://ORN reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "|!");
		return 0;
	case 52://ORN reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "|!");
		return 0;
	case 53://ORN reg, reg, reg,shift num/reg
		ARM_arithmatic_propagate_reg_reg_shift(operand1, operand2, ea, func, "|!");
		return 0;
	case 54://REV reg, reg
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value = "("+defined_value1 + "&ff000000)>>24|("+defined_value1+"&ff0000)>>8|("+defined_value1+"&ff00)<<8|("+defined_value1+"&ff)<<24";
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 55://ASR reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, ">>");
		return 0;
	case 56://ASR reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, ">>");
		return 0;
	case 57://LSL reg, reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "<<");
		return 0;
	case 58://LSL reg, reg, num
		ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, "<<");
		return 0;
	case 59://RRX reg, reg
		defined_value1 = ARM_lookForDefine(operand1,ea,func);
		defined_value = "("+defined_value1 + ">>1)&fffffff|((" + defined_value1 + "&1)<<31)";
		ARM_propagate_to_operand(ea, defined_value, 0);
		//ARM_arithmatic_propagate_reg_reg_reg(operand1, "1", ea, func, ">>");
		return 0;
	case 60://RRX reg, reg, num
		//ARM_arithmatic_propagate_reg_reg_num(operand1, operand2, ea, func, ">>");
		return 0;
	case 61://MUL  reg,reg
		ARM_arithmatic_propagate_reg_reg(operand0, operand1, ea, func, "*");
		return 0;
	case 62://MUL  reg,reg, reg
		ARM_arithmatic_propagate_reg_reg_reg(operand1, operand2, ea, func, "*");
		return 0;
	case 63://MLA reg, reg, reg, reg
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea,3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea, "("+defined_value1 + "*" + defined_value2+"+"+defined_value3+")", 0);
		return 0;
	case 64://MLS reg, reg, reg, reg
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea, "("+defined_value1 + "*" + defined_value2 + "-" + defined_value3+")", 0);
		return 0;
	case 65://UMULL reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea, "(("+defined_value2 + "*" + defined_value3+")|ffffffff00000000)",1);
		ARM_propagate_to_operand(ea, "(("+defined_value2 + "*" + defined_value3 + ")|ffffffff)", 0);
		return 0;
	case 66://UMLAL reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		defined_value1= ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, defined_value1+"+(("+defined_value2 + "*" + defined_value3 + ")|ffffffff00000000)", 1);
		ARM_propagate_to_operand(ea, defined_value+"+(("+defined_value2 + "*" + defined_value3 + ")|ffffffff)", 0);
		return 0;
	case 67://SMULxy reg,reg,reg
		
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		if (Mnem == "SMULTB")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+ "|ffffffff)";
		}
		else if (Mnem == "SMULTT")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		else if (Mnem == "SMULBB")
		{
			defined_value1 = "("+defined_value1+ "|ffffffff)";
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		else if (Mnem == "SMULBT")
		{
			defined_value1 = "("+defined_value1+"|ffffffff)";
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		ARM_propagate_to_operand(ea, defined_value1+"*"+defined_value2, 0);
		return 0;
	case 68://SMLAxy reg, reg, reg, reg	
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea,3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		if (Mnem == "SMLATB")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+ "|ffffffff)";
		}
		else if (Mnem == "SMLATT")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		else if (Mnem == "SMLABB")
		{
			defined_value1 = "("+defined_value1+"|ffffffff)";
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		else if (Mnem == "SMLABT")
		{
			defined_value1 = "("+defined_value1+"|ffffffff)";
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		ARM_propagate_to_operand(ea, "("+defined_value1 + "*" + defined_value2+"+"+defined_value3+")", 0);
		return 0;
	case 69://SMULWy reg, reg, reg
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		if (Mnem == "SMULWT")
		{
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		else if (Mnem == "SMULWB")
		{
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		ARM_propagate_to_operand(ea, defined_value1 + "*" + defined_value2, 0);
		return 0;
	case 70://SMLAWy reg, reg, reg, reg
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea,3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		if (Mnem == "SMLAWT")
		{
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		else if (Mnem == "SMLAWB")
		{
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		ARM_propagate_to_operand(ea, "("+defined_value1 + "*" + defined_value2+"+"+defined_value3+")", 0);
		return 0;
	case 71://SMLALxy reg, reg, reg, reg
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		if (Mnem == "SMLALTT")
		{
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
			defined_value3 = "("+defined_value3+"|ffffffff00000000)";
		}
		else if (Mnem == "SMLALTB")
		{
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
			defined_value3 = "("+defined_value3+"|ffffffff)";
		}
		else if (Mnem == "SMLALBB")
		{
			defined_value2 = "("+defined_value2+ "|ffffffff)";
			defined_value3 = "("+defined_value3+"|ffffffff)";
		}
		else if (Mnem == "SMLALBT")
		{
			defined_value2 = "("+defined_value2+"|ffffffff)";
			defined_value3 = "("+defined_value3+"|ffffffff00000000)";
		}
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, "(("+defined_value2 + "*" + defined_value3 + "+" + defined_value1+"<<32|"+defined_value+")|ffffffff00000000)", 1);
		ARM_propagate_to_operand(ea, "((" + defined_value2 + "*" + defined_value3 + "+" + defined_value1 + "<<32|" + defined_value + ")|ffffffff)", 0);
		return 0;
	case 72://SMUAD reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "("+defined_value1+"|ffffffff*"+defined_value2+"|ffffffff+"+defined_value1+"|ffffffff00000000*"+defined_value2+"|ffffffff00000000)", 0);
		return 0;
	case 73://SMUSD reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "("+defined_value1 + "|ffffffff*" + defined_value2 + "|ffffffff-" + defined_value1 + "|ffffffff00000000*" + defined_value2 + "|ffffffff00000000)", 0);
		return 0;
	case 74://SMMUL reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "(("+defined_value1 +"*"+defined_value2+")|ffffffff00000000)", 0);
		return 0;
	case 75://SMMLA reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		tmp3 = ARM_get_operand(ea,3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea, "(("+defined_value1 + "*" + defined_value2 + ")|ffffffff00000000)+"+defined_value3, 0);
		return 0;
	case 76://SMMLS reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea, "("+defined_value3+"<<32-"+"((" + defined_value1 + "*" + defined_value2 + ")|ffffffff00000000))", 0);
		return 0;
	case 77://SMLAD reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea,  "("+defined_value1 + "|ffffffff00000000*" + defined_value2 + "|ffffffff00000000+"+defined_value1+"|ffffffff*"+defined_value2+"|ffffffff+"+defined_value3+")", 0);
		return 0;
	case 78://SMLSD reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		ARM_propagate_to_operand(ea, "("+defined_value1 + "|ffffffff*" + defined_value2 + "|ffffffff-" + defined_value1 + "|ffffffff00000000*" + defined_value2 + "|ffffffff00000000+" + defined_value3+")", 0);
		return 0;
	case 79://SMLALD reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, "(("+defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff+" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" +defined_value1+"<<32|"+defined_value+")|ffffffff)", 0);
		ARM_propagate_to_operand(ea, "((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff+" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff00000000)", 1);
		return 0;
	case 80://SMLSLD reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, "((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff-" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff)", 0);
		ARM_propagate_to_operand(ea, "((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff-" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff00000000)", 1);
		return 0;
	case 81://UMAAL reg, reg, reg, reg
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		tmp3 = ARM_get_operand(ea, 3);
		defined_value3 = ARM_lookForDefine(tmp3, ea, func);
		if (defined_value3 == "")
			defined_value3 = arm_allocate_new_variable(tmp3);
		ARM_propagate_to_operand(ea, defined_value3, 3);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, "(("+defined_value2+"*"+defined_value3+"+"+defined_value+"+"+defined_value1+")|ffffffff)",0);
		ARM_propagate_to_operand(ea, "((" + defined_value2 + "*" + defined_value3 + "+" + defined_value + "+" + defined_value1 + ")|ffffffff00000000)", 1);
		return 0;
	case 82://B reg
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 83:// ADD reg, PC, reg
		defined_value2= ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		ARM_propagate_to_operand(ea, defined_value2, 2);
		ARM_propagate_to_operand(ea, defined_value2, 0);
		return 0;
	case 84: //STREX reg, reg, [reg {,shift}]
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if(defined_value1=="")
			defined_value1= arm_allocate_new_variable(operand1);
		tmp2 = ARM_extract_bracket_base(operand2);
		defined_value2 = ARM_lookForDefine(tmp2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(tmp2);
		defined_value2= ARM_translate_type4_register_offset(operand2, defined_value2);
		ARM_propagate_to_operand(ea, defined_value1, 1);
		ARM_propagate_to_operand(ea, "0", 0);
		ARM_propagate_to_operand(ea, "["+defined_value2+"]="+defined_value1, 2);
		ARM_my_insn[ea2ARM_my_insn[ea]].parameters2.insert({ tmp2,defined_value2 });
		return 0;
	case 85://ROR reg, reg, reg
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value2 = ARM_lookForDefine(operand2, ea, func);
		if (defined_value2 == "")
			defined_value2 = arm_allocate_new_variable(operand2);
		defined_value = "("+defined_value1 + ">>" + defined_value2 + "|" + defined_value1 + "<<" + "(32-" + defined_value2 + "))";
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 86://ROR reg, reg, num
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = "("+defined_value1 + ">>" + operand2 + "|" + defined_value1 + "<<" + "(32-" + operand2 + "))";
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 87://MOVT reg,num
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		defined_value = "(("+defined_value + "&ffff0000)|(" + operand1+"<<16"+"))";
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0= defined_value;
		return 0;
	case 88://MOVW reg,num
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		defined_value =  operand1;
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
		return 0;
	case 89: //MOVW reg,reg  
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		defined_value1= ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = defined_value1;
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
		return 0;
	case 90://unknown Mnem reg, reg
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = "UNKNOWN("+defined_value + "," + defined_value1 + ")";
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
		return 0;
	case 91: //unknown Mnem reg, num
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		defined_value = "UNKNOWN(" + defined_value + "," + operand1 + ")";
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
		return 0;
	case 92://unknown Mnem reg, reg,shift
		defined_value = ARM_lookForDefine(operand0, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(operand0);
		defined_value1 = ARM_process_shift_operand(operand1, 1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = "UNKNOWN(" + defined_value + "," + defined_value1 + ")";
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value;
		return 0;
	case 93:/*RBIT reg, reg*/
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = "(" + defined_value1 + "&80000000h)>>31|(" + defined_value1 + "&40000000h)>>29|(" + defined_value1 + "&20000000h)>>27|("\
			+defined_value1+"&10000000h)>>25|("+defined_value1+"&8000000h)>>23|("+defined_value1+"&4000000h)>>21|("+defined_value1+"&2000000h)>>19|("\
			+defined_value1+"&1000000h)>>17|("+defined_value1+"&800000h)>>15|("+defined_value1+"&400000h)>>13|("+defined_value1+"&200000h)>>11|("\
			+defined_value1+"&100000h)>>9|("+defined_value1+"&80000h)>>7|("+defined_value1+"&40000h)>>5|("+defined_value1+"&20000h)>>3|("\
			+defined_value1+"&10000h)>>1|("+defined_value1+"&8000h)<<1|("+defined_value1+"&4000h)<<3|("+defined_value1+"&2000h)<<5|("+defined_value1\
			+"&1000h)<<7|("+defined_value1+"&800h)<<9|("+defined_value1+"&400h)<<11|("+defined_value1+"&200h)<<13|("+defined_value1+"&100h)<<15|("+\
			defined_value1+"&80h)<<17|("+defined_value1+"&40h)<<19|("+defined_value1+"&20h)<<21|("+defined_value1+"&10h)<<23|("+defined_value1+"&8h)<<25|("\
			+defined_value1+"4h)<<27|("+defined_value1+"&2h)<<29|("+defined_value1+"&1h)<<31";
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 94:/*REV16 reg, reg*/
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = "(" + defined_value1 + "&ff00ff00)>>8|(" + defined_value1 + "&00ff00ff)<<8";
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 95:/*REVSH reg, reg*/
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		defined_value = "(" + defined_value1 + "&ff00)>>8|(" + defined_value1 + "&ff)<<8|("+defined_value1+"&80h)&ffff";
		ARM_propagate_to_operand(ea, defined_value, 0);
		return 0;
	case 96:/*LDRD, reg, reg, [reg {,num}], LDRD, reg, reg, [reg], num, LDRD, reg, reg, [reg ,num]! */
		if (ARM_is_regiter_offset(operand2))
			ARM_LDRD_type4_register_offset(operand2, ea, func);
		else if (ARM_is_pre_indexed(operand2))
			ARM_LDRD_type4_pre_indexed(operand2, ea, func);
		else if (ARM_is_post_indexed(operand2))
			ARM_LDRD_type4_post_indexed(operand2, ea, func);
		return 0;
	case 97:/*STRD reg, reg, [reg{ ,num }]  STRD reg, reg, [reg, num]!STRD reg, reg, [reg], num*/
		if (ARM_is_regiter_offset(operand2))
			ARM_STRD_type4_register_offset(operand0, operand1,operand2, ea, func);
		else if (ARM_is_pre_indexed(operand2))
			ARM_STRD_type4_pre_indexed(operand0, operand1,operand2, ea, func);
		else if (ARM_is_post_indexed(operand2))
			ARM_STRD_type4_post_indexed(operand0, operand1,operand2, ea, func);
		return 0;
	case 98:/*CLZ reg, reg*/
		defined_value1= ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value1;
		//tmp = std::to_string(ARM_BIT - 1)+ "-log2(" + defined_value1 + ")";
		tmp = "bsr(" + defined_value1 + ')';
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = tmp;
		return 0;
	case 99:/*UXT reg, reg*/
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value1;
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value1;
		return 0;
	case 100:/*UXT reg, reg, ror #8/#16/#24*/
		defined_value1 = ARM_process_shift_operand(operand1, 1, ea, func);
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find("UXTB") != -1)
			defined_value1 = defined_value1 + "&ff";
		else if(Mnem.find("UXTH") != -1)
			defined_value1 = defined_value1 + "&ffff";
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value1;
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = defined_value1;
		return 0;
	case 101:/*CTZ reg, reg*/
		defined_value1 = ARM_lookForDefine(operand1, ea, func);
		if (defined_value1 == "")
			defined_value1 = arm_allocate_new_variable(operand1);
		ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = defined_value1;
		//tmp = std::to_string(ARM_BIT - 1)+ "-log2(" + defined_value1 + ")";
		tmp = "bsf(" + defined_value1 + ')';
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = tmp;
		return 0;
	case 102://ADR, reg, num
		ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = operand1;
		return 0;
	}
}

//Cases like moveq when condition does not hold, we need to propagate operand value directly from backward instructions.
void ARM_propagate_insn_value(ea_t ea, func_t* func)
{
	int op0_type = 0, op1_type = 0, op2_type = 0, op3_type = 0;
	std::string operand0, operand1, operand2, operand3;
	int ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
	{
		operand0 = ARM_get_operand(ea, 0);
		op0_type = get_optype(ea, 0);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op0_type, operand0,ea,func,0);
	}
	else if (ea_operand_num == 2)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op0_type, operand0, ea, func, 0);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op1_type, operand1, ea, func, 1);
	}
	else if (ea_operand_num == 3)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = ARM_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op0_type, operand0, ea, func, 0);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op1_type, operand1, ea, func, 1);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op2_type, operand2, ea, func, 2);
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
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op0_type, operand0, ea, func, 0);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op1_type, operand1, ea, func, 1);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op2_type, operand2, ea, func, 2);
		ARM_no_execute_update_insn(&ARM_my_insn[ea2ARM_my_insn[ea]], op3_type, operand3, ea, func, 3);
	}
}

//Not execute the instruction, directly check up history values and update registers in this instruction.
//Parameter 1: pointer to the ARM_my_instruction.
//Parameter 2: operand type.
//Parameter 3: operand.
//Parameter 4: ea_t.
//Parameter 5: func.
//Parameter 6: which operand.
void ARM_no_execute_update_insn(ARM_my_instruction* instrction, int op_type,std::string operand, ea_t ea, func_t* func,int num)
{
	std::string defined_value,tmp;
	std::vector <std::string> reg_list;
	if (op_type == 1 || op_type == 2)//register
	{
		if (num == 0)
		{
			defined_value= ARM_lookForDefine(operand, ea, func);
			if (defined_value == "")
				defined_value = arm_allocate_new_variable(operand);
			instrction->operand0 = defined_value;
		}
		else if (num == 1)
		{
			defined_value = ARM_lookForDefine(operand, ea, func);
			if (defined_value == "")
				defined_value = arm_allocate_new_variable(operand);
			instrction->operand1 = defined_value;
		}
		else if (num == 2)
		{
			defined_value = ARM_lookForDefine(operand, ea, func);
			if (defined_value == "")
				defined_value = arm_allocate_new_variable(operand);
			instrction->operand2 = defined_value;
		}
		else if (num == 3)
		{
			defined_value = ARM_lookForDefine(operand, ea, func);
			if (defined_value == "")
				defined_value = arm_allocate_new_variable(operand);
			instrction->operand3 = defined_value;
		}
	}
	else if (op_type == 8)//reg,shift num
	{
		operand = ARM_translate_shift(operand);
		ARM_process_shift_operand(operand, num, ea, func);
	}
	else if (op_type == 9)//{reg-reg}
	{
		reg_list = ARM_get_reg_list(operand);
		for (int i = 0;i < reg_list.size();i++)
		{
			defined_value = ARM_lookForDefine(reg_list[i], ea, func);
			instrction->parameters1.insert({ reg_list[i],defined_value});
		}
	}
	else if (op_type == 4)//[reg {,num}] 
	{
		tmp = ARM_extract_bracket_base(operand);
		defined_value = ARM_lookForDefine(tmp, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(tmp);
		if(num==0)
			instrction->parameters0.insert({ tmp,defined_value });
		else if(num==1)
			instrction->parameters1.insert({ tmp,defined_value });
		else if(num==2)
			instrction->parameters2.insert({ tmp,defined_value });
		else if(num==3)
			instrction->parameters3.insert({ tmp,defined_value });
	}
	else if (op_type == 3)//[reg, reg {,shift}] 
	{
		bool fake;
		tmp = ARM_extract_bracket_base(operand);
		defined_value = ARM_lookForDefine(tmp, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(tmp);
		if (num == 0)
			instrction->parameters0.insert({ tmp,defined_value });
		else if (num == 1)
			instrction->parameters1.insert({ tmp,defined_value });
		else if (num == 2)
			instrction->parameters2.insert({ tmp,defined_value });
		else if (num == 3)
			instrction->parameters3.insert({ tmp,defined_value });
		tmp = ARM_extract_bracket_second_register(operand, fake);
		defined_value = ARM_lookForDefine(tmp, ea, func);
		if (defined_value == "")
			defined_value = arm_allocate_new_variable(tmp);
		if (num == 0)
			instrction->parameters0.insert({ tmp,defined_value });
		else if (num == 1)
			instrction->parameters1.insert({ tmp,defined_value });
		else if (num == 2)
			instrction->parameters2.insert({ tmp,defined_value });
		else if (num == 3)
			instrction->parameters3.insert({ tmp,defined_value });
	}
}