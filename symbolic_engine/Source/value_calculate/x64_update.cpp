#include "../../Headers/value_calculate/x64_update.h"
#include "../../Headers/value_calculate/x64_mylibrary.h";



int x64_subfindupdate(ea_t ea, func_t* func, std::string operand0 ,std::string operand1,std::string operand2, int mode) {
	
		qstring disasm;
		std::string defined_value, defined_value1,disasms,address,defined_value2;
		int result;
		std::string num;
		int comma, tmp;
		qstring Mnemq; 
		std::string Mnem;
		insn_t insn;
		uval_t out;
		ea_t ea1;
		qstring buffer;
		if (ea == 0x454025)
		{
			decode_insn(&insn, ea);

		}
 		switch (mode) {
		case 0: /*"mov reg,reg"*/
			print_insn_mnem(&Mnemq, ea);
			Mnem = Mnemq.c_str();
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			defined_value= x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			if (Mnem == "movd")
			{
				defined_value = x64_movd(operand0, defined_value, defined_value1);
			}
			else if (Mnem == "movq")
				defined_value = x64_movq(operand0, operand1, defined_value, defined_value1);
			else if (Mnem.find("movsx") != -1)
				defined_value = defined_value1;
			else defined_value = x64_get_right_sub_reg(operand1,defined_value,defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;

		case 1:/*"mov reg,[]"*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			defined_value1 = x64_lookForDefine(x64_extractBase(operand1), ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			if (defined_value1 != "")
			{
				x64_only_Rbase_is_defined_propagate(ea, operand0,defined_value, defined_value1, func);
				return 0;
			}
			
			x64_even_Rbase_is_not_defined_propagate(ea, func, operand0,defined_value,operand1);
			return 0;
	
		case 2:/*"mov [],num"*/
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
	/*		if (disasms.find("byte") != -1)
				num = "(" + num + "&0xff)";
			else if (disasm.find("word") != -1)
				num = "(" + num + "&ffff)";
			else if (disasm.find("dword") != -1)
				num = "(" + num + "&0xffffffff)";
			else if (disasm.find("qwird") != -1)
				num = num;*/
			num = operand1;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			if (defined_value != "") { x64_Ldefined_base_propagate(ea, defined_value, num, func);return 0; }
			x64_even_Lundefined_base_propagate(ea, num, func,operand0);
			return 0;

		case 3:/*"mov [],reg"*/
			print_insn_mnem(&Mnemq, ea);
			Mnem = Mnemq.c_str();
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			if (Mnem == "movd")
				defined_value = x64_movd(operand0, x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1);
			else if (Mnem == "movq")
				defined_value = x64_movq(operand0, operand1,x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1);
			else defined_value1 = x64_get_right_sub_reg(operand1,defined_value,defined_value1);
			
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			if (defined_value != "") { x64_Ldefined_base_propagate(ea, defined_value, defined_value1, func);return 0; }
			x64_even_Lundefined_base_propagate(ea, defined_value1, func,operand0);
			return 0;
		case 4:/*mov reg, num*/
			print_insn_mnem(&Mnemq, ea);
			Mnem = Mnemq.c_str();
			num = operand1;
			defined_value = x64_lookForDefine(operand0,ea,func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			defined_value = x64_get_right_sub_reg(operand0,defined_value,num);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 5://push
			return 0;
		case 6://pop
			return 0;
		case 7:/*"lea reg,[]")*/
			decode_insn(&insn, ea);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_lea_explain_member_propagate(ea, func);
			return 0;
		case 8:/*"lea reg,str"*/
			x64_lea_extract_string_content_propagate(ea, func,operand0,operand1);
			return 0;
		case 9:/*"test reg,reg*/

			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") { defined_value1 = x64_allocate_new_variable(operand1); }
			x64_propagate_to_right_operand(ea, defined_value1);
			if (operand0 == operand1) { x64_propagate_to_left_operand(ea, defined_value1); return 0; }
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") { defined_value = x64_allocate_new_variable(operand0); }
			x64_propagate_to_left_operand(ea, defined_value);
			return 0;

		case 10:/*"test reg,num*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") { defined_value = x64_allocate_new_variable(operand0); }
			x64_propagate_to_left_operand(ea, defined_value);
			return 0;
		case 11:/*"test [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") 
			{ defined_value = x64_allocate_new_variable(x64_extractBase(operand0)); }
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			return 0;
		case 12:/*"cmp [],reg*/
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") { defined_value1 = x64_allocate_new_variable(operand1); }
			x64_propagate_to_right_operand(ea, defined_value1);

			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") { defined_value = x64_allocate_new_variable(x64_extractBase(operand0)); }
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			return 0;
		case 13:/*"xor eax,eax*/
			//defined_value = x64_lookForDefine(operand0,ea,func);
			//if (defined_value == "") { defined_value1 = x64_allocate_new_variable(operand0); }
			//x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"original",defined_value});
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "0";
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = "0";
			return 0;
		case 14:/*"add reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "+");
			return 0;
		case 15:/*"add reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "+");
			return 0;
		case 16:/*"add reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "+");
			return 0;
		case 17:/*"add [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "+");
			return 0;
		case 18:/*"add [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "+");
			return 0;
		case 19:/*"sub reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "-");
			return 0;
		case 20:/*"sub reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "-");
			return 0;
		case 21:/*"sub reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "-");
			return 0;
		case 22:/*"sub [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "-");
			return 0;
		case 23:/*"sub [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "-");
			return 0;
		case 24:/*"imul reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "*");
			return 0;
		case 25:/*"imul reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "*");
			return 0;
		case 26:/*imul reg,reg,num*/
			comma = x64_count_comma_ea(ea);
			if (comma == 1)
			{
				x64_get_reg_val(ea, operand0, func, defined_value1);
				num = operand1;
				if (num[0] == '-')
					num = "(-(" + num.substr(1, num.size() - 1) + "))";
				x64_arithmatic_propagate_reg_reg_num(operand0, defined_value1, "dup 1", num, ea, "*");
			}
			else if (comma == 2)
			{
				x64_get_reg_val(ea, operand1, func, defined_value1);
				x64_get_reg_val(ea, operand0, func, defined_value);
				num = operand2;
				if (num[0] == '-')
					num = "(-(" + num.substr(1, num.size() - 1) + "))";
				x64_arithmatic_propagate_reg_reg_num(operand1, defined_value, defined_value1, num, ea, "*");

			}
			return 0;
		case 27:/*"imul reg,[],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value1);
			x64_arithmatic_propagate_reg_disp_num(operand0, ea, "*", defined_value1);
			return 0;
		case 29:/*"div reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_div_propagate_reg(operand0, defined_value, ea, func, "/");
			return 0;
		case 30:/*"div []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_div_propagate_disp(ea, func, "/");
			return 0;
		case 31:/*mul/imul reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_mul_single_propagate_reg(operand0, defined_value, ea, func, "*");
			return 0;
		case 32:/*mul/imul []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_mul_single_propagate_disp(ea, func, "*");
			return 0;
		case 34:/*"rol reg,num*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value});
			defined_value = x64_rotate_shift_reg(operand0,defined_value,operand1,"<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "("+defined_value+")";//update left operand
			return 0;
		case 35:/*"rol [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
			defined_value = x64_rotate_shift_disp(disasms, x64_my_insn[ea2x64_my_insn[ea]].operand0, operand1,"<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;//update left operand
			return 0;
		case 36: /*"ror reg,num*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value = x64_rotate_shift_reg(operand0, defined_value, operand1, ">>");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "("+defined_value+")";//update left operand
			return 0;
		case 37:/*"ror [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
			defined_value = x64_rotate_shift_disp(disasms, x64_my_insn[ea2x64_my_insn[ea]].operand0, operand1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;//update left operand
			return 0;
		case 38:/*"and reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "&");
			return 0;
		case 39:/*"and reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "&");
			return 0;
		case 40:/*"and reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "&");
			return 0;
		case 41:/*"and [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "&");
			return 0;
		case 42:/*"and [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "&");
			return 0;
		case 43:/*"or reg,reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "|");
			return 0;
		case 44:/*"or reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "|");
			return 0;
		case 45:/*"or reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "|");
			return 0;
		case 46:/*"or [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "|");
			return 0;
		case 47:/*"or [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "|");
			return 0;
		case 48:/*call [rax]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_further_explain_displace(ea, 0, func, 1);
			x64_look_for_same_displ(0, ea, func);
			return 0;
		case 49:/*call rax*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value != "")
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			else
			{
				defined_value = x64_allocate_new_variable(operand0);
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			}
			return 0;
		case 50:/*punpck xmm0,xmm1*/
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "")	defined_value = x64_allocate_new_variable(operand0);
			print_insn_mnem(&Mnemq, ea);
			Mnem = Mnemq.c_str();
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_punpck(operand1,defined_value,defined_value1,Mnem);
			return 0;

		case 51:/*inc reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + "+1)";
			return 0;
		case 52:/*dec reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + "-1)";
			return 0;
		case 53://cmp reg, []
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			defined_value1 = x64_lookForDefine(x64_extractBase(operand1), ea, func);
			if (defined_value1 == "") { defined_value1 = x64_allocate_new_variable(x64_extractBase(operand1)); }
			x64_define_base(ea, 1, defined_value1);
			x64_further_explain_displace(ea, 1, func, defined_value1.length() + 2);
			x64_look_for_same_displ(1, ea, func);
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") { defined_value = x64_allocate_new_variable(operand0); }
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 54://not reg
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(!(" + defined_value+"))";
			return 0;
		case 55://neg reg
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(-(" + defined_value+"))";
			return 0;
		case 56://xor rax, rbx
			if (operand0 == operand1)
			{
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = "0";
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = "0";
				return 0;
			}
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "^");
			return 0;
		case 57: //xor reg, num
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "^");
			return 0;
		case 58: //xor [], num
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "^");
			return 0;
		case 59: //xor reg, []
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "^");
			return 0;
		case 60:/*"shl reg,num*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value = sub_shift(defined_value, operand0, operand1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "("+defined_value+")";
			return 0;
		case 61:/*"shl [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			//x64_propagate_to_left_operand(ea, "<<" + operand1);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
				defined_value2= x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=')+1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size()-1-\
					x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address+"=(" + defined_value2+"<<"+operand1 + ")";
			return 0;
		case 62: /*"shr reg,num*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value});
			defined_value = sub_shift(defined_value, operand0, operand1, ">>");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "("+defined_value+")";
			return 0;
		case 63:/*"shr [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			//x64_propagate_to_left_operand(ea, ">>" + operand1);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
				defined_value2= x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=')+1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size()-1-\
					x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address+"=(" + defined_value2+">>"+operand1 + ")";
			return 0;
		case 64:/*set reg*/
			tmp = rand() % 2;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = std::to_string(tmp);
			return 0;
		case 65:/*cmov reg, reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			tmp = rand() % 2;
			if (tmp==0)
			{
				x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			}
			else if (tmp==1)
			{
				defined_value = x64_get_right_sub_reg(operand1, defined_value, defined_value1);
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
				x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			}
			return 0;
		case 66:/*cmov reg,[]*/
			tmp = rand() % 2;
			if (tmp == 0)
			{
				defined_value = x64_lookForDefine(operand0, ea, func);
				if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
				defined_value1 = x64_lookForDefine(x64_extractBase(operand1), ea, func);
				if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(x64_extractBase(operand1));
				x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
				if (defined_value1 != "")
				{
					x64_only_Rbase_is_defined_propagate(ea, operand0, defined_value, defined_value1, func);
					return 0;
				}

				x64_even_Rbase_is_not_defined_propagate(ea, func, operand0, defined_value, operand1);
			}
			else if (tmp==1)
			{
				defined_value = x64_lookForDefine(operand0, ea, func);
				if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
				x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
				x64_get_disp_val(ea, 1, operand1, func);
				x64_look_for_same_displ(1, ea, func);
			}
			return 0;
		case 67:/*"sbb reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 68:/*"sbb reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 69:/*"sbb reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 70:/*"sbb [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 71:/*"sbb [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 73:/*stos*/
			x64_stos(ea,operand0,func);
			return 0;
		case 74:/*scas*/
			x64_scas(ea, operand0, func);
			return 0;
		case 75:/*"adc reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 76:/*"adc reg,[]*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_displ(operand0, defined_value, ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 77:/*"adc reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_num(operand0, defined_value, ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 78:/*"adc [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 79:/*"adc [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_num(ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 80:/*unknown reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN("+ defined_value +")";
			return 0;
		case 81:/*"unknown []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0+"="+ "UNKNOWN(" + x64_my_insn[ea2x64_my_insn[ea]].operand0 +")";
			return 0;
		case 82:/*"unknown reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value+", "+defined_value1 + ")";
			return 0;
		case 83:/*"unknown reg,[]*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value+", "+ x64_my_insn[ea2x64_my_insn[ea]].operand1 + ")";
			return 0;
		case 84:/*"unknown reg,num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value+", "+operand1 + ")";
			return 0;
		case 85:/*"unknown [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0 + "=" + "UNKNOWN(" + x64_my_insn[ea2x64_my_insn[ea]].operand0 +", "+defined_value1+ ")";
			return 0;
		case 86:/*"unknown [],num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0 + "=" + "UNKNOWN(" + x64_my_insn[ea2x64_my_insn[ea]].operand0 +", "+operand1+ ")";
			return 0;
		case 87:/*"unknown reg, reg, reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value+", "+defined_value1 + ")";
			return 0;
		case 88:/*"unknown reg, reg, num*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value+", "+defined_value1 + ")";
			return 0;
		case 89:/*"unknown reg, [], reg*/
			x64_get_reg_val(ea, operand2, func, defined_value2);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find('=') != -1)//[] has '='
				defined_value1 = x64_my_insn[ea2x64_my_insn[ea]].operand1.substr(x64_my_insn[ea2x64_my_insn[ea]].operand1.find('=') + 1, \
					x64_my_insn[ea2x64_my_insn[ea]].operand1.size() - 1 - x64_my_insn[ea2x64_my_insn[ea]].operand1.find('='));
			else//[] does not have =
				defined_value1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value1+", "+ defined_value2 + ")";
			return 0;
		case 90:/*"unknown reg, [], num*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find('=') != -1)//[] has '='
				defined_value1 = x64_my_insn[ea2x64_my_insn[ea]].operand1.substr(x64_my_insn[ea2x64_my_insn[ea]].operand1.find('=') + 1, \
					x64_my_insn[ea2x64_my_insn[ea]].operand1.size() - 1 - x64_my_insn[ea2x64_my_insn[ea]].operand1.find('='));
			else//[] does not have =
				defined_value1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value1 + ", " + operand2 + ")";
			return 0;
		case 91:/*"xchg reg,reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_get_right_sub_reg(operand1, defined_value, defined_value1);;
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = x64_get_right_sub_reg(operand0, defined_value1, defined_value);;
			return 0;
		case 92:/*"xchg reg, []*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_disp_val(ea, 1, operand1, func);
			x64_look_for_same_displ(1, ea, func);
			defined_value1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
			if (defined_value1.find("=") != -1)
				defined_value1 = defined_value1.substr(defined_value1.find("=") + 1, defined_value1.size() - 1 - defined_value1.find("="));
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_get_right_sub_reg(operand0, defined_value, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = x64_get_right_sub_reg(operand0, defined_value1, defined_value);;
			return 0;
		case 93:/*"xchg [],reg*/
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			defined_value = x64_my_insn[ea2x64_my_insn[ea]].operand0;
			if (defined_value.find("=") != -1)
				defined_value = defined_value.substr(defined_value.find("=") + 1, defined_value.size() - 1 - defined_value.find("="));
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_get_right_sub_reg(operand1, defined_value, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = x64_get_right_sub_reg(operand1, defined_value1, defined_value);;
			return 0;
		case 94:/*"cmpxchg [], reg*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);

			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			x64_get_reg_val(ea, "eax", func, defined_value);
			tmp = rand() % 2;
			if (tmp == 0)//store operand1 into operand0
			{
				if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") != -1)
					x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
				x64_my_insn[ea2x64_my_insn[ea]].operand0 += x64_get_right_sub_reg(operand1, x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1);
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "eax",defined_value });
			}
			else if (tmp == 1)//store operand1 into al,ax,eax, rax
			{
				defined_value=x64_get_right_sub_reg(operand1,defined_value, defined_value1);//new value for al,ax,eax,rax
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({"eax",defined_value });
			}
			return 0;
		case 95:/*"cmpxchg reg, reg*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
			tmp = rand() % 2;
			if (tmp == 0)//store operand1 into operand0
			{
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_get_right_sub_reg(operand0,defined_value,defined_value1);
				x64_get_reg_val(ea, "eax", func, defined_value);
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "eax",defined_value });
			}
			else if (tmp == 1)//store operand1 into al,ax,eax, rax
			{
				x64_get_reg_val(ea, "eax", func, defined_value);
				defined_value= x64_get_right_sub_reg(operand1, defined_value, defined_value1);
				x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "eax",defined_value });
			}
			return 0;
		case 96:/*xor [], reg*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	
				defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_arithmatic_propagate_displ_reg(operand1, defined_value1, ea, "^");
			return 0;
		case 97:/*"mov reg,cs:xxx"*/
			if (operand1.find("cs:") != -1)
				operand1 = operand1.substr(operand1.find("cs:") + 3, operand1.size() - 1 - operand1.find("cs:") - 2);
			//ea1 = get_name_ea(BADADDR,operand1.c_str());
			//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
			//defined_value = filter_specific_string(buffer.c_str());
			defined_value = get_label_value(operand1.c_str());
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 98:/*"rol [],reg*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
			defined_value1= x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = x64_rotate_shift_disp(disasms, x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1, "<<");
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address+"=(" + defined_value + ")";//update left operand
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 99:/*"ror [],reg*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = x64_rotate_shift_disp(disasms, x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1, "<<");
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 =address+ "=(" + defined_value + ")";//update left operand
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 100:/*"shl [],reg*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			//x64_propagate_to_left_operand(ea, "<<" + defined_value1);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
				defined_value2= x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=')+1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size()-1-\
					x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address+"=(" + defined_value2+"<<"+defined_value1+ ")";
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 101:/*"shr [],reg*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			//x64_propagate_to_left_operand(ea, ">>" + defined_value1);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
				defined_value2= x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=')+1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size()-1-\
					x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address+"=(" + defined_value2+">>" +defined_value1+ ")";
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 103:/*set []*/
			tmp = rand() % 2;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "=" + std::to_string(tmp);
			return 0;
		case 104:/*"rol reg,reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";//update left operand
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 105:/*"ror reg,reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1= x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value1, ">>");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";//update left operand
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 106:/*"shl reg,reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1= x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = sub_shift(defined_value, operand0, defined_value1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 107:/*"shr reg,reg*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "")
				defined_value1 = x64_allocate_new_variable(operand1);
			defined_value = sub_shift(defined_value, operand0, defined_value1, ">>");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;//update right operand
			return 0;
		case 108:/*inc []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
				defined_value2= x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=")+1,\
					x64_my_insn[ea2x64_my_insn[ea]].operand0.size()-1-x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=(" + defined_value2+"+1)";
			return 0;
		case 109:/*dec []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") + 1, \
					x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=(" + defined_value2 + "-1)";
			return 0;
		case 110:/*not []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") + 1, \
					x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=(!(" + defined_value2 + "))";
			return 0;
		case 111:/*neg []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") + 1, \
					x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - x64_my_insn[ea2x64_my_insn[ea]].operand0.find("="));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("=") == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=(-(" + defined_value2 + "))";
			return 0;
		case 114:/*"unknown reg, reg, []*/
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand2;
			x64_get_disp_val(ea, 1, operand2, func);//Since there is no room for operand2, we just store operand2 at the space for operand1
			x64_look_for_same_displ(1, ea, func);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find("=") != -1)
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand1.substr(x64_my_insn[ea2x64_my_insn[ea]].operand1.find("=") + 1, \
					x64_my_insn[ea2x64_my_insn[ea]].operand1.size() - 1 - x64_my_insn[ea2x64_my_insn[ea]].operand1.find("="));
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find("=") == -1)
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
			x64_get_reg_val(ea, operand1, func, defined_value1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value1 + ", " + defined_value2 + ")";
			return 0;
		case 115:/*"xor reg, label*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "^");
			return 0;
		case 116:/*"xor [], label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "^");
			return 0;
		case 117:/*"add reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "+");
			return 0;
		case 118:/*"add [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "+");
			return 0;
		case 119:/*"sub reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "-");
			return 0;
		case 120:/*"sub [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "-");
			return 0;
		case 121:/*"rol reg,label*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1 = get_label_value(operand1);
			defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";//update left operand
			return 0;
		case 122:/*"rol [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
			defined_value1= get_label_value(operand1);
			defined_value = x64_rotate_shift_disp(disasms, x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;//update left operand
			return 0;
		case 123:/*"ror reg,label*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1 = get_label_value(operand1);
			defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value1, ">>");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";//update left operand
			return 0;
		case 124:/*"ror [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasms = disasm.c_str();
			defined_value1 = get_label_value(operand1);
			defined_value = x64_rotate_shift_disp(disasms, x64_my_insn[ea2x64_my_insn[ea]].operand0, defined_value1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;//update left operand
			return 0;
		case 125:/*"shl reg,label*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1 = get_label_value(operand1);
			defined_value = sub_shift(defined_value, operand0, defined_value1, "<<");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";
			return 0;
		case 126:/*"shl [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			//x64_propagate_to_left_operand(ea, "<<" + operand1);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') + 1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - \
					x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			defined_value1 = get_label_value(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=(" + defined_value2 + "<<" + defined_value1 + ")";
			return 0;
		case 127:/*"shr reg,label*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",defined_value });
			defined_value1 = get_label_value(operand1);
			defined_value = sub_shift(defined_value, operand0, defined_value1, ">>");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "(" + defined_value + ")";
			return 0;
		case 128:/*"shr [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			defined_value = x64_lookForDefine(x64_extractBase(operand0), ea, func);
			if (defined_value == "") defined_value = x64_allocate_new_variable(x64_extractBase(operand0));
			x64_define_base(ea, 0, defined_value);
			x64_further_explain_displace(ea, 0, func, defined_value.length() + 2);
			x64_look_for_same_displ(0, ea, func);
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "original",x64_my_insn[ea2x64_my_insn[ea]].operand0 });
			//x64_propagate_to_left_operand(ea, ">>" + operand1);
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') != -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
				defined_value2 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') + 1, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1 - \
					x64_my_insn[ea2x64_my_insn[ea]].operand0.find('='));
			}
			else if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find('=') == -1)
			{
				address = x64_my_insn[ea2x64_my_insn[ea]].operand0;
				defined_value2 = address;
			}
			defined_value1 = get_label_value(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = address + "=(" + defined_value2 + ">>" + defined_value1 + ")";
			return 0;
		case 129:/*"and reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "&");
			return 0;
		case 130:/*"and [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "&");
			return 0;
		case 131:/*"or reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "|");
			return 0;
		case 132:/*"or [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "|");
			return 0;
		case 133:/*cmov reg, label*/
			defined_value = x64_lookForDefine(operand0, ea, func);
			if (defined_value == "") 	defined_value = x64_allocate_new_variable(operand0);
			defined_value1 = get_label_value(operand1);
			tmp = rand() % 2;
			if (tmp == 0)
			{
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			}
			else if (tmp == 1)
			{
				defined_value = x64_get_right_sub_reg(operand0, defined_value, defined_value1);
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			}
			return 0; 
		case 134:/*"sbb reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 135:/*"sbb [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "-");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "-CF)";
			return 0;
		case 136:/*"adc [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			x64_arithmatic_propagate_displ_label(ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 137:/*"adc reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_label(operand0, defined_value, ea, "+");
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(0, x64_my_insn[ea2x64_my_insn[ea]].operand0.size() - 1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 += "+CF)";
			return 0;
		case 138:/*"unknown reg,label*/
			x64_get_reg_val(ea, operand0, func, defined_value);
			defined_value1 = get_label_value(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = "UNKNOWN(" + defined_value + ", " + defined_value1 + ")";
			return 0;
		case 139:/*"unknown [],label*/
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			x64_get_disp_val(ea, 0, operand0, func);
			x64_look_for_same_displ(0, ea, func);
			defined_value1 = get_label_value(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = x64_my_insn[ea2x64_my_insn[ea]].operand0 + "=" + "UNKNOWN(" + x64_my_insn[ea2x64_my_insn[ea]].operand0 + ", " + defined_value1 + ")";
			return 0;
		case 140:/*movs*/
			x64_movs(ea, func, operand0, operand1);
			return 0;
		case 141:/*bsr reg,reg*/
			defined_value1= x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			defined_value = "bsr(" + defined_value1 + ')';
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 142:/*bsf reg,reg*/
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			defined_value = "bsf(" + defined_value1 + ')';
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 143:/*mov label,reg*/
			defined_value1 = x64_lookForDefine(operand1, ea, func);
			if (defined_value1 == "") 	defined_value1 = x64_allocate_new_variable(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			defined_value = x64_allocate_new_variable(operand1);
			defined_value = '[' + defined_value + "]=" + defined_value1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 144:/*mov label,num*/
			defined_value = x64_allocate_new_variable("rax");
			defined_value = '[' + defined_value + "]=" + operand1;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value;
			return 0;
		case 145:/*"div label*/
			defined_value = get_label_value(operand0);
			x64_div_propagate_label(defined_value, ea, func, "/");
			return 0;
		case 146:/*call label*/
			if (operand0.find('[') == -1)//if only has label but no []
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
			else if (operand0.find('[') != -1)//if not only has label but also has []
			{
				std::string disp = operand0.substr(operand0.find('['), operand0.rfind(']') - operand0.find('[') + 1);
				std::string label= operand0.substr(0, operand0.find('['));
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = disp;
				x64_further_explain_displace(ea, 0, func, 1);
				x64_look_for_same_displ(0, ea, func);
				x64_my_insn[ea2x64_my_insn[ea]].operand0 = label+ x64_my_insn[ea2x64_my_insn[ea]].operand0;

			}
			return 0;
		case 148:/*"imul reg,label,num*/
			defined_value1 = get_label_value(operand1);
			x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;
			x64_get_reg_val(ea, operand0, func, defined_value);
			x64_arithmatic_propagate_reg_disp_num(operand0, ea, "*", defined_value);
			return 0;
		case 149:/*mul label*/
			defined_value1 = get_label_value(operand0);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value1;
			defined_value = "eax";
			x64_get_reg_val(ea, defined_value, func, defined_value);
			//x64_arithmatic_propagate_reg_disp_num(operand0, ea, "*", defined_value);
			defined_value = "((" + defined_value + "*" + defined_value1 + ")>>64)";
			defined_value2= "((" + defined_value + "*" + defined_value1 + ")&ffffffffffffffff)";
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "rdx",defined_value });
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ "rax",defined_value2 });
			return 0;
		}
		
}