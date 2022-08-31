#include "../../Headers/value_calculate/x64_iterator_propagate_handler.h"
void x64_re_update_each_insn(ea_t ea, func_t * func)
{
	if (ea == 0x50429)
		int breakp = 1;
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();

	int op0_type = 0, op1_type = 0, op2_type = 0,index=-1;
	std::string operand0, operand1, operand2;
	int ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
	{
		
		op0_type = get_optype(ea, 0);
		operand0 = x64_get_operand(ea, 0);
	
	}
	else if (ea_operand_num == 2)
	{
		
		op0_type = get_optype(ea, 0);
		operand0 = x64_get_operand(ea, 0);
		op1_type = get_optype(ea, 1);
		operand1 = x64_get_operand(ea, 1);

	}
	else if (ea_operand_num == 3)
	{
		
		op0_type = get_optype(ea, 0);
		operand0 = x64_get_operand(ea, 0);
		op1_type = get_optype(ea, 1);
		operand1 = x64_get_operand(ea, 1);
		op2_type = get_optype(ea, 2);
		operand2 = x64_get_operand(ea, 2);
	}

	//x64_recover_renamed_register(ea, &operand0, &operand1, &operand2, op0_type, op1_type, op2_type, ea_operand_num);
	if (Mnem.find('j') == 0)
	{
		x64_create_new_tmp_x64_my_instruction("", "");
	}
	else if (Mnem == "nop")
	{
		x64_create_new_tmp_x64_my_instruction("", "");
	}
	else if (Mnem.find("cdq") != -1|| Mnem.find("cqo") != -1 || Mnem.find("cbw") != -1 || Mnem.find("cwd") != -1)
	{
		x64_create_new_tmp_x64_my_instruction("", "");
	}
	else if (Mnem == "call" && op0_type == 7)
	{
		x64_create_new_tmp_x64_my_instruction("", "");
	}
	else
	{
		std::string keyword = x64_get_root(Mnem) + " ";
		if (ea_operand_num >= 1)
		{
			if (op0_type == 3 || op0_type == 4)
				keyword += "[]";
			else if (op0_type == 1)
				keyword += "reg";
			else if (op0_type == 2)
				keyword += "label";
		}
		if (ea_operand_num >= 2)
		{
			if (op1_type == 3 || op1_type == 4)
				keyword += ",[]";
			else if (op1_type == 1)
				keyword += ",reg";
			else if (op1_type == 2)
				keyword += ",label";
			else if (op1_type == 5)
				keyword += ",num";
		}
		if (ea_operand_num == 3)
		{
			if (op2_type == 3 || op2_type == 4)
				keyword += ",[]";
			else if (op2_type == 1)
				keyword += ",reg";
			else if (op2_type == 2)
				keyword += ",label";
			else if (op2_type == 5)
				keyword += ",num";
		}
		keyword= x64_rectify_specific_Mnem(Mnem, keyword, ea, op1_type);
		if (x64_Mnem2index.find(keyword) != x64_Mnem2index.end())//recongnize instruction
			index = x64_Mnem2index[keyword];
		else if (x64_Mnem2index.find(keyword) == x64_Mnem2index.end())//do not recongnize instruction
		{
			//unknown mnem
		if (ea_operand_num == 1 && op0_type == 1) { x64_sub_iter_handler(operand0, "", "", 80, ea/*"unknown reg*/); }
		else if (ea_operand_num == 1 && (op0_type == 3 || op0_type == 4)) { x64_sub_iter_handler(operand0, "", "", 81, ea/*"unknown []*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 82, ea/*"unknown reg,reg*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_sub_iter_handler(operand0, operand1, "", 83, ea/*"unknown reg,[]*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 84, ea/*"unknown reg,num*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 138, ea/*"unknown reg,label*/); }
		else if (ea_operand_num == 2 && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 85, ea/*"unknown [],reg*/); }
		else if (ea_operand_num == 2 && (op0_type == 3 || op0_type == 4) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 86, ea/*"unknown [],num*/); }
		else if (ea_operand_num == 2 && (op0_type == 3 || op0_type == 4) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 139, ea/*"unknown [],label*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && op2_type == 1) { x64_sub_iter_handler(operand0, operand1, operand2, 87, ea/*"unknown reg, reg, reg*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && (op2_type == 5)) { x64_sub_iter_handler(operand0, operand1, operand2, 88, ea/*"unknown reg, reg, num*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && (op2_type == 3 || op2_type == 4)) { x64_sub_iter_handler(operand0, operand1, operand2, 113, ea/*"unknown reg, reg, []*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && (op1_type == 3 || op1_type == 4) && op2_type == 1) { x64_sub_iter_handler(operand0, operand1, operand2, 89, ea/*"unknown reg, [], reg*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && (op1_type == 3 || op1_type == 4) && op2_type == 5) {
			x64_sub_iter_handler(operand0, operand1, operand2, 90, ea/*"unknown reg, [], num*/);
		}
		else
			x64_create_new_tmp_x64_my_instruction("", "");
		return;
		}
	}
	switch (index)
	{
	case 48:x64_sub_iter_handler(operand0, "", "", 48/*call [rax]*/,ea);break;
	case 49:x64_sub_iter_handler(operand0, "", "", 49/*call rax*/,ea);break;
	case 146:x64_sub_iter_handler(operand0, "", "", 146/*call label*/, ea);break;
	case 5:x64_sub_iter_handler(operand0, "", "", 5/*push*/,ea); break;
	case 147:x64_sub_iter_handler(operand0, "", "", 5/*push*/, ea); break;
	case 6: x64_sub_iter_handler(operand0, "", "", 6/*pop*/,ea); break;
	case 0: x64_sub_iter_handler(operand0, operand1, "", 0/*"mov reg,reg"*/,ea);break;
	case 97:x64_sub_iter_handler(operand0, operand1, "", 97/*"mov reg,cs:xxx"*/,ea);break;
	case 1:x64_sub_iter_handler(operand0, operand1, "", 1/*"mov reg,[]"*/,ea);break;
	case 4:x64_sub_iter_handler(operand0, operand1, "", 4/*mov reg, num*/,ea);break;
	case 2:x64_sub_iter_handler(operand0, operand1, "", 2/*"mov [],num"*/,ea);break;
	case 3:x64_sub_iter_handler(operand0, operand1, "", 3/*"mov [],reg"*/,ea);break;
	case 7:x64_sub_iter_handler(operand0, operand1, "", 7/*"lea reg,[]")*/,ea);break;
	case 8:x64_sub_iter_handler(operand0, operand1, "", 8/*"lea reg,label"*/,ea);break;
	case 9:x64_sub_iter_handler(operand0, operand1, "", 9/*"test reg,reg*/,ea);break;
	case 10:x64_sub_iter_handler(operand0, operand1, "", 10/*"test reg,num*/,ea);break;
	case 11:x64_sub_iter_handler(operand0, operand1, "", 11/*"test [],num*/,ea);break;
	case 12:x64_sub_iter_handler(operand0, operand1, "", 12/*"test [],reg*/,ea);break;
	//case 13:x64_sub_iter_handler(operand0, operand1, "", 13/*"xor eax,eax*/,ea);break;
	case 56:x64_sub_iter_handler(operand0, operand1, "", 56/*"xor eax,ebx*/,ea);break;
	case 57:x64_sub_iter_handler(operand0, operand1, "", 57/*"xor reg, num*/,ea);break;
	case 115:x64_sub_iter_handler(operand0, operand1, "", 115/*"xor reg, label*/,ea);break;
	case 58:x64_sub_iter_handler(operand0, operand1, "", 58/*"xor [], num*/,ea);break;
	case 116:x64_sub_iter_handler(operand0, operand1, "", 116/*"xor [], label*/,ea);break;
	case 59:x64_sub_iter_handler(operand0, operand1, "", 59/*"xor reg, []*/,ea);break;
	case 96:x64_sub_iter_handler(operand0, operand1, "", 96/*"xor [], reg*/,ea);break;
	case 53:x64_sub_iter_handler(operand0, operand1, "", 53/*"cmp reg, []*/,ea);break;
	case 14:x64_sub_iter_handler(operand0, operand1, "", 14/*"add reg,reg*/,ea);break;
	case 15:x64_sub_iter_handler(operand0, operand1, "", 15/*"add reg,[]*/,ea);break;
	case 16:x64_sub_iter_handler(operand0, operand1, "", 16/*"add reg,num*/,ea);break;
	case 117:x64_sub_iter_handler(operand0, operand1, "", 117/*"add reg,label*/, ea);break;
	case 17:x64_sub_iter_handler(operand0, operand1, "", 17/*"add [],reg*/,ea);break;
	case 18:x64_sub_iter_handler(operand0, operand1, "", 18/*"add [],num*/,ea);break;
	case 118:x64_sub_iter_handler(operand0, operand1, "", 118/*"add [],label*/,ea);break;
	case 19:x64_sub_iter_handler(operand0, operand1, "", 19/*"sub reg,reg*/, ea);break;
	case 20:x64_sub_iter_handler(operand0, operand1, "", 20/*"sub reg,[]*/, ea);break;
	case 21:x64_sub_iter_handler(operand0, operand1, "", 21/*"sub reg,num*/, ea);break;
	case 119:x64_sub_iter_handler(operand0, operand1, "", 119/*"sub reg,label*/, ea);break;
	case 22:x64_sub_iter_handler(operand0, operand1, "", 22/*"sub [],reg*/, ea);break;
	case 23:x64_sub_iter_handler(operand0, operand1, "", 23/*"sub [],num*/, ea);break;
	case 120:x64_sub_iter_handler(operand0, operand1, "", 120/*"sub [],label*/, ea);break;
	case 24:x64_sub_iter_handler(operand0, operand1, "", 24/*"imul reg,reg*/, ea);break;
	case 25:x64_sub_iter_handler(operand0, operand1, "", 25/*"imul reg,[]*/, ea);break;
	case 26:x64_sub_iter_handler(operand0, operand1, operand2, 26/*"imul reg,reg,num*/, ea);break;
	case 27:x64_sub_iter_handler(operand0, operand1, operand2, 27/*"imul reg,[],num*/, ea);break;
	case 148:x64_sub_iter_handler(operand0, operand1, operand2, 148/*"imul reg,label,num*/, ea);break;
	case 31:x64_sub_iter_handler(operand0, "", "", 31/*"mul/imul reg*/, ea);break;
	case 32:x64_sub_iter_handler(operand0, "", "", 32/*"mul/imul []*/, ea);break;
	case 149:x64_sub_iter_handler(operand0, "", "", 149/*"mul/imul label*/, ea);break;
	case 29:x64_sub_iter_handler(operand0, "", "", 29/*"div reg*/, ea);break;
	case 30:x64_sub_iter_handler(operand0, "", "", 30/*"div []*/, ea);break;
	case 145: x64_sub_iter_handler(operand0, "", "", 145/*"div reg*/, ea);break;
	case 34:x64_sub_iter_handler(operand0, operand1, "", 34/*"rol reg,num*/, ea);break;
	case 121:x64_sub_iter_handler(operand0, operand1, "", 121/*"rol reg,label*/, ea);break;
	case 104:x64_sub_iter_handler(operand0, operand1, "", 104/*"rol reg,reg*/, ea);break;
	case 35:x64_sub_iter_handler(operand0, operand1, "", 35/*"rol [],num*/, ea);break;
	case 122:x64_sub_iter_handler(operand0, operand1, "", 122/*"rol [],label*/, ea);break;
	case 98:x64_sub_iter_handler(operand0, operand1, "", 98/*"rol [],reg*/, ea);break;
	case 36:x64_sub_iter_handler(operand0, operand1, "", 36/*"ror reg,num*/, ea);break;
	case 123:x64_sub_iter_handler(operand0, operand1, "", 123/*"ror reg,label*/, ea);break;
	case 37:x64_sub_iter_handler(operand0, operand1, "", 37/*"ror [],num*/, ea);break;
	case 124:x64_sub_iter_handler(operand0, operand1, "", 124/*"ror [],label*/, ea);break;
	case 99: x64_sub_iter_handler(operand0, operand1, "", 99/*"ror [],reg*/, ea);break;
	case 105:x64_sub_iter_handler(operand0, operand1, "", 105/*"ror reg,reg*/, ea);break;
	case 60:x64_sub_iter_handler(operand0, operand1, "", 60/*"shl reg,num*/, ea);break;
	case 125:x64_sub_iter_handler(operand0, operand1, "", 125/*"shl reg,label*/, ea);break;
	case 106:x64_sub_iter_handler(operand0, operand1, "", 106/*"shl reg,reg*/, ea);break;
	case 61:x64_sub_iter_handler(operand0, operand1, "", 61/*"shl [],num*/, ea);break;
	case 126: x64_sub_iter_handler(operand0, operand1, "", 126/*"shl [],label*/, ea);break;
	case 100:x64_sub_iter_handler(operand0, operand1, "", 100/*"shl [],reg*/, ea);break;
	case 62:x64_sub_iter_handler(operand0, operand1, "", 62/*"shr reg,num*/, ea);break;
	case 127:x64_sub_iter_handler(operand0, operand1, "", 127/*"shr reg,label*/, ea);break;
	case 107:x64_sub_iter_handler(operand0, operand1, "", 107/*"shr reg,reg*/, ea);break;
	case 63:x64_sub_iter_handler(operand0, operand1, "", 63/*"shr [],num*/, ea);break;
	case 128:x64_sub_iter_handler(operand0, operand1, "", 128/*"shr [],label*/, ea);break;
	case 101:x64_sub_iter_handler(operand0, operand1, "", 101/*"shr [],reg*/, ea);break;
	case 38:x64_sub_iter_handler(operand0, operand1, "", 38/*"and reg,reg*/, ea);break;
	case 39:x64_sub_iter_handler(operand0, operand1, "", 39/*"and reg,[]*/, ea);break;
	case 40:x64_sub_iter_handler(operand0, operand1, "", 40/*"and reg,num*/, ea);break;
	case 129:x64_sub_iter_handler(operand0, operand1, "", 129/*"and reg,label*/, ea);break;
	case 41:x64_sub_iter_handler(operand0, operand1, "", 41/*"and [],reg*/, ea);break;
	case 42:x64_sub_iter_handler(operand0, operand1, "", 42/*"and [],num*/, ea);break;
	case 130:x64_sub_iter_handler(operand0, operand1, "", 130/*"and [],label*/, ea);break;
	case 43:x64_sub_iter_handler(operand0, operand1, "", 43/*"or reg,reg*/, ea);break;
	case 44:x64_sub_iter_handler(operand0, operand1, "", 44/*"or reg,[]*/, ea);break;
	case 45:x64_sub_iter_handler(operand0, operand1, "", 45/*"or reg,num*/, ea);break;
	case 131:x64_sub_iter_handler(operand0, operand1, "", 131/*"or reg,label*/, ea);break;
	case 46:x64_sub_iter_handler(operand0, operand1, "", 46/*"or [],reg*/, ea);break;
	case 47:x64_sub_iter_handler(operand0, operand1, "", 47/*"or [],num*/, ea);break;
	case 132:x64_sub_iter_handler(operand0, operand1, "", 132/*"or [],label*/, ea);break;
	case 50:x64_sub_iter_handler(operand0, operand1, "", 50/*punpck xmm0,xmm1*/, ea);break;
	case 51:x64_sub_iter_handler(operand0, "", "", 51/*inc reg*/, ea);break;
	case 108:x64_sub_iter_handler(operand0, "", "", 108/*inc []*/, ea);break;
	case 52:x64_sub_iter_handler(operand0, "", "", 52/*dec reg*/, ea);break;
	case 109:x64_sub_iter_handler(operand0, "", "", 109/*dec []*/, ea);break;
	case 54:x64_sub_iter_handler(operand0, "", "", 54/*not reg*/, ea);break;
	case 110:x64_sub_iter_handler(operand0, "", "", 110/*not []*/, ea);break;
	case 55:x64_sub_iter_handler(operand0, "", "", 55/*neg reg*/, ea);break;
	case 111:x64_sub_iter_handler(operand0, "", "", 111/*neg []*/, ea);break;
	case 64:x64_sub_iter_handler(operand0, "", "", 64/*set reg*/, ea);break;
	case 103:x64_sub_iter_handler(operand0, "", "", 103/*set []*/, ea);break;
	case 133:x64_sub_iter_handler(operand0, operand1, "", 133/*cmov reg, label*/, ea);break;
	case 65:x64_sub_iter_handler(operand0, operand1, "", 65/*cmov reg, reg*/, ea);break;
	case 66:x64_sub_iter_handler(operand0, operand1, "", 66/*cmov reg, []*/, ea);break;
	case 67:x64_sub_iter_handler(operand0, operand1, "", 67/*"sbb reg,reg*/, ea);break;
	case 68:x64_sub_iter_handler(operand0, operand1, "", 68/*"sbb reg,[]*/, ea);break;
	case 69:x64_sub_iter_handler(operand0, operand1, "", 69/*"sbb reg,num*/, ea);break;
	case 134:x64_sub_iter_handler(operand0, operand1, "", 134/*"sbb reg,label*/, ea);break;
	case 70:x64_sub_iter_handler(operand0, operand1, "", 70/*"sbb [],reg*/, ea);break;
	case 71:x64_sub_iter_handler(operand0, operand1, "", 71/*"sbb [],num*/, ea);break;
	case 135: x64_sub_iter_handler(operand0, operand1, "", 135/*"sbb [],label*/, ea);break;
	case 75:x64_sub_iter_handler(operand0, operand1, "", 75/*"adc reg,reg*/, ea);break;
	case 76:x64_sub_iter_handler(operand0, operand1, "", 76/*"adc reg,[]*/, ea);break;
	case 77:x64_sub_iter_handler(operand0, operand1, "", 77/*"adc reg,num*/,ea);break;
	case 137:x64_sub_iter_handler(operand0, operand1, "", 137/*"adc reg,label*/, ea);break;
	case 78: x64_sub_iter_handler(operand0, operand1, "", 78/*"adc [],reg*/, ea);break;
	case 79:x64_sub_iter_handler(operand0, operand1, "", 79/*"adc [],num*/, ea);break;
	case 136:x64_sub_iter_handler(operand0, operand1, "", 136/*"adc [],label*/, ea);break;
	case 91:x64_sub_iter_handler(operand0, operand1, "", 91/*"xchg reg,reg*/, ea);break;
	case 92:x64_sub_iter_handler(operand0, operand1, "", 92/*"xchg reg, []*/, ea);break;
	case 93:x64_sub_iter_handler(operand0, operand1, "", 93/*"xchg [],reg*/, ea);break;
	case 94:x64_sub_iter_handler(operand0, operand1, "", 94/*"cmpxchg [], reg*/, ea);break;
	case 95: x64_sub_iter_handler(operand0, operand1, "", 95/*"cmpxchg reg, reg*/, ea);break;
	case 73: x64_sub_iter_handler(operand0, operand1, "", 73/*"stos*/, ea);break;
	case 74: x64_sub_iter_handler(operand0, operand1, "", 74/*"scas*/, ea);break;
	case 140: x64_sub_iter_handler(operand0, operand1, "", 140/*"mov*/, ea);break;
	case 141: x64_sub_iter_handler(operand0, operand1, "", 141/*"bsr reg,reg*/, ea);break;
	case 142: x64_sub_iter_handler(operand0, operand1, "", 142/*"bsf reg,reg*/, ea);break;
	case 143: x64_sub_iter_handler(operand0, operand1, "", 143/*"mov label,reg*/, ea);break;
	case 144: x64_sub_iter_handler(operand0, operand1, "", 144/*"mov label,num*/, ea);break;
	
		//if (Mnem == "call")
		//{
			//warning("%s op_type0=%d", operand0, op0_type);
		//	if (op0_type == 3 || op0_type == 4)
		//		x64_sub_iter_handler(operand0, "", "", 48, ea/*call [rax]*/);
		//	else if (op0_type == 1)
		//		x64_sub_iter_handler(operand0, "", "", 49, ea/*call rax*/);
		//	else
		//		x64_create_new_tmp_x64_my_instruction("", "");
		//	return;
		//}
		//else if (Mnem.find('j') == 0)
		//{
		//	x64_create_new_tmp_x64_my_instruction("", "");
		//	return;
		//}
		//else if (Mnem == "push") { x64_sub_iter_handler("", "", "", 5, ea/*push*/); return; }
		//else if (Mnem == "pop") { x64_sub_iter_handler("", "", "", 6, ea/*pop*/); return; }
		//else if (Mnem == "nop") { x64_create_new_tmp_x64_my_instruction("", "");return; }
		//else if (op0_type == 5) { return; }           //like push 12, 
		//if (ea == 0x1a54)
		//	int breakpoint1 = 9;
		//mov eax,ebx, find defination for ebx
		//if (op0_type == 1 && op1_type == 1 && Mnem.find("mov") != -1) { x64_sub_iter_handler(operand0, operand1, "", 0, ea/*"mov reg,reg"*/); }

		//mov eax,cs:
		//else if (op0_type == 1 && op1_type == 2 && Mnem.find("mov") != -1) { x64_sub_iter_handler(operand0, operand1, "", 97, ea/*"mov reg,cs:"*/); }

		// mov rax, [rbx+14], find defination for rbx
		//else if (op0_type == 1 && (op1_type == 4 || op1_type == 3) && Mnem.find("mov") != -1) { x64_sub_iter_handler(operand0, operand1, "", 1, ea/*"mov reg,[]"*/); }

		//mov eax, 1
		//else if (op0_type == 1 && op1_type == 5 && Mnem.find("mov") != -1) { x64_sub_iter_handler(operand0, operand1, "", 4, ea/*mov reg, num*/);return; }

		//mov [rax+5], 1
		//else if ((op0_type == 4 || op0_type == 3) && op1_type == 5 && Mnem.find("mov") != -1) { x64_sub_iter_handler(operand0, operand1, "", 2, ea/*"mov [],num"*/);return; }

		// mov [rbx+14], rax find defination for rbx
		//else if ((op0_type == 4 || op0_type == 3) && op1_type == 1 && Mnem.find("mov") != -1) { x64_sub_iter_handler(operand0, operand1, "", 3, ea/*"mov [],reg"*/); }

		//lea rax, [rbx+rsi]
		//else if (op0_type == 1 && (op1_type == 4 || op1_type == 3) && Mnem == "lea") { x64_sub_iter_handler(operand0, operand1, "", 7, ea/*"lea reg,[]")*/); }

		//lea rax, "string"
		//else if (op0_type == 1 && op1_type == 2 && Mnem == "lea") { x64_sub_iter_handler(operand0, operand1, "", 8, ea/*"lea reg,str"*/); }

		//test rax,rax or test rax,rbx
		//else if (Mnem == "test" && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 9, ea/*"test reg,reg*/); }

		//test rax,1

		//else if (Mnem == "test" && op0_type == 1 && (op1_type == 5 || op1_type == 2)) { x64_sub_iter_handler(operand0, operand1, "", 10, ea/*"test reg,num*/); }

		//test [],1
		//else if (Mnem == "test" && (op0_type == 4 || op0_type == 3) && (op1_type == 5 || op1_type == 2)) { x64_sub_iter_handler(operand0, operand1, "", 11, ea/*"test [],num*/); }

		//test [],reg
		//else if (Mnem == "test" && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 12, ea/*"test [],reg*/); }

		//xor rax, rax
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 1 && operand0 == operand1) { x64_sub_iter_handler(operand0, operand1, "", 13, ea/*"xor rax, rax*/); }

		//xor reg, reg
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 1 && operand0 != operand1) { x64_sub_iter_handler(operand0, operand1, "", 56, ea/*"xor reg, reg*/); }

		//xor reg, num
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 57, ea/*"xor reg, num*/); }

		//xor reg, label
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 114, ea/*"xor reg, label*/); }

		//xor [], num
		//else if (Mnem.find("xor") != -1 && (op0_type == 3 || op0_type == 4) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 58, ea/*"xor [], num*/); }

		//xor [], label
		//else if (Mnem.find("xor") != -1 && (op0_type == 3 || op0_type == 4) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 115, ea/*"xor [], label*/); }

		//xor reg, []
		//else if (Mnem.find("xor") != -1 && (op0_type == 1) && (op1_type == 3 || op1_type == 4)) { x64_sub_iter_handler(operand0, operand1, "", 59, ea/*"xor reg,[]*/); }

		//xor [], reg
		//else if (Mnem.find("xor") != -1 && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 96, ea/*"xor [], reg*/); }

		//cmp reg,reg
		//else if (Mnem == "cmp" && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 9, ea/*"cmp reg,reg*/); }

		//cmp reg,num
		//else if (Mnem == "cmp" && op0_type == 1 && (op1_type == 5 || op1_type == 2)) { x64_sub_iter_handler(operand0, operand1, "", 10, ea/*"cmp reg,num*/); }

		//cmp [],num
		//else if (Mnem == "cmp" && (op0_type == 4 || op0_type == 3) && (op1_type == 5 || op1_type == 2)) { x64_sub_iter_handler(operand0, operand1, "", 11, ea/*"cmp [],num*/); }

		//cmp [],reg
		//else if (Mnem == "cmp" && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 12, ea/*"cmp [],reg*/); }

		//cmp reg, []
		//else if (Mnem == "cmp" && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_sub_iter_handler(operand0, operand1, "", 53, ea/*"cmp reg,[]*/); }

		//add reg,reg
		//else if (Mnem.find("add") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 14, ea/*"add reg,reg*/); }

		//add reg,[]
		//else if (Mnem.find("add") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, operand1, "", 15, ea/*"add reg,[]*/); }

		//add reg,num
		//else if (Mnem.find("add") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 16, ea/*"add reg,num*/); }

		//add reg,label
		//else if (Mnem.find("add") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 116, ea/*"add reg,label*/); }

		//add [],reg
		//else if (Mnem.find("add") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 17, ea/*"add [],reg*/); }

		//add [],num
		//else if (Mnem.find("add") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 18, ea/*"add [],num*/); }

		//add [],label
		//else if (Mnem.find("add") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 117, ea/*"add [],label*/); }

		//sub  reg,reg
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 19, ea/*"sub reg,reg*/); }

		//sub reg,[]
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, operand1, "", 20, ea/*"sub reg,[]*/); }

		//sub reg,num
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 21, ea/*"sub reg,num*/); }

		//sub reg,label
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 118, ea/*"sub reg,label*/); }

		//sub [],reg
		//else if (Mnem.find("sub") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 22, ea/*"sub [],reg*/); }

		//sub [],num
		//else if (Mnem.find("sub") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 23, ea/*"sub [],num*/); }

		//sub [],label
		//else if (Mnem.find("sub") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 119, ea/*"sub [],label*/); }

		//imul  reg,reg
		//else if (Mnem.find("imul") != -1 && op0_type == 1 && op1_type == 1 && ea_operand_num == 2) { x64_sub_iter_handler(operand0, operand1, "", 24, ea/*"imul reg,reg*/); }

		//imul reg,[]
		//else if (Mnem.find("imul") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3) && ea_operand_num == 2) { x64_sub_iter_handler(operand0, operand1, "", 25, ea/*"imul reg,[]*/); }

		//imul reg,reg,num
		//else if (Mnem.find("imul") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { x64_sub_iter_handler(operand0, operand1, operand2, 26, ea/*"imul reg,reg,num*/); }

		//imul reg,[],num
		//else if (Mnem.find("imul") != -1 && (op0_type == 1 && (op1_type == 4 || op1_type == 3) && op2_type == 5)) { x64_sub_iter_handler(operand0, operand1, operand2, 27, ea/*"imul reg,[],num*/); }

		//mul reg
		//else if (Mnem.find("mul") != -1 && ea_operand_num == 2 && op1_type == 1) { x64_sub_iter_handler(operand0, "", "", 31, ea/*"mul/imul reg*/); }

		//mul []
		//else if (Mnem.find("mul") != -1 && ea_operand_num == 2 && (op1_type == 3 || op1_type == 4)) { x64_sub_iter_handler(operand0, "", "", 32, ea/*"mul/imul []*/); }

		//div  reg
		//else if (Mnem.find("div") != -1 && op1_type == 1) { x64_sub_iter_handler(operand0, "", "", 29, ea/*"div reg*/); }

		//div []
		//else if (Mnem.find("div") != -1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, "", "", 30, ea/*"div []*/); }

		//rol reg,num
		//else if ((Mnem.find("rol") != -1) && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 34, ea/*"rol reg,num*/); }

		//rol reg,label
		//else if ((Mnem.find("rol") != -1) && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 120, ea/*"rol reg,label*/); }

		//rol reg,reg
		//else if ((Mnem.find("rol") != -1) && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 104, ea/*"rol reg,reg*/); }

		//rol [],num
		//else if ((Mnem.find("rol") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 35, ea/*"rol [],num*/); }

		//rol [],label
		//else if ((Mnem.find("rol") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 121, ea/*"rol [],label*/); }

		//rol [],reg
		//else if ((Mnem.find("rol") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 98, ea/*"rol [],reg*/); }

		//ror reg,num
		//else if ((Mnem == "ror") && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 36, ea/*"ror reg,num*/); }

		//ror reg,label
		//else if ((Mnem == "ror") && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 122, ea/*"ror reg,label*/); }

		//ror reg,reg
		//else if ((Mnem == "ror") && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 105, ea/*"ror reg,reg*/); }

		//ror [],num
		//else if ((Mnem.find("ror") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 37, ea/*"ror [],num*/); }

		//ror [],label
		//else if ((Mnem.find("ror") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 123, ea/*"ror [],label*/); }

		//ror [],reg
		//else if ((Mnem.find("ror") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 99, ea/*"ror [],reg*/); }

		//and  reg,reg
		//else if (Mnem.find("and") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 38, ea/*"and reg,reg*/); }

		//and reg,[]
		//else if (Mnem.find("and") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, operand1, "", 39, ea/*"and reg,[]*/); }

		//and reg,num
		//else if (Mnem.find("and") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 40, ea/*"and reg,num*/); }

		//and reg,label
		//else if (Mnem.find("and") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 124, ea/*"and reg,label*/); }

		//and [],reg
		//else if (Mnem.find("and") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 41, ea/*"and [],reg*/); }

		//and [],num
		//else if (Mnem.find("and") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 42, ea/*"and [],num*/); }

		//and [],label
		//else if (Mnem.find("and") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 125, ea/*"and [],label*/); }

		//or  reg,reg
		//else if (Mnem.find("or") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 43, ea/*"or reg,reg*/); }

		//or reg,[]
		//else if (Mnem.find("or") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, operand1, "", 44, ea/*"or reg,[]*/); }

		//or reg,num
		//else if (Mnem.find("or") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 45, ea/*"or reg,num*/); }

		//or reg,label
		//else if (Mnem.find("or") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 126, ea/*"or reg,label*/); }

		//or [],reg
		//else if (Mnem.find("or") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 46, ea/*"or [],reg*/); }

		//or [],num
		//else if (Mnem.find("or") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 47, ea/*"or [],num*/); }

		//or [],label
		//else if (Mnem.find("or") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 127, ea/*"or [],label*/); }

		//punpck reg, reg
		//else if (Mnem.find("punpck") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 50, ea/*punpck reg, reg*/); }

		//inc reg
		//else if (Mnem == "inc" && op0_type == 1) { x64_sub_iter_handler(operand0, "", "", 51, ea/*inc reg*/); }

		//inc []
		//else if (Mnem == "inc" && (op0_type == 3 || op0_type == 4)) { x64_sub_iter_handler(operand0, "", "", 108, ea/*inc []*/); }

		//dec reg
		//else if (Mnem == "dec" && op0_type == 1) { x64_sub_iter_handler(operand0, "", "", 52, ea/*dec reg*/); }

		//dec []
		//else if (Mnem == "dec" && (op0_type == 3 || op0_type == 4)) { x64_sub_iter_handler(operand0, "", "", 109, ea/*dec []*/); }

		//not reg
		//else if (Mnem == "not" && op0_type == 1) { x64_sub_iter_handler(operand0, "", "", 54, ea/*not reg*/); }

		//not []
		//else if (Mnem == "not" && (op0_type == 3 || op0_type == 4)) { x64_sub_iter_handler(operand0, "", "", 110, ea/*not []*/); }

		//neg reg
		//else if (Mnem == "neg" && op0_type == 1) { x64_sub_iter_handler(operand0, "", "", 55, ea/*neg reg*/); }

		//neg []
		//else if (Mnem == "neg" && (op0_type == 3 || op0_type == 4)) { x64_sub_iter_handler(operand0, "", "", 111, ea/*neg []*/); }

		//shl reg, num
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 60, ea/*shl reg, num*/); }

		//shl reg, label
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 129, ea/*shl reg, label*/); }

		//shl reg,reg
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 106, ea/*shl reg,reg*/); }

		//shl [], num
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && (op0_type == 3 || op0_type == 4) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 61, ea/*shl [], num*/); }

		//shl [], label
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && (op0_type == 3 || op0_type == 4) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 130, ea/*shl [], label*/); }

		//shl [],reg
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 100, ea/*shl [],reg*/); }

		//shr reg, num
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 62, ea/*shr reg, num*/); }

		//shr reg, label
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 131, ea/*shr reg, label*/); }

		//shr reg,reg
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 107, ea/*shr reg,reg*/); }

		//shr [], num
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && (op0_type == 3 || op0_type == 4) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 63, ea/*shr [], num*/); }

		//shr [], label
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && (op0_type == 3 || op0_type == 4) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 132, ea/*shr [], label*/); }

		//shr [],reg
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 101, ea/*shr [],reg*/); }

		//set{z} reg
		//else if (Mnem.find("set") != -1 && op0_type == 1) { x64_sub_iter_handler(operand0, "", "", 64, ea/*set reg*/); }

		//set{z} []
		//else if (Mnem.find("set") != -1 && (op0_type == 3 || op0_type == 4)) { x64_sub_iter_handler(operand0, "", "", 112, ea/*set []*/); }

		//cmov reg, reg
		//else if (Mnem == "cmov" && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 65, ea/*cmov reg, reg*/); }

		//cmov reg, label
		//else if (Mnem == "cmov" && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 133, ea/*cmov reg, label*/); }

		//cmov reg, []
		//else if (Mnem == "cmov" && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_sub_iter_handler(operand0, operand1, "", 66, ea/*cmov reg, []*/); }

		//sbb  reg,reg
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 67, ea/*"sbb reg,reg*/); }

		//sbb reg,[]
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, operand1, "", 68, ea/*"sbb reg,[]*/); }

		//sbb reg,num
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 69, ea/*"sbb reg,num*/); }

		//sbb reg,label
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 134, ea/*"sbb reg,label*/); }

		//sbb [],reg
		//else if (Mnem.find("sbb") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 70, ea/*"sbb [],reg*/); }

		//sbb [],num
		//else if (Mnem.find("sbb") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 71, ea/*"sbb [],num*/); }

		//sbb [],label
		//else if (Mnem.find("sbb") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 135, ea/*"sbb [],label*/); }

		//scas
		//else if (Mnem.find("scas") == 0) {}

		//stos
		//else if (Mnem.find("stos") == 0) { x64_sub_iter_handler(operand0, operand1, "", 73/*"stos num*/, Mnem); }

		//rep
		//else if (Mnem.find("rep") == 0) { x64_sub_iter_handler(operand0, operand1, "", 74, ea/*"rep*/); }

		//adc  reg,reg
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 75, ea/*"adc reg,reg*/); }

		//adc reg,[]
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_sub_iter_handler(operand0, operand1, "", 76, ea/*"adc reg,[]*/); }

		//adc reg,num
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 77, ea/*"adc reg,num*/); }

		//adc reg,label
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 136, ea/*"adc reg,label*/); }

		//adc [],reg
		//else if (Mnem.find("adc") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 78, ea/*"adc [],reg*/); }

		//adc [],num
		//else if (Mnem.find("adc") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_sub_iter_handler(operand0, operand1, "", 79, ea/*"adc [],num*/); }

		//adc [],label
		//else if (Mnem.find("adc") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_sub_iter_handler(operand0, operand1, "", 137, ea/*"adc [],label*/); }

		//xchg reg,reg
		//else if (Mnem == "xchg" && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 91, ea/*"xchg reg,reg*/); }

		//xchg reg, []
		//else if (Mnem == "xchg" && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_sub_iter_handler(operand0, operand1, "", 92, ea/*"xchg reg, []*/); }

		//xchg [],reg
		//else if (Mnem == "xchg" && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 93, ea/*"xchg [],reg*/); }

		//cmpxchg [], reg
		//else if (Mnem == "cmpxchg" && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 94, ea/*"cmpxchg [], reg*/); }

		//cmpxchg reg, reg
		//else if (Mnem == "cmpxchg" && op0_type == 1 && op1_type == 1) { x64_sub_iter_handler(operand0, operand1, "", 95, ea/*"cmpxchg reg, reg*/); }
	}
	//cdqe
	//else if (Mnem.find("cdq")!=-1) { x64_create_new_tmp_x64_my_instruction("",""); }


}

int x64_sub_iter_handler(std::string operand0, std::string operand1, std::string operand2, int mode, std::string Mnem)
{
	std::string defined_value;
	std::string defined_value1;
	switch (mode) {
	case 73:/*stos*/
		if (Mnem == "stosb")
		{
			defined_value1 = x64_iter_lookForDefine("rax");
			defined_value1 = defined_value1 + "&ff";
			defined_value = x64_iter_lookForDefine("rdi");
			defined_value = '[' + defined_value + "]=" + defined_value1;
			x64_create_new_tmp_x64_my_instruction(0, defined_value);
		}
		else if (Mnem == "stosw")
		{
			defined_value1 = x64_iter_lookForDefine("rax");
			defined_value1 = defined_value1 + "&ffff";
			defined_value = x64_iter_lookForDefine("rdi");
			defined_value = '[' + defined_value + "]=" + defined_value1;
			x64_create_new_tmp_x64_my_instruction(0, defined_value);
		}
		else if (Mnem == "stosd")
		{
			defined_value1 = x64_iter_lookForDefine("rax");
			defined_value1 = defined_value1 + "&ffffffff";
			defined_value = x64_iter_lookForDefine("rdi");
			defined_value = '[' + defined_value + "]=" + defined_value1;
			x64_create_new_tmp_x64_my_instruction(0, defined_value);
		}
		else if (Mnem == "stosq")
		{
			defined_value1 = x64_iter_lookForDefine("rax");
			defined_value1 = defined_value1;
			defined_value = x64_iter_lookForDefine("rdi");
			defined_value = '[' + defined_value + "]=" + defined_value1;
			x64_create_new_tmp_x64_my_instruction(0, defined_value);
		}
		return 0;
	}

}

int x64_sub_iter_handler(std::string operand0, std::string operand1, std::string operand2, int mode,ea_t ea)
{
	std::string defined_value, defined_value1,defined_value2;
	std::string num,address;
	qstring Mnemq;
	std::string Mnem;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	int comma;
	int tmp;
	ea_t ea1;
	qstring buffer;
	if (ea==0x4ac707)
		int breakp = 1;
	switch (mode) {
	case 0: /*"mov reg,reg"*/
		defined_value1 = x64_iter_lookForDefine(operand1);
		defined_value= x64_iter_lookForDefine(operand0);
		if (defined_value1 == ""|| defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		else 
		{
			if (Mnem == "movd")
			{
				defined_value = x64_movd(operand0, defined_value, defined_value1);
			}
			else if (Mnem == "movq")
				defined_value = x64_movq(operand0,operand1, defined_value, defined_value1);
			else if(Mnem.find("movsx")!=-1)
				defined_value = defined_value1;
			else defined_value = x64_get_right_sub_reg(operand0, defined_value, defined_value1);
			x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1); 
		}
		return 0;


	case 1:/*"mov reg,[]"*/
		defined_value1 = x64_iter_lookForDefine(x64_extractBase(operand1));
		x64_create_new_tmp_x64_my_instruction(1,operand1);
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value1 != ""&& defined_value != "") 
		{ 
			x64_iter_only_Rbase_is_defined_propagate(operand0,defined_value, defined_value1,Mnem);
			return 0; 
		}
		warning("Error: Strange! Register should have been defined!");
		return 0;


	case 2:/*"mov [],num"*/
		num = operand1;
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		if (defined_value != "") { x64_iter_Ldefined_base_propagate(defined_value, num,ea);return 0; }
		warning("Error: Strange! Register should have been defined!");
		return 0;
	case 3:/*"mov [],reg"*/
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") warning("Error: Strange! Register should have been defined!");
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		if (defined_value != "") { x64_iter_Ldefined_base_propagate( defined_value, defined_value1,ea);return 0; }
		warning("Error: Strange! Register should have been defined!");
		return 0;
	case 4:/*mov reg, num*/
		num = operand1;
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "")warning("Error: Strange! Register should have been defined!");
		defined_value = x64_get_right_sub_reg(operand0, defined_value, num);
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		return 0;
	case 5://push
		x64_create_new_tmp_x64_my_instruction("", "");
		return 0;
	case 6://pop
		x64_create_new_tmp_x64_my_instruction("", "");
		return 0;
	case 7:/*"lea reg,[]")*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		//x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		x64_iter_lea_explain_member_propagate();
		return 0;
	case 8:/*"lea reg,label"*/
		x64_create_new_tmp_x64_my_instruction("","");
		x64_iter_lea_extract_string_content_propagate(operand0,operand1);
		return 0;
	case 9:/*"test reg,reg*/

		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		//propagate_to_right_operand(ea, defined_value1);
		if (operand0 == operand1) { tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value1; return 0; }
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		//propagate_to_left_operand(ea, defined_value);
		return 0;

	case 10:/*"test reg,num*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		//iter_propagate_to_left_operand(ea, defined_value);
		return 0;
	case 11:/*"test [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace( 0,  defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		return 0;
	case 12:/*"cmp [],reg*/
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		//iter_propagate_to_right_operand(ea, defined_value1);

		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		//create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace( 0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		return 0;
	case 13:/*"xor eax,eax*/
		x64_create_new_tmp_x64_my_instruction("0","0");
		return 0;
	case 14:/*"add reg,reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1,  "+");
		return 0;
	case 15:/*"add reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "+");
		return 0;
	case 16:/*"add reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_num(operand0,defined_value, operand1, "+");
		return 0;
	case 17:/*"add [],reg*/
		x64_iter_get_reg_val( operand1,  defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		x64_iter_get_disp_val( 0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_reg(operand1,defined_value1, "+");
		return 0;
	case 18:/*"add [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "+");
		return 0;
	case 19:/*"sub reg,reg*/
		x64_iter_get_reg_val( operand0,  defined_value);
		x64_iter_get_reg_val( operand1,  defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1, "-");
		return 0;
	case 20:/*"sub reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0,defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "-");
		return 0;
	case 21:/*"sub reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_num(operand0,defined_value, operand1, "-");
		return 0;
	case 22:/*"sub [],reg*/
		x64_iter_get_reg_val(operand1,  defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_reg(operand1,defined_value1, "-");
		return 0;
	case 23:/*"sub [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "-");
		return 0;
	case 24:/*"imul reg,reg*/
		x64_iter_get_reg_val( operand0, defined_value);
		x64_iter_get_reg_val( operand1,  defined_value1);
		x64_create_new_tmp_x64_my_instruction(operand0, operand1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1, "*");
		return 0;
	case 25:/*"imul reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "*");
		return 0;
	case 26:/*imul reg,reg,num*/
		comma = x64_count_comma_ea(ea);
		if (comma==1)
		{
			x64_iter_get_reg_val(operand0, defined_value);
			num = operand1;
			if (num[0] == '-')
				num = "(-(" + num.substr(1, num.size() - 1) + "))";
			x64_create_new_tmp_x64_my_instruction(1, num);
			x64_iter_arithmatic_propagate_reg_num(operand0, defined_value, num, "*");
		}
		else if (comma==2)
		{
			x64_iter_get_reg_val(operand0, defined_value);
			x64_iter_get_reg_val( operand1, defined_value1);
			num = operand2;
			if (num[0] == '-')
				num = "(-(" + num.substr(1, num.size() - 1) + "))";
			x64_create_new_tmp_x64_my_instruction("","");
			x64_iter_arithmatic_propagate_reg_reg_num(operand1, defined_value, defined_value1, num, "*");
		}
		return 0;
	case 27:/*"imul reg,[],num*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		num = operand2;
		if (num[0] == '-')
			num = "(-(" + num.substr(1, num.size() - 1) + "))";
		x64_iter_arithmatic_propagate_reg_disp_num(ea,defined_value,num, "*");
		return 0;
	case 29:/*"div reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0,"");
		x64_iter_div_propagate_reg(operand0, defined_value, "/");
		return 0;
	case 30:/*"div []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_div_propagate_disp(ea,"/");
		return 0;
	case 31:/*"mul/imul reg*/
		x64_create_new_tmp_x64_my_instruction("","");
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_iter_mul_single_propagate_reg(operand0, defined_value, ea, "*");
		return 0;
	case 32:/*"mul/imul []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_mul_single_propagate_disp(ea, "*");
		return 0;
	case 34:/*"rol reg,num*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = defined_value;
		defined_value = x64_rotate_shift_reg(operand0, defined_value, operand1, "<<");
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1});
		return 0;
	case 35:/*"rol [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base( 0, defined_value);
		x64_iter_further_explain_displace( 0,  defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value = x64_rotate_shift_disp(disasms, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0, operand1, "<<");
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0= defined_value;
		return 0;
	case 36: /*"ror reg,num*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = defined_value;
		defined_value = x64_rotate_shift_reg(operand0, defined_value, operand1, ">>");
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"original",defined_value1});
		return 0;
	case 37:/*"ror [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0,  defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value = x64_rotate_shift_disp(disasms, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0, operand1, ">>");
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0= defined_value;
		return 0;
	case 38:/*"and reg,reg*/
		x64_iter_get_reg_val(operand0,  defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(defined_value,defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1, "&");
		return 0;
	case 39:/*"and reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		//x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0,  defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value,  "&");
		return 0;
	case 40:/*"and reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0,"");
		x64_iter_arithmatic_propagate_reg_num(operand0,defined_value, operand1, "&");
		return 0;
	case 41:/*"and [],reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0=operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_reg(operand1,defined_value1,  "&");
		return 0;
	case 42:/*"and [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "&");
		return 0;
	case 43:/*"or reg,reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_iter_get_reg_val(operand0,  defined_value);
		x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1, "|");
		return 0;
	case 44:/*"or reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "|");
		return 0;
	case 45:/*"or reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_num(operand0,defined_value, operand1, "|");
		return 0;
	case 46:/*"or [],reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_reg(operand1,defined_value1, "|");
		return 0;
	case 47:/*"or [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "|");
		return 0;
	case 48:/*call [rax]*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_further_explain_displace(0, 1);
		x64_iter_look_for_same_displ(0);
		return 0;
	case 49:/*call rax*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value != "")
		{
			x64_create_new_tmp_x64_my_instruction(0, defined_value);
		}
		else { warning("error: Strange! register should have been defined!"); }
		return 0;
	case 50:/*unpck xmm0,xmm1*/
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction(x64_punpck(operand1,defined_value, defined_value1,Mnem), defined_value1);
		return 0;
	case 51:/*inc reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = defined_value + "+1";
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		return 0;
	case 52:/*dec reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = defined_value + "-1";
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		return 0;
	case 53://cmp reg, []
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction(0, defined_value);

		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = operand1;
		defined_value1 = x64_iter_lookForDefine(x64_extractBase(operand1));
		if (defined_value1 == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_iter_define_base(1, defined_value1);
		x64_iter_further_explain_displace(1, defined_value1.length() + 2);
		x64_iter_look_for_same_displ(1);
		return 0;
	case 54://not reg
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		defined_value = "(!(" + defined_value + "))";
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		return 0;
	case 55://neg reg
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		defined_value = "(-(" + defined_value + "))";
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		return 0;
	case 56://xor rax, rbx
		if (operand0 == operand1)
		{
			x64_create_new_tmp_x64_my_instruction("0", "0");
			return 0;
		}
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("Error: Strange! Register should have been defined!"); }
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand1, defined_value, defined_value1, "^");
		return 0;
	case 57: //xor reg, num
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		//defined_value = "(" + defined_value + "^" + operand1 + ")";
		x64_create_new_tmp_x64_my_instruction("","");
		x64_iter_arithmatic_propagate_reg_num(operand0, defined_value, operand1, "^");
		return 0;
	case 58: //xor [], num
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "^");
		return 0;
	case 59: //xor reg, []
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "^");
		return 0;
	case 60:/*"shl reg,num*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = defined_value;
		defined_value = sub_shift(defined_value, operand0, operand1, "<<");;
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		return 0;
	case 61:/*"shl [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2= tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=')+1,\
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size()-1- tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address+"=("+defined_value2+"<<" + operand1+")";
		return 0;
	case 62: /*"shr reg,num*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); };
		defined_value = sub_shift(defined_value, operand0, operand1, ">>");;
		defined_value1 = defined_value;
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		return 0;
	case 63:/*"shr [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2= tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=')+1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size()-1- tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address+"=("+defined_value2+">>" + operand1+")";
		return 0;
	case 64:/*set reg*/
		tmp = rand() % 2;
		defined_value = std::to_string(tmp);
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		return 0;
	case 65:/*cmov reg, reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		tmp = rand() % 2;
		if (tmp == 0)
		{
			x64_create_new_tmp_x64_my_instruction(defined_value,defined_value1);
		}
		else if (tmp == 1)
		{
			defined_value = x64_get_right_sub_reg(operand1, defined_value, defined_value1);
			x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		}
		return 0;
	case 66:/*cmov reg,[]*/
		tmp = rand() % 2;
		if (tmp == 0)
		{
			defined_value = x64_iter_lookForDefine(operand0);
			if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
			defined_value1 = x64_iter_lookForDefine(x64_extractBase(operand1));
			if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
			x64_create_new_tmp_x64_my_instruction(1, operand1);
			if (defined_value1 != "")
			{
				x64_iter_only_Rbase_is_defined_propagate(operand0,defined_value,defined_value1,Mnem);
				return 0;
			}

			{ warning("error: Strange! register should have been defined!"); }
		}
		else if (tmp == 1)
		{
			defined_value = x64_iter_lookForDefine(operand0);
			if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
			x64_create_new_tmp_x64_my_instruction(0, defined_value);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = operand1;
			x64_iter_get_disp_val(1, operand1);
			x64_iter_look_for_same_displ(1);
		}
		return 0;
	case 67:/*"sbb reg,reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 +="-CF";
		return 0;
	case 68:/*"sbb reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		//x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "-CF";
		return 0;
	case 69:/*"sbb reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_num(operand0,defined_value, operand1, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "-CF";
		return 0;
	case 70:/*"sbb [],reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_reg(operand1,defined_value1, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "-CF";
		return 0;
	case 71:/*"sbb [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "-CF";
		return 0;
	case 73:/*stos*/
		x64_create_new_tmp_x64_my_instruction("","");
		x64_iter_stos(ea, operand0);
		return 0;
	case 74:/*scas*/
		x64_create_new_tmp_x64_my_instruction("", "");
		x64_iter_scas(ea, operand0);
		return 0;
	case 75:/*"adc reg,reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		x64_iter_arithmatic_propagate_reg_reg(operand0,defined_value, defined_value1, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 76:/*"adc reg,[]*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		//x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_arithmatic_propagate_reg_displ(operand0,defined_value, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 77:/*"adc reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_num(operand0,defined_value, operand1, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 78:/*"adc [],reg*/
		x64_iter_get_reg_val(operand1, defined_value1);

		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_reg(operand1,defined_value1, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 79:/*"adc [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_num(ea,operand1, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 80:/*unknown reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "UNKNOWN("+defined_value+")");
		return 0;
	case 81:/*"unknown []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN("+ tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0+")";
		return 0;
	case 82:/*"unknown reg,reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction("UNKNOWN("+defined_value+","+defined_value1+")", defined_value1);
		return 0;
	case 83:/*"unknown reg,[]*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		//x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN("+defined_value+","+ tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1+")";
		return 0;
	case 84:/*"unknown reg,num*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0,"UNKNOWN("+defined_value+", "+operand1+")");
		return 0;
	case 85:/*"unknown [],reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(operand0, defined_value1);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN("+ tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0+", "+defined_value1+")";
		return 0;
	case 86:/*"unknown [],num*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN(" + tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 + ", " + operand1 + ")";
		return 0;
	case 87:/*"unknown reg, reg, reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction("UNKNOWN("+defined_value+", "+defined_value1+")", defined_value1);
		return 0;
	case 88:/*"unknown reg, reg, num*/
		if (operand2 == "")
		{
			x64_iter_get_reg_val(operand0, defined_value);
			x64_create_new_tmp_x64_my_instruction(0,"UNKNOWN("+defined_value+", "+operand1+")");
			return 0;
		}
		else if (operand2 != "")
		{
			x64_iter_get_reg_val(operand0, defined_value);
			x64_iter_get_reg_val(operand1, defined_value1);
			x64_create_new_tmp_x64_my_instruction("UNKNOWN("+defined_value+", "+defined_value1+")", defined_value1);
			return 0;
		}
		return 0;
	case 89:/*"unknown reg, [], reg*/
		x64_iter_get_reg_val(operand2, defined_value2);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find('=') != -1)//[] has '='
			defined_value1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find('='));
		else defined_value1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1;//[] does not have '='
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN("+defined_value1+", "+ defined_value2+")";
		return 0;
	case 90:/*"unknown reg, [], num*/
		//x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find('=') != -1)//[] has '='
			defined_value1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find('='));
		else defined_value1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1;//[] does not have '='
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN("+defined_value1+", "+ operand2+")";
		return 0;
	case 91:/*"xchg reg,reg*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_iter_get_reg_val(operand1, defined_value1);
		defined_value = x64_get_right_sub_reg(operand1, defined_value, defined_value1);
		defined_value1 = x64_get_right_sub_reg(operand0, defined_value1, defined_value);
		x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		return 0;
	case 92:/*"xchg reg, []*/
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		//x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		x64_iter_get_disp_val(1, operand1);
		x64_iter_look_for_same_displ(1);
		x64_iter_get_reg_val(operand0, defined_value);
		defined_value1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1;
		if (defined_value1.find("=") != -1)
			defined_value1 = defined_value1.substr(defined_value1.find("=") + 1, defined_value1.size() - 1 - defined_value1.find("="));
		defined_value = x64_get_right_sub_reg(operand0, defined_value, defined_value1);
		defined_value1 = x64_get_right_sub_reg(operand0, defined_value1, defined_value);
		x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		return 0;
	case 93:/*"xchg [],reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);

		defined_value = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
		if (defined_value.find("=") != -1)
			defined_value = defined_value.substr(defined_value.find("=") + 1, defined_value.size() - 1 - defined_value.find("="));
		defined_value = x64_get_right_sub_reg(operand1, defined_value, defined_value1);
		defined_value1 = x64_get_right_sub_reg(operand1, defined_value1, defined_value);
		//x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 94:/*"cmpxchg [], reg*/ 
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_create_new_tmp_x64_my_instruction(1, operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		tmp = rand() % 2;
		if (tmp == 0)//store operand1 into operand0
		{
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = x64_get_right_sub_reg(operand1, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0,defined_value1);
			x64_iter_get_reg_val("eax", defined_value);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"eax",defined_value});
		}
		else if (tmp == 1)//store operand1 into al,ax,eax, rax
		{
			x64_iter_get_reg_val("eax", defined_value);
			defined_value = x64_get_right_sub_reg(operand1,defined_value,defined_value1);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",defined_value});
		}
		return 0;
	case 95:/*"cmpxchg reg, reg*/
		x64_iter_get_reg_val(operand1, defined_value1);
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		tmp = rand() % 2;
		if (tmp == 0)//store operand1 into operand0
		{
			defined_value = x64_get_right_sub_reg(operand1,defined_value,defined_value1);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
			x64_iter_get_reg_val("eax", defined_value);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",defined_value});
		}
		else if(tmp==1)//store operand1 into al,ax,eax, rax
		{
			x64_iter_get_reg_val("eax", defined_value);
			defined_value= x64_get_right_sub_reg(operand1, defined_value, defined_value1);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",defined_value });
		}
		return 0;
	case 96:/*xor [], reg*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("Error: Strange! Register should have been defined!"); }
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		x64_iter_arithmatic_propagate_displ_reg(operand1, defined_value1, "^");
		return 0;
	case 97:/*mov reg, cs:*/
		x64_create_new_tmp_x64_my_instruction("","");
		if (operand1.find("cs:") != -1)
			operand1 = operand1.substr(operand1.find("cs:") + 3, operand1.size() - 1 - operand1.find("cs:") - 2);
		//ea1 = get_name_ea(BADADDR, operand1.c_str());
		//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
		//defined_value = filter_specific_string(buffer.c_str());
		defined_value = get_label_value(operand1.c_str());
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 98:/*"rol [],reg*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value1= x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		defined_value = x64_rotate_shift_disp(disasms, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0, defined_value1, "<<");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 99:/*"ror [],reg*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value1= x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		defined_value = x64_rotate_shift_disp(disasms, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0, defined_value1, ">>");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 100:/*"shl [],reg*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value1= x64_iter_lookForDefine(operand1);
		if(defined_value1=="") { warning("error: Strange! register should have been defined!"); }
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2= tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=')+1,\
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size()-1- tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address+"=(" + defined_value2 + "<<" + defined_value1 + ")";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 101:/*"shr [],reg*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value1 = x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2= tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=')+1,\
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size()-1- tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value = address + "=(" + defined_value2 + ">>" + defined_value1 + ")";
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + ">>" + operand1;
		}
		return 0;
	case 103:/*set []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
		}
		tmp = rand() % 2;
		defined_value = std::to_string(tmp);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=" + defined_value;
		return 0;
	case 104:/*"rol reg,reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value2 = defined_value;
		defined_value1= x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value1, "<<");
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value2 });
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 105:/*"ror reg,reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value2 = defined_value;
		defined_value1= x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value1, ">>");
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value2 });
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 106:/*"shl reg,reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value2 = defined_value;
		defined_value1= x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		defined_value = sub_shift(defined_value, operand0, defined_value1, "<<");;
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value2 });
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 107:/*"shr reg,reg*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); };
		defined_value1= x64_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		defined_value = sub_shift(defined_value, operand0, defined_value1, ">>");;
		defined_value1 = defined_value;
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 108:/*inc []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=" + defined_value2 + "+1";
		return 0;
	case 109:/*dec []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=" + defined_value2 + "-1";
		return 0;
	case 110:/*not []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=(!(" + defined_value2 + "))";
		return 0;
	case 111:/*neg []*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=(-(" + defined_value2 + "))";
		return 0;
	case 112:/*set{ z }[]*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
		}

		tmp = rand() % 2;
		defined_value = std::to_string(tmp);
		//x64_create_new_tmp_x64_my_instruction(0, address + "=" + defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=" + defined_value;
		return 0;
	case 113:/*"unknown reg, reg, []*/
		x64_create_new_tmp_x64_my_instruction("","");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = operand2;
		x64_iter_get_disp_val(1, operand2);//Since there is no room for operand0 in structure tmp_x64_my_insn, we record operand2 into the space for operand1
		x64_iter_look_for_same_displ(1);
		if(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find("=")==-1)
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1;
		else if(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find("=") != -1)
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find("=")+1,\
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.size()-1- tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1.find("="));
		x64_iter_get_reg_val(operand1, defined_value1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0="UNKNOWN(" + defined_value1 + ", " + defined_value2 + ")";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		return 0;
	case 114:/*"xor reg, label*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_create_new_tmp_x64_my_instruction("", "");
		defined_value1 = get_label_value(operand1);
		x64_iter_arithmatic_propagate_reg_num(operand0, defined_value, defined_value1, "^");
		return 0;
	case 115:/*"xor reg, label*/
		x64_create_new_tmp_x64_my_instruction("", "");
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("Error: Strange! Register should have been defined!"); }
		x64_iter_arithmatic_propagate_reg_label(operand0, defined_value, operand1, "^");
		return 0;
	case 116:/*"xor [], label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "^");
		return 0;
	case 117:/*"add reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		defined_value1= get_label_value(operand1);
		x64_iter_arithmatic_propagate_reg_num(operand0, defined_value, defined_value1, "+");
		return 0;
	case 118:/*"add [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "+");
		return 0;
	case 119:/*"sub reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_label(operand0, defined_value, operand1, "-");
		return 0;
	case 120:/*"sub [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "-");
		return 0;
	case 121:/*"rol reg,label*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = defined_value;
		defined_value2 = get_label_value(operand1);
		defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value2, "<<");
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		return 0;
	case 122:/*"rol [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value2 = get_label_value(operand1);
		defined_value = x64_rotate_shift_disp(disasms, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0, defined_value2, "<<");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 123:/*"ror reg,label*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = defined_value;
		defined_value2= get_label_value(operand1);
		defined_value = x64_rotate_shift_reg(operand0, defined_value, defined_value2, ">>");
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		return 0;
	case 124:/*"ror [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		defined_value2= get_label_value(operand1);
		defined_value = x64_rotate_shift_disp(disasms, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0, defined_value2, ">>");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 125:/*shl reg, label*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = defined_value;
		defined_value2 = get_label_value(operand1);
		defined_value = sub_shift(defined_value, operand0, defined_value2, "<<");;
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		return 0;
	case 126:/*shl [], label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		defined_value2 = get_label_value(operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=(" + defined_value2 + "<<" + defined_value2 + ")";
		return 0;
	case 127:/*shr reg, label*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); };
		defined_value2 = get_label_value(operand1);
		defined_value = sub_shift(defined_value, operand0, defined_value2, ">>");;
		defined_value1 = defined_value;
		x64_create_new_tmp_x64_my_instruction(0, defined_value);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value1 });
		return 0;
	case 128:/*shr [], label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		defined_value = x64_iter_lookForDefine(x64_extractBase(operand0));
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		x64_iter_define_base(0, defined_value);
		x64_iter_further_explain_displace(0, defined_value.length() + 2);
		x64_iter_look_for_same_displ(0);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
		if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') != -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
			defined_value2 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1, \
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		}
		else if (tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') == -1)
		{
			address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
			defined_value2 = address;
		}
		defined_value2 = get_label_value(operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=(" + defined_value2 + ">>" + defined_value2 + ")";
		return 0;
	case 129:/*"and reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_label(operand0, defined_value, operand1, "&");
		return 0;
	case 130:/*"and [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "&");
		return 0;
	case 131:/*"or reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_label(operand0, defined_value, operand1, "|");
		return 0;
	case 132:/*"or [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "|");
		return 0;
	case 133:/*cmov reg, label*/
		defined_value = x64_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! register should have been defined!"); }
		defined_value1 = get_label_value(operand1);
		tmp = rand() % 2;
		if (tmp == 0)
		{
			x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		}
		else if (tmp == 1)
		{
			defined_value = x64_get_right_sub_reg(operand0, defined_value, defined_value1);
			x64_create_new_tmp_x64_my_instruction(defined_value, defined_value1);
		}
		return 0;
	case 134:/*"sbb reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_label(operand0, defined_value, operand1, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "-CF";
		return 0;
	case 135:/*"sbb [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "-");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "-CF";
		return 0;
	case 136:/*"adc [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		//x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		x64_iter_get_disp_val(0, operand0);
		x64_iter_look_for_same_displ(0);
		x64_iter_arithmatic_propagate_displ_label(ea, operand1, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 137:/*"adc reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		x64_create_new_tmp_x64_my_instruction(0, "");
		x64_iter_arithmatic_propagate_reg_label(operand0, defined_value, operand1, "+");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "+CF";
		return 0;
	case 138:/*"unknown reg,label*/
		x64_iter_get_reg_val(operand0, defined_value);
		defined_value1 = get_label_value(operand1);
		x64_create_new_tmp_x64_my_instruction(0, "UNKNOWN(" + defined_value + ", " + defined_value1 + ")");
		return 0;
	case 139:/*"unknown [],label*/
		x64_create_new_tmp_x64_my_instruction(0, operand0);
		x64_iter_get_disp_val(0, operand0);
		defined_value1 = get_label_value(operand1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "UNKNOWN(" + tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 + ", " + defined_value1 + ")";
		return 0;
	case 140:/*movs*/
		x64_create_new_tmp_x64_my_instruction("", "");
		x64_iter_movs(ea, operand0, operand1);
		return 0;
	case 141:/*bsr reg,reg*/
		x64_create_new_tmp_x64_my_instruction("", "");
		x64_iter_get_reg_val(operand1, defined_value1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		defined_value = "bsr(" + defined_value1 + ')';
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 142:/*bsf reg,reg*/
		x64_create_new_tmp_x64_my_instruction("", "");
		x64_iter_get_reg_val(operand1, defined_value1);
		if (defined_value1 == "") { warning("error: Strange! register should have been defined!"); }
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		defined_value = "bsf(" + defined_value1 + ')';
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 143:/*mov label,reg*/
		x64_create_new_tmp_x64_my_instruction("", "");
		x64_iter_get_reg_val(operand1, defined_value1);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 = defined_value1;
		defined_value = x64_allocate_new_variable(operand1);
		defined_value = '[' + defined_value + "]=" + defined_value1;
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 144:/*mov label,num*/
		x64_create_new_tmp_x64_my_instruction("", "");
		defined_value = x64_allocate_new_variable("rax");
		defined_value = '[' + defined_value + "]=" + operand1;
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
		return 0;
	case 145:/*"div label*/
		x64_create_new_tmp_x64_my_instruction("", "");
		defined_value=get_label_value(operand0);
		x64_iter_div_propagate_label(defined_value, "/");
		return 0;
	case 146:/*call label*/
		x64_create_new_tmp_x64_my_instruction("", "");
		if (operand0.find('[') == -1)//if only has label but no []
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = operand0;
		else if (operand0.find('[') != -1)//if not only has label but also has []
		{
			std::string disp = operand0.substr(operand0.find('['), operand0.rfind(']') - operand0.find('[') + 1);
			std::string label = operand0.substr(0, operand0.find('['));
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = disp;
			x64_iter_further_explain_displace(0, 1);
			x64_iter_look_for_same_displ(0);
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = label + tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;

		}
		return 0;
	case 148:/*"imul reg,label,num*/
		defined_value1 = get_label_value(operand1);
		x64_create_new_tmp_x64_my_instruction(1, defined_value1);
		x64_iter_get_reg_val(operand0, defined_value);
		num = operand2;
		if (num[0] == '-')
			num = "(-(" + num.substr(1, num.size() - 1) + "))";
		x64_iter_arithmatic_propagate_reg_disp_num(ea, defined_value, num, "*");
		return 0;
	case 149:/*mul label*/
		defined_value1 = get_label_value(operand0);
		x64_create_new_tmp_x64_my_instruction(0, defined_value1);
		defined_value = x64_iter_lookForDefine("eax");
		defined_value = "((" + defined_value + "*" + defined_value1 + ")>>64)";
		defined_value2= "((" + defined_value + "*" + defined_value1 + ")&ffffffffffffffff)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"edx",defined_value });
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",defined_value2 });
		return 0;
	}
}
//Each time we recalculate the loop instructions for the second time, we create a 
//new x64_my_instruction object and store it into tmp_x64_my_insn to represent
//this instructions' symbolic value for the second time.
void x64_create_new_tmp_x64_my_instruction(int index, std::string operand)
{
	if (index == 1)
	{
		struct x64_my_instruction new_one;
		new_one.operand1 = operand;
		tmp_x64_my_insn.push_back(new_one);
	}
	else if (index == 0)
	{
		struct x64_my_instruction new_one;
		new_one.operand0 = operand;
		tmp_x64_my_insn.push_back(new_one);
	}
}

void x64_create_new_tmp_x64_my_instruction(std::string operand,std::string operand1)
{
	struct x64_my_instruction new_one;
	new_one.operand0 = operand;
	new_one.operand1 = operand1;
	tmp_x64_my_insn.push_back(new_one);
}

std::string x64_iter_lookForDefine(std::string operand)
{
	bool operandIsEax = false;
	qstring Mnem = "";
	std::string equivilant_operand, return_val;
	int which_op = -1;
	if (operand == "eax" || operand == "rax" || operand == "ax" || operand == "ah" || operand == "al")
		operandIsEax = true;
	for (int i = tmp_x64_insn_record.size() - 2;i >= 0;i--) {
		print_insn_mnem(&Mnem, tmp_x64_insn_record[i]);
		if (Mnem == "push" || Mnem == "pop" || Mnem == "nop"||Mnem.find('j')==0)
		{
			continue;
		}
		else if (Mnem == "call")
		{
			if (operandIsEax == true)
			{
				return_val = "RETURN_" + dec2hex(tmp_x64_insn_record[i]);
				return return_val;
			}
			std::string expression=x64_get_operand(tmp_x64_insn_record[i], 0);
			std::vector<std::string> expression_list = split_expression(expression);
			bool has_this_reg= has_this_register(expression_list,operand);
			if (has_this_reg==true)
			{
				if(expression.find("[")==-1)//if operand is a register
					return_val = tmp_x64_my_insn[i].operand0;
				else if (expression.find("[") != -1)//if operand is a []
					return_val = tmp_x64_my_insn[i].parameters0[operand];
				return return_val;
			}
			continue;
		}
		else if (Mnem==("div")|| Mnem == ("idiv") || ((Mnem=="mul"|| Mnem=="imul" )&& has_single_operand(tmp_x64_insn_record[i]) == true))
		{
			if (operand == "eax" || operand == "rax" || operand == "ax" || operand == "ah" || operand == "al")
			{
				return tmp_x64_my_insn[i].parameters0["eax"];
			}
			else if (operand == "rdx" || operand == "edx" || operand == "dx" || operand == "dh" || operand == "dl")
			{
				return tmp_x64_my_insn[i].parameters0["edx"];
			}
			else if (x64_is_equal_register(x64_get_operand(tmp_x64_insn_record[i], 0), operand))
			{ 
					return tmp_x64_my_insn[i].operand0;
			}
			else
			{
				std::string tmp = x64_contain_equal_register(x64_get_operand(tmp_x64_insn_record[i], 0), operand);
				if (tmp!="")
				return tmp_x64_my_insn[i].parameters0[tmp];
			}
		}
		else if (Mnem == "cmpxchg")
		{
			if (operand == "eax" || operand == "rax" || operand == "ax" || operand == "ah" || operand == "al")
				return tmp_x64_my_insn[i].parameters0["eax"];
		}
		std::string operand0 = x64_get_operand(tmp_x64_insn_record[i], 0);
		std::string operand1 = x64_get_operand(tmp_x64_insn_record[i], 1);
		std::string operand2= x64_get_operand(tmp_x64_insn_record[i], 2);
		int op0_type = get_optype(tmp_x64_insn_record[i], 0);
		int op1_type = get_optype(tmp_x64_insn_record[i], 1);
		int op2_type = get_optype(tmp_x64_insn_record[i], 2);
		if (operand1.find(';') != -1) operand1 = operand1.substr(0, operand1.find(';'));
		if (x64_is_equal_register(operand0, operand)) 
		{ return_val = tmp_x64_my_insn[i].operand0; which_op = 0; }
		else if (x64_is_equal_register(operand1, operand)) 
		{ return_val = tmp_x64_my_insn[i].operand1; which_op = 1; }
		else {
			equivilant_operand = x64_contain_equal_register(operand0, operand);
			if (equivilant_operand != "" && (op0_type==3|| op0_type == 4))
			{ return_val = tmp_x64_my_insn[i].parameters0[equivilant_operand]; which_op = 0; }
			equivilant_operand = x64_contain_equal_register(operand1, operand);
			if (equivilant_operand != "" && (op1_type == 3 || op1_type == 4))
			{ return_val = tmp_x64_my_insn[i].parameters1[equivilant_operand]; which_op = 1; }
			equivilant_operand = x64_contain_equal_register(operand2, operand);
			if (equivilant_operand != "" && (op2_type == 3 || op2_type == 4))
			{return_val = tmp_x64_my_insn[i].parameters1[equivilant_operand]; which_op = 2;}
		}
		if (return_val != "")
			return return_val;
		else if (return_val == "" && which_op != -1 && x64_is_use_stmt(Mnem, tmp_x64_insn_record[i], which_op)) 
			continue;
		else if (return_val == "" && which_op != -1 && !x64_is_use_stmt(Mnem, tmp_x64_insn_record[i], which_op))
			return return_val;
	}
	return return_val = "";
}

void x64_iter_only_Rbase_is_defined_propagate(std::string operand_to_decide,std::string defined_value,std::string defined_value1,std::string Mnem)
{
	x64_iter_define_base(1, defined_value1);
	x64_iter_further_explain_displace( 1, defined_value1.length() + 2);
	x64_iter_look_for_same_displ(1);
	defined_value1 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1;

	if (Mnem == "movd")
	{
		defined_value = x64_movd(operand_to_decide, defined_value, defined_value1);
	}
	else if (Mnem == "movq")
		defined_value = x64_movq(operand_to_decide, "[]", defined_value, defined_value1);
	else defined_value = x64_get_right_sub_reg(operand_to_decide, defined_value, defined_value1);

	tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0 = defined_value;//update left operand
}

void x64_iter_Ldefined_base_propagate( std::string defined_value, std::string value,ea_t ea)
{
	std::string operand_size = which_operand_size(ea);
	x64_iter_define_base(0, defined_value);
	x64_iter_further_explain_displace( 0, defined_value.length() + 2);
	if (operand_size == "xmmword")//xmm
	{
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "=" + value;//update left operand
	}
	else if (operand_size=="qword")//rx
	{
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "=" + value;//update left operand
	}
	else if (operand_size=="dword")//ex
	{
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "=" + value;//update left operand
	}
	else if (operand_size=="word")//x
	{
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "= (" + tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 + "&ffffffffffff0000)|" + value;//update left operand
	}
	else if (operand_size=="byte")//al
	{
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "= (" + tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 + "&ffffffffffffff00)|" + value;//update left operand
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 += "=" + value;//update left operand
	}
}

void x64_iter_lea_explain_member_propagate()
{
	std::string defined_value = x64_iter_lookForDefine(x64_extractBase(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1));
	if (defined_value == "") { warning("error! Strange! Register should have been defined!"); }
	x64_iter_define_base(1, defined_value);
	x64_iter_further_explain_displace(1, defined_value.length()+2);
	tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.replace(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.find('['), 1, "(");
	tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.replace(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.rfind(']'), 1, ")");
	tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0 = tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1;
}

void x64_iter_lea_extract_string_content_propagate(std::string operand0, std::string operand1)
{
	ea_t ea1;
	qstring buffer;
	std::string defined_value;
	//ea1 = get_name_ea(BADADDR, operand1.c_str());
	//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
	//defined_value = filter_specific_string(buffer.c_str());
	defined_value = get_label_value(operand1.c_str());
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 =defined_value;
	
}

void x64_iter_define_base(int operand_num, std::string value)
{
	std::string operand0, operand1, original_value;

	int plus_index, start_index;
	if (operand_num == 0)
	{
		operand0 = tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0;
		start_index = operand0.find('[');
		if (start_index == -1)start_index = 0;
		plus_index = operand0.find_first_of("+-*/");
		if (plus_index == -1)
			plus_index = operand0.find(']');
		original_value = operand0.substr(start_index + 1, plus_index - start_index - 1);
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].parameters0.insert(std::pair<std::string, std::string>(original_value, value));
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0 = operand0.replace(start_index + 1, plus_index - start_index - 1, value);

	}

	else if (operand_num == 1)
	{
		operand1 = tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1;
		start_index = operand1.find('[');
		if (start_index == -1)start_index = 0;
		plus_index = operand1.find_first_of("+-*/");
		if (plus_index == -1)
			plus_index = operand1.find(']');
		original_value = operand1.substr(start_index + 1, plus_index - start_index - 1);
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].parameters1.insert(std::pair<std::string, std::string>(original_value, value));
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1 = operand1.replace(start_index + 1, plus_index - start_index - 1, value);
	}

}

void x64_iter_further_explain_displace(int operand_num, int index)
{
	int length;
	std::string to_resolve, result;
	if (operand_num == 0)
	{
		while (index < tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0.length())
		{
			to_resolve = get_next_element(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0, &index);
			if (not_resolvable(to_resolve) == true) continue;
			result = x64_iter_resolve(to_resolve, tmp_x64_my_insn.size() - 1);
			tmp_x64_my_insn[tmp_x64_my_insn.size()-1].parameters0.insert(std::pair<std::string, std::string>(to_resolve, result));
			x64_iter_replace_element(0, to_resolve, result, &index);
		}
	}
	else if (operand_num == 1)
	{
		while (index < tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.length())
		{
			to_resolve = get_next_element(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1, &index);
			if (not_resolvable(to_resolve) == true) continue;
			result = x64_iter_resolve(to_resolve, tmp_x64_my_insn.size() - 1);
			tmp_x64_my_insn[tmp_x64_my_insn.size()-1].parameters1.insert(std::pair<std::string, std::string>(to_resolve, result));
			x64_iter_replace_element(1, to_resolve, result, &index);
		}
	}

}

void x64_iter_replace_element(int operand_num, std::string resolvable, std::string result, int* index)
{
	if (operand_num == 0)
	{	
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0.replace(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0.find(resolvable), resolvable.length(), result);
		*index = *index - resolvable.length() + result.length();
	}
	else if (operand_num == 1)
	{	
		tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.replace(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1.find(resolvable), resolvable.length(), result);
		*index = *index - resolvable.length() + result.length();
	}
}

//If "resolvable" is a register, look for its previous definition. If "resolvable" is a stack variable name, transform it into actual value.
std::string x64_iter_resolve(std::string resolvable, int tmp_insn_index)
{
	ea_t index;
	std::string define;
	uval_t out;
	int real_value;
	define = x64_iter_lookForDefine(resolvable);
	if (x64_is_register(resolvable))//If resolvable is register
	{
		if (define != "")
			return define;
		else
		{
			warning("error: Strange! Variable shoud have been defined!");
		}
	}
	else if(regex_match(resolvable, std::regex("[$]*[0-9a-zA-Z_]+")))//If "resolvable" is a (stack) name
	{
		get_name_value(&out, tmp_x64_insn_record[tmp_insn_index], resolvable.c_str());
			real_value = 0 - out;
			return "-" + dec2hex(real_value);
	}
}

void x64_iter_get_reg_val(std::string operand, std::string& defined_value)
{

	defined_value = x64_iter_lookForDefine(operand);
	if (defined_value == "") { warning("error! Strange! Register should have been defined!"); }
	//if (defined_value[0] == '-')
	//	defined_value = '(' + defined_value + ')';
}

void x64_iter_get_disp_val( int index, std::string operand)
{
	std::string defined_value;
	defined_value = x64_iter_lookForDefine(x64_extractBase(operand));
	if (defined_value == "") { warning("error! Strange! Register should have been defined!"); }
	x64_iter_define_base(index, defined_value);
	x64_iter_further_explain_displace(index, defined_value.length() + 2);
}

void x64_iter_arithmatic_propagate_reg_reg(std::string operand_to_decide,std::string defined_value, std::string defined_value1, std::string Mnem) {
	std::string operand;
	//propagate_to_right_operand(ea, defined_value1);
	std::string operand_size = which_operand_size(operand_to_decide);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"original",defined_value });
	defined_value = x64_arithmatic_result_basedon_size(defined_value, defined_value1, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
}

void x64_iter_arithmatic_propagate_reg_displ(std::string operand_to_decide,std::string defined_value, std::string Mnem) {
	std::string operand1;
	operand1 = tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1;
	//propagate_to_left_operand(ea, "(" + defined_value + Mnem + operand1 + ")");
	std::string operand_size = which_operand_size(operand_to_decide);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value });
	defined_value = x64_arithmatic_result_basedon_size(defined_value, operand1, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
}

void x64_iter_arithmatic_propagate_reg_num(std::string operand_to_decide,std::string defined_value, std::string num, std::string Mnem) {
	std::string operand_size = which_operand_size(operand_to_decide);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"original",defined_value });
	defined_value = x64_arithmatic_result_basedon_size(defined_value, num, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
}

void x64_iter_arithmatic_propagate_reg_label(std::string operand_to_decide, std::string defined_value, std::string operand1, std::string Mnem) {
	std::string operand_size = which_operand_size(operand_to_decide);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",defined_value });
	std::string defined_value1 = get_label_value(operand1);
	defined_value = x64_arithmatic_result_basedon_size(defined_value, defined_value1, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
}

void x64_iter_arithmatic_propagate_displ_reg(std::string operand_to_decide,std::string defined_value,  std::string Mnem) {
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string operand0 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
	std::string address;
	if (operand0.find("=") != -1)
	{
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.length() - 1 - operand0.find("="));
		address= operand0.substr(0, operand0.find("="));
	}
	else if (operand0.find("=") == -1)
	{
		address = operand0;
	}
	operand0 = x64_arithmatic_result_basedon_size(operand0, defined_value, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0});
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 =address+"="+ operand0;
}

void x64_iter_arithmatic_propagate_displ_num(ea_t ea,std::string num, std::string Mnem) {
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
	std::string operand_size = which_operand_size(ea);
	std::string operand0 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
	std::string address;
	if (operand0.find("=") != -1)
	{
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.length() - 1 - operand0.find("="));
		address= operand0.substr(0, operand0.find("="));
	}
	else if (operand0.find("=") == -1)
	{
		address = operand0;
	}
	operand0 = x64_arithmatic_result_basedon_size(operand0, num, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({"original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address+"="+operand0;
}

void x64_iter_arithmatic_propagate_displ_label(ea_t ea, std::string operand1, std::string Mnem) {
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
	std::string operand_size = which_operand_size(ea);
	std::string operand0 = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
	std::string address;
	if (operand0.find("=") != -1)
	{
		operand0 = operand0.substr(operand0.find("=") + 1, operand0.length() - 1 - operand0.find("="));
		address = operand0.substr(0, operand0.find("="));
	}
	else if (operand0.find("=") == -1)
	{
		address = operand0;
	}
	std::string defined_value1 = get_label_value(operand1);
	operand0 = x64_arithmatic_result_basedon_size(operand0, defined_value1, operand_size, Mnem);
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "original",tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 });
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = address + "=" + operand0;
}

void x64_iter_arithmatic_propagate_reg_reg_num(std::string operand_to_decide,std::string defined_value,std::string defined_value1, std::string num, std::string Mnem)
{
	std::string operand1;
	std::string operand_size = which_operand_size(operand_to_decide);
	//propagate_to_right_operand(ea, defined_value);
	if (operand_size == "xmmword")//xmm
	{
		defined_value = "(" + defined_value1 + Mnem + num + ")";
	}
	else if (operand_size == "qword")//rx
	{
		defined_value = "(" + defined_value1 + Mnem + num + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(defined_value1, 32))
			defined_value1 = defined_value1;
		else
			defined_value1 = "(" + defined_value1 + "&ffffffff)";
		if (x64_is_within_size(num, 32))
			num = num;
		else
			num = "(" + num + "&ffffffff)";
		defined_value = "(" + defined_value1 + Mnem + num + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(defined_value1, 16))
		{
			defined_value1 = defined_value1;
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			defined_value1 = "(" + defined_value1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			defined_value1 = "(((" + defined_value1 + "&ffff)" + Mnem + num + ")&ffff)";
		}
		defined_value = "((" + defined_value + "&ffffffffffff0000)|(" + defined_value1 + "))";
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(defined_value1, 8))
		{
			defined_value1 = defined_value1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			defined_value1 = "(" + defined_value1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			defined_value1 = "(((" + defined_value1 + "&ff00)" + Mnem + num + ")&ff00)";
		}
		defined_value = "((" + defined_value + "&ffffffffffff00ff)|(" + defined_value1 + "))";
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(defined_value1, 8))
		{
			defined_value1 = defined_value1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			defined_value1 = "(" + defined_value1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			defined_value1 = "(((" + defined_value1 + "&ff)" + Mnem + num + ")&ff)";
		}
		defined_value = "((" + defined_value + "&ffffffffffffff00)|(" + defined_value1 + "))";
	}
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
}

void x64_iter_arithmatic_propagate_reg_disp_num(ea_t ea,std::string defined_value,std::string num, std::string Mnem) {
	std::string  operand1;
	operand1 = tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1;
	std::string operand_size = which_operand_size(ea);
	operand1 = x64_my_insn[ea2x64_my_insn[ea]].operand1;
	if (operand_size == "xmmword")//xmm
	{
		defined_value = "(" + operand1 + Mnem + num + ")";
	}
	else if (operand_size == "qword")//rx
	{
		defined_value = "(" + operand1 + Mnem + num + ")";
	}
	else if (operand_size == "dword")//ex
	{
		if (x64_is_within_size(operand1, 32))
			operand1 = operand1;
		else
			operand1 = "(" + operand1 + "&ffffffff)";
		if (x64_is_within_size(num, 32))
			num = num;
		else
			num = "(" + num + "&ffffffff)";
		defined_value = "(" + operand1 + Mnem + num + ")";
	}
	else if (operand_size == "word")//x
	{
		if (x64_is_within_size(operand1, 16))
		{
			operand1 = operand1;
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			operand1 = "(" + operand1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 16))
				num = num;
			else
				num = "(" + num + "&ffff)";
			operand1 = "(((" + operand1 + "&ffff)" + Mnem + num + ")&ffff)";
		}
		defined_value = "((" + defined_value + "&ffffffffffff0000)|" + operand1 + ")";
	}
	else if (operand_size == "hbyte")//ah
	{
		if (x64_is_within_size(operand1, 8))
		{
			operand1 = operand1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			operand1 = "(" + operand1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff00)";
			operand1 = "(((" + operand1 + "&ff00)" + Mnem + num + ")&ff00)";
		}
		defined_value = "((" + defined_value + "&ffffffffffff00ff)|" + operand1 + ")";
	}
	else if (operand_size == "lbyte")//al
	{
		if (x64_is_within_size(operand1, 8))
		{
			operand1 = operand1;
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			operand1 = "(" + operand1 + Mnem + num + ")";
		}
		else
		{
			if (x64_is_within_size(num, 8))
				num = num;
			else
				num = "(" + num + "&ff)";
			operand1 = "(((" + operand1 + "&ff)" + Mnem + num + ")&ff)";
		}
		defined_value = "((" + defined_value + "&ffffffffffffff00)|" + operand1 + ")";
	}
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
}

void x64_iter_div_propagate_reg(std::string operand_to_decide,std::string defined_value, std::string Mnem)
{
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string operand0 = x64_iter_lookForDefine("eax");
	std::string operand1 = x64_iter_lookForDefine("edx");
	std::string catenate;
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
	if (operand_size == "qword")//rx
	{
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<64|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size == "dword")//ex
	{
		if (!x64_is_within_size(operand1, 32))
			operand1 = "(" + operand1 + "&ffffffff)";
		if (!x64_is_within_size(operand0, 32))
			operand0 = "(" + operand0 + "&ffffffff)";
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "(" + defined_value + "&ffffffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<32|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size == "word")//x
	{
		if (!x64_is_within_size(operand1, 16))
			operand1 = "(" + operand1 + "&ffff)";
		if (!x64_is_within_size(operand0, 16))
			operand0 = "(" + operand0 + "&ffff)";
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<16|" + operand0;
		operand0 = "((" + catenate + Mnem + defined_value + ")&ffff)";
		operand1 = "((" + catenate + "%" + defined_value + ")&ffff)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size == "lbyte")//al
	{
		if (!x64_is_within_size(operand1, 8))
			operand1 = "(" + operand1 + "&ff)";
		if (!x64_is_within_size(operand0, 8))
			operand0 = "(" + operand0 + "&ff)";
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		operand0 = "((" + operand0 + "&ffffffffffffff00)|((" + operand0 + Mnem + defined_value + \
			")&ff)|(((" + operand0 + "%" + defined_value + ")&ff)<<8))";
	}
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",operand0 });
}

void x64_iter_div_propagate_label(std::string label_operand, std::string Mnem)
{
	std::string operand0 = x64_iter_lookForDefine("eax");
	std::string operand1 = x64_iter_lookForDefine("edx");
	std::string catenate;
	if (operand1 == "0" || operand1 == "")
		catenate = operand0;
	else
		catenate = operand1 + "<<64|" + operand0;
	operand0 = "(" + catenate + Mnem + label_operand + ")";
	operand1 = "(" + catenate + "%" + label_operand + ")";
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",operand0 });
}


void x64_iter_div_propagate_disp(ea_t ea,std::string Mnem)
{
	std::string operand_size = which_operand_size(ea);
	std::string operand0 = x64_iter_lookForDefine("eax");
	std::string operand1 = x64_iter_lookForDefine("edx");
	std::string defined_value = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0;
	std::string catenate;
	if (operand_size=="qword")//rx
	{
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<64|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size=="dword")//ex
	{
		if (!x64_is_within_size(operand1, 32))
			operand1 = "(" + operand1 + "&ffffffff)";
		if (!x64_is_within_size(operand0, 32))
			operand0 = "(" + operand0 + "&ffffffff)";
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "(" + defined_value + "&ffffffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<32|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "((" + catenate + "%(" + defined_value + "&ffffffff))";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size==" word")//x
	{
		if (!x64_is_within_size(operand1, 16))
			operand1 = "(" + operand1 + "&ffff)";
		if (!x64_is_within_size(operand0, 16))
			operand0 = "(" + operand0 + "&ffff)";
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (operand1 == "0" || operand1 == "")
			catenate = operand0;
		else
			catenate = operand1 + "<<16|" + operand0;
		operand0 = "((" + catenate + Mnem + defined_value + ")&ffff)";
		operand1 = "((" + catenate + "%" + defined_value + ")&ffff)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	else if (operand_size=="byte")//al
	{
		if (!x64_is_within_size(operand1, 8))
			operand1 = "(" + operand1 + "&ff)";
		if (!x64_is_within_size(operand0, 8))
			operand0 = "(" + operand0 + "&ff)";
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		operand0 = "((" + operand0 + "&ffffffffffffff00)|((" + operand0 + Mnem + defined_value + \
			")&ff)|(((" + operand0 + "%" + defined_value + ")&ff)<<8))";
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		if (operand1 == "0")
			catenate = operand0;
		else
			catenate = operand1 + "<<64|" + operand0;
		operand0 = "(" + catenate + Mnem + defined_value + ")";
		operand1 = "(" + catenate + "%" + defined_value + ")";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx" ,operand1 });
	}
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",operand0 });//update left operand
}

void x64_iter_look_for_same_displ(int operand_num)
{
	int equation_index;
	if (operand_num == 1)
	{
		for (int i = tmp_x64_insn_record.size() - 2;i >= 0;i--)
		{
			if (tmp_x64_my_insn[i].operand0.find(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1+"=") == 0)
			{
				equation_index = tmp_x64_my_insn[i].operand0.find('=');
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 +="="+ tmp_x64_my_insn[i].operand0.substr(equation_index+1, tmp_x64_my_insn[i].operand0.size()-equation_index);
				return;
			}
			else if (tmp_x64_my_insn[i].operand1.find(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand1+"=") == 0)
			{
				equation_index = tmp_x64_my_insn[i].operand1.find('=');
				tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand1 +="="+ tmp_x64_my_insn[i].operand1.substr(equation_index + 1, tmp_x64_my_insn[i].operand1.size() - equation_index);
				return;
			}

		}
	}
	else if (operand_num == 0)
	{
		for (int i = tmp_x64_insn_record.size() - 2;i >= 0;i--)
		{
			if (tmp_x64_my_insn[i].operand0.find(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0+"=") == 0)
			{
				equation_index = tmp_x64_my_insn[i].operand0.find('=');
				tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0 +="="+ tmp_x64_my_insn[i].operand0.substr(equation_index + 1, tmp_x64_my_insn[i].operand0.size() - equation_index);
				return;
			}
			else if (tmp_x64_my_insn[i].operand1.find(tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0+"=") == 0)
			{
				equation_index = tmp_x64_my_insn[i].operand1.find('=');
				tmp_x64_my_insn[tmp_x64_my_insn.size()-1].operand0 +="="+ tmp_x64_my_insn[i].operand1.substr(equation_index + 1, tmp_x64_my_insn[i].operand1.size() - equation_index);
				return;
			}

		}
	}
}


void x64_iter_mul_single_propagate_reg(std::string operand_to_decide, std::string defined_value, ea_t ea, std::string Mnem)
{
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = defined_value;
	std::string operand_size = which_operand_size(operand_to_decide);
	std::string operand = x64_iter_lookForDefine("eax");
	std::string defined_value1 = x64_iter_lookForDefine("edx");;
	if (operand_size == "qword")//rx
	{
		defined_value = "(" + defined_value + "*" + operand + "&ffffffffffffffff)";
		defined_value1 = "((" + defined_value + "*" + operand + "&ffffffffffffffff0000000000000000)>>64)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}
	else if (operand_size == "dword")//ex
	{
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "(" + defined_value + "&ffffffff)";
		if (!x64_is_within_size(operand, 32))
			operand = "(" + operand + "&ffffffff)";
		defined_value = "((" + defined_value + "*" + operand + ")&ffffffff)";
		defined_value1 = "(((" + defined_value + "*" + operand + ")&ffffffff00000000)>>32)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}
	else if (operand_size == "word")//x
	{
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (!x64_is_within_size(operand, 16))
			operand = "(" + operand + "&ffff)";
		defined_value = "((" + operand + "&ffffffffffff0000)|(" + defined_value + "*" + operand + ")&ffff)";
		defined_value1 = "((" + defined_value1 + "&ffffffffffff0000)|((" + defined_value + "*" + operand + ")&ffff0000)>>16)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}
	else if (operand_size == "lbyte")//al
	{
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		if (!x64_is_within_size(operand, 8))
			operand = "(" + operand + "&ff)";
		defined_value = "((" + operand + "&ffffff00)|((" + defined_value + "*" + operand + ")&ffff))";
	}
	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",defined_value });
}

void x64_iter_mul_single_propagate_disp(ea_t ea, std::string Mnem)
{
	qstring disasm;
	std::string disasms;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	disasms = disasm.c_str();
	std::string operand0 = x64_iter_lookForDefine("eax");
	std::string defined_value1 = x64_iter_lookForDefine("edx");
	std::string defined_value = x64_my_insn[ea2x64_my_insn[ea]].operand0;
	if (disasms.find("qword") != -1)//rx
	{
		defined_value = "((" + operand0 + "*" + defined_value + ")&ffffffffffffffff)";
		defined_value1 = "(((" + operand0 + "*" + defined_value + ")&ffffffffffffffff0000000000000000)>>64)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}
	else if (disasms.find("dword") != -1)//ex
	{
		if (!x64_is_within_size(defined_value, 32))
			defined_value = "(" + defined_value + "&ffffffff)";
		if (!x64_is_within_size(operand0, 32))
			operand0 = "(" + operand0 + "&ffffffff)";
		defined_value = "((" + operand0 + "*" + defined_value + ")&ffffffff)";
		defined_value1 = "(((" + operand0 + "*" + defined_value + ")&ffffffff00000000)>>32)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}
	else if (disasms.find(" word") != -1)//x
	{
		if (!x64_is_within_size(defined_value, 16))
			defined_value = "(" + defined_value + "&ffff)";
		if (!x64_is_within_size(operand0, 16))
			operand0 = "(" + operand0 + "&ffff)";
		defined_value = "((" + operand0 + "&ffffffffffff0000)|((" + operand0 + "*" + defined_value + ")&ffff))";
		defined_value1 = "((" + defined_value1 + "&ffffffffffff0000)|(((" + operand0 + "*" + defined_value + ")&ffff0000)>>16))";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}
	else if (disasms.find("byte") != -1)//al
	{
		if (!x64_is_within_size(defined_value, 8))
			defined_value = "(" + defined_value + "&ff)";
		if (!x64_is_within_size(operand0, 8))
			operand0 = "(" + operand0 + "&ff)";
		defined_value = "((" + operand0 + "&ffffffffffffff00)|((" + operand0 + "*" + defined_value + ")&ffff))";
	}
	else//no prefix like BYTE or WORD or DWORD or QWORD
	{
		defined_value = "((" + operand0 + "*" + defined_value + ")&ffffffffffffffff)";
		defined_value1 = "(((" + operand0 + "*" + defined_value + ")&ffffffffffffffff0000000000000000)>>64)";
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "edx",defined_value1 });
	}

	tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].parameters0.insert({ "eax",defined_value });//update left operand
}

void x64_iter_stos(ea_t ea, std::string operand0)
{
	qstring Mnemq;
	std::string Mnem, defined_value1, defined_value;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string operand_size;
	if (x64_is_register(operand0))//if contains register in this instruction
	{
		operand_size = which_operand_size(operand0);
	}
	else if (Mnem == "stosb")
		operand_size = "lbyte";
	else if (Mnem == "stosw")
		operand_size = "word";
	else if (Mnem == "stosd")
		operand_size = "dword";
	else if (Mnem == "stosq")
		operand_size = "xmmword";
	if (operand_size == "lbyte")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1 + "&ff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	else if (operand_size == "word")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1 + "&ffff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	else if (operand_size == "dword")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1 + "&ffffffff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	else if (operand_size == "xmmword")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1;
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = '[' + defined_value + "]=" + defined_value1;
	}
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_s = disasm.c_str();
	std::string address;
	std::string content;
	if (disasm_s.find("rep") != -1)// if contains rep
	{
		address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		content = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1,\
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "ITER(" + address + ")=" + content;
	}
}

void x64_iter_scas(ea_t ea, std::string operand0)
{
	qstring Mnemq;
	std::string Mnem, defined_value1, defined_value;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string operand_size;
	if (x64_is_register(operand0))//contains register in this instruction
	{
		operand_size = which_operand_size(operand0);
	}
	else if (Mnem == "scasb")
		operand_size = "lbyte";
	else if (Mnem == "scasw")
		operand_size = "word";
	else if (Mnem == "scasd")
		operand_size = "dword";
	else if (Mnem == "scasq")
		operand_size = "xmmword";
	if (operand_size == "lbyte")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1 + "&ff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	else if (operand_size == "word")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1 + "&ffff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	else if (operand_size == "dword")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1 + "&ffffffff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	else if (operand_size == "xmmword")
	{
		defined_value1 = x64_iter_lookForDefine("rax");
		defined_value1 = defined_value1;
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "] cmp " + defined_value1;
	}
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_s = disasm.c_str();
	std::string address;
	std::string content;
	if (disasm_s.find("rep") != -1)// if contains rep
	{
		address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('['),\
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find("cmp")- tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('['));
		content = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find("cmp") + 4,\
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find("cmp") - 4);
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "(ITER(" + address + ") cmp " + content+")";
	}
}

void x64_iter_movs(ea_t ea, std::string operand0, std::string operand1)
{
	qstring Mnemq;
	std::string Mnem, defined_value1, defined_value;
	print_insn_mnem(&Mnemq, ea);
	Mnem = Mnemq.c_str();
	std::string operand_size;
	if (x64_is_register(operand0))//contains register in this instruction
	{
		operand_size = which_operand_size(operand0);
	}
	else if (Mnem == "movsb")
		operand_size = "lbyte";
	else if (Mnem == "movsw")
		operand_size = "word";
	else if (Mnem == "movsd")
		operand_size = "dword";
	else if (Mnem == "movsq")
		operand_size = "xmmword";
	if (operand_size == "lbyte")
	{
		defined_value1 = x64_iter_lookForDefine("rsi");
		defined_value1 = defined_value1 + "&ff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	else if (operand_size == "word")
	{
		defined_value1 = x64_iter_lookForDefine("rsi");
		defined_value1 = defined_value1 + "&ffff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	else if (operand_size == "dword")
	{
		defined_value1 = x64_iter_lookForDefine("rsi");
		defined_value1 = defined_value1 + "&ffffffff";
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	else if (operand_size == "xmmword")
	{
		defined_value1 = x64_iter_lookForDefine("rsi");
		defined_value1 = defined_value1;
		defined_value = x64_iter_lookForDefine("rdi");
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "[" + defined_value + "]=[" + defined_value1 + ']';
	}
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string disasm_s = disasm.c_str();
	std::string address;
	std::string content;
	if (disasm_s.find("rep") != -1)// if contains rep
	{
		address = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(0, tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		content = tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.substr(tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('=') + 1,\
			tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.size() - 1 - tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0.find('='));
		tmp_x64_my_insn[tmp_x64_my_insn.size() - 1].operand0 = "ITER(" + address + ")=" + content;
	}
}

/*void sub_iter_handler(ea_t ea, func_t* func, int mode)
{
	std::string defined_value, defined_value1,tmp;
	std::string num;
	int comma;
	int reg_index;
	std::string operand1,operand0;
	operand1 = x64_get_operand(ea, 1);
	operand0 = x64_get_operand(ea, 0);
	switch (mode) {
	case 0: /*"mov reg,reg"*/
/*		if (operand_index == 1) {

			propagate_to_right_left_operand(ea, iterator_var);
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}


	case 1:/*"mov reg,[]"*/
		//first find [rbx+14] defination
		//defined_value = lookForDefine(operand, ea, func);

/*		if (operand_index == 1)
		{
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 != "") { only_Rbase_is_defined_propagate(ea, defined_value1, func);return; }
			even_Rbase_is_not_defined_propagate(ea, func);return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}



	case 2:/*"mov [],num"*/
/*		warning("iterator variable been overwrite!");
		return;

	case 3:/*"mov [],reg"*/
/*		iter_get_displ_reg_val(ea, func, defined_value, defined_value1, operand_index, reg, iterator_var, operand0, operand1);

		propagate_to_right_operand(ea, defined_value1);
		if (defined_value != "") { Ldefined_base_propagate(ea, defined_value, defined_value1, func);return; }
		even_Lundefined_base_propagate(ea, defined_value1, func);
		return;
		
	case 4:/*mov reg, num*/
/*		warning("iterator variable been overwrite!");
		return;

	case 5://push
		return;
	case 6://pop
		return;
	case 7:/*"lea reg,[]")*/
/*		if (operand_index == 0)
		{
			warning("iterator variable been overwrite!");
			return;
		}
		tmp = replace_all_iter_var(operand1, reg, iterator_var);
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = tmp;
		lea_explain_member_propagate(ea, func);
		return;
	case 8:/*"lea reg,str"*/
/*		warning("iterator variable been overwrite!");
		return;
	case 9:/*"test reg,reg*/
/*		if (operand_index == 1||operand_index==0&&operand0==operand1)
		{	
			propagate_to_right_operand(ea, iterator_var);
			
			if (operand1 == operand0) { propagate_to_left_operand(ea, iterator_var); return; }
			defined_value = lookForDefine(operand0, ea, func);
			if (defined_value == "") { defined_value = allocate_new_variable(); }
			propagate_to_left_operand(ea, defined_value);
			return;
		}
		else if(operand_index==0){
			propagate_to_left_operand(ea, iterator_var);
			defined_value1 = lookForDefine(operand1, ea, func);
			if (defined_value1 == "") { defined_value1 = allocate_new_variable(); }
			propagate_to_right_operand(ea, defined_value1);
			return;
		}
	
	case 10:/*"test reg,num*/
/*		if (operand_index == 0)
		{
			
			propagate_to_left_operand(ea, iterator_var);
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 11:/*"test [],num*/
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			return;
		}
		else if (operand_index==1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 12:/*"cmp [],reg*/
/*		iter_get_displ_reg_val(ea, func, defined_value, defined_value1, operand_index, reg, iterator_var, operand0, operand1);
		propagate_to_right_operand(ea,defined_value1);
		if (defined_value == "") { defined_value = allocate_new_variable(); }
		define_base(ea, 0, defined_value);
		further_explain_displace(ea, 0, func, defined_value.length() + 2);
		return ;
	case 13:/*"xor eax,eax*/
/*		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "0";
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = "0";
		return ;
	case 14:/*"add reg,reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_reg_val(ea, operand0, func, defined_value);
		}
		else if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_reg_val(ea, operand1, func, defined_value1);
		}
		arithmatic_propagate_reg_reg(defined_value,defined_value1, ea, "+");
		return ;
	case 15:/*"add reg,[]*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_disp_val(ea, 1, operand1, func);
		}
		else if (operand_index == 1)
		{
			get_reg_val(ea, operand0, func, defined_value);
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 == "")
				defined_value1 = allocate_new_variable();
			define_base(ea, 1, defined_value1);
			further_explain_displace(ea,0,func,defined_value1.length()+2);
		}
		arithmatic_propagate_reg_displ(defined_value,ea, "+");
		return ;
	case 16:/*"add reg,num*/
/*		if (operand_index == 0) {
			defined_value = iterator_var;
			arithmatic_propagate_reg_num(defined_value, ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 17:/*"add [],reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_disp_val(ea, 0, operand0, func);
		}
		else if (operand_index == 0)
		{
			get_reg_val(ea, operand1, func, defined_value1);
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
		}
		arithmatic_propagate_displ_reg(defined_value1, ea, "+");
		return ;
	case 18:/*"add [],num*/ 
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			arithmatic_propagate_displ_num(ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 19:/*"sub reg,reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_reg_val(ea, operand0, func, defined_value);
		}
		else if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_reg_val(ea, operand1, func, defined_value1);
		}
		arithmatic_propagate_reg_reg(defined_value,defined_value1, ea, "-");
		return ;
	case 20:/*"sub reg,[]*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_disp_val(ea, 1, operand1, func);
		}
		else if (operand_index == 1)
		{
			get_reg_val(ea, operand0, func, defined_value);
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 == "")
				defined_value1 = allocate_new_variable();
			define_base(ea, 1, defined_value1);
			further_explain_displace(ea, 0, func, defined_value1.length() + 2);
		}
		arithmatic_propagate_reg_displ(defined_value, ea, "-");
		return ;
	case 21:/*"sub reg,num*/
/*		if (operand_index == 0) {
			defined_value = iterator_var;
			arithmatic_propagate_reg_num(defined_value, ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 22:/*"sub [],reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_disp_val(ea, 0, operand0, func);
		}
		else if (operand_index == 0)
		{
			get_reg_val(ea, operand1, func, defined_value1);
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
		}
		arithmatic_propagate_displ_reg(defined_value1, ea, "-");
		return ;
	case 23:/*"sub [],num*/
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			arithmatic_propagate_displ_num(ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 24:/*"mul reg,reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_reg_val(ea, operand0, func, defined_value);
		}
		else if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_reg_val(ea, operand1, func, defined_value1);
		}		
		arithmatic_propagate_reg_reg(defined_value,defined_value1, ea, "*");
		return ;
	case 25:/*"mul reg,[]*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_disp_val(ea, 1, operand1, func);
		}
		else if (operand_index == 1)
		{
			get_reg_val(ea, operand0, func, defined_value);
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 == "")
				defined_value1 = allocate_new_variable();
			define_base(ea, 1, defined_value1);
			further_explain_displace(ea, 0, func, defined_value1.length() + 2);
		}
		arithmatic_propagate_reg_displ(defined_value, ea, "*");
		return ;
	case 26:/*mul reg,reg,num*/
/*		if (operand_index == 0)
		{
			warning("iterator variable been overwrite!");
			return;
		}
		else {
			comma = x64_count_comma_ea(ea);
			if (comma == 1)
			{
				if (operand_index == 0)
					defined_value1 = iterator_var;
				num = x64_get_operand(ea, 1);
			}
			else if (comma == 2)
			{
				if (operand_index == 1)
					defined_value1 = iterator_var;
				num = x64_get_operand(ea, 2);
			}
			arithmatic_propagate_reg_reg_num(defined_value1, num, ea, "*");
			return;
		}
	case 27:/*"mul reg,[],num*/
/*		if (operand_index == 0)
		{
			warning("iterator variable been overwrite!");
			return;
		}
		else if (operand_index == 1)
		{
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 == "")
				defined_value1 = allocate_new_variable();
			define_base(ea, 1, defined_value1);
			further_explain_displace(ea, 1, func, defined_value1.length() + 2);
			arithmatic_propagate_reg_disp_num(ea, "*");
			return;
		}
	case 29:/*"div reg*/
/*		if (operand_index == 0)
		{
			div_propagate_reg(iterator_var, ea, func, "/");
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 30:/*"div []*/
/*		if (operand_index == 0)
		{
			get_disp_val(ea, 0, operand0, func);
			div_propagate_disp(ea, func, "/");
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 34:/*"rol reg,num*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			propagate_to_left_operand(ea, defined_value + "<<" + x64_get_operand(ea, 1));
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 35:/*"rol [],num*/
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			propagate_to_left_operand(ea,  "<<" + x64_get_operand(ea, 1));
			return;
		}
		else {
			warning("iterator variable been overwrite!");
			return;
		}
	case 36: /*"ror reg,num*/
/*		if (operand_index == 0)
		{
			defined_value = operand_index;
			propagate_to_left_operand(ea, defined_value + ">>" + x64_get_operand(ea, 1));
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 37:/*"ror [],num*/
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			propagate_to_left_operand(ea, ">>" + x64_get_operand(ea, 1));
			return;
		}
		else
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 38:/*"and reg,reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_reg_val(ea, operand0, func, defined_value);
		}
		else if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_reg_val(ea, operand1, func, defined_value1);
		}
		arithmatic_propagate_reg_reg(defined_value,defined_value1,ea,"&");
		return ;
	case 39:/*"and reg,[]*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_disp_val(ea, 1, operand1, func);
		}
		else if (operand_index == 1)
		{
			get_reg_val(ea, operand0, func, defined_value);
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 == "")
				defined_value1 = allocate_new_variable();
			define_base(ea, 1, defined_value1);
			further_explain_displace(ea, 0, func, defined_value1.length() + 2);
		}
		arithmatic_propagate_reg_displ(defined_value, ea, "&");
		return ;
	case 40:/*"and reg,num*/
/*		if (operand_index == 0) {
			defined_value = iterator_var;
			arithmatic_propagate_reg_num(defined_value, ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 41:/*"and [],reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_disp_val(ea, 0, operand0, func);
		}
		else if (operand_index == 0)
		{
			get_reg_val(ea, operand1, func, defined_value1);
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
		}
		arithmatic_propagate_displ_reg(defined_value1, ea, "&");
		return ;
	case 42:/*"and [],num*/
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			arithmatic_propagate_displ_num(ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 43:/*"or reg,reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_reg_val(ea, operand0, func, defined_value);
		}
		else if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_reg_val(ea, operand1, func, defined_value1);
		}
		arithmatic_propagate_reg_reg(defined_value, defined_value1, ea, "&");
		return;
	case 44:/*"or reg,[]*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_disp_val(ea, 1, operand1, func);
		}
		else if (operand_index == 1)
		{
			get_reg_val(ea, operand0, func, defined_value);
			iter_get_right_displ_val(ea, func, defined_value1, reg, iterator_var, operand1);
			if (defined_value1 == "")
				defined_value1 = allocate_new_variable();
			define_base(ea, 1, defined_value1);
			further_explain_displace(ea, 0, func, defined_value1.length() + 2);
		}
		arithmatic_propagate_reg_displ(defined_value, ea, "&");
		return;
	case 45:/*"or reg,num*/
/*		if (operand_index == 0) {
			defined_value = iterator_var;
			arithmatic_propagate_reg_num(defined_value, ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	case 46:/*"or [],reg*/
/*		if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_disp_val(ea, 0, operand0, func);
		}
		else if (operand_index == 0)
		{
			get_reg_val(ea, operand1, func, defined_value1);
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
		}
		arithmatic_propagate_displ_reg(defined_value1, ea, "&");
		return;
	case 47:/*"or [],num*/
/*		if (operand_index == 0)
		{
			iter_get_left_displ_val(ea, func, defined_value, reg, iterator_var, operand0);
			if (defined_value == "")
				defined_value = allocate_new_variable();
			define_base(ea, 0, defined_value);
			further_explain_displace(ea, 0, func, defined_value.length() + 2);
			arithmatic_propagate_displ_num(ea, "+");
			return;
		}
		else if (operand_index == 1)
		{
			warning("iterator variable been overwrite!");
			return;
		}
	
	case 50:/*unpck xmm0,xmm1*/
/*		if (operand_index == 0)
		{
			defined_value = iterator_var;
			get_reg_val(ea, operand1, func, defined_value1);
		}
		else if (operand_index == 1)
		{
			defined_value1 = iterator_var;
			get_reg_val(ea, operand0, func, defined_value);
		}
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = defined_value1;		
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = defined_value + ":" + defined_value1;
		return ;
	}
}

/*std::string replace_all_iter_var(std::string insn_string, std::string reg, std::string iterator_var)
{
	int index;
	index = insn_string.find(reg);
	while (index!= -1)
	{
		insn_string.replace(index,reg.size(),iterator_var);
		index = insn_string.find(reg);
	}
	return insn_string;
} 



void iter_get_displ_reg_val(ea_t ea, func_t * func, std::string & defined_value, std::string & defined_value1,int operand_index,std::string reg, std::string iterator_var,std::string operand0,std::string operand1)

{
	std::string tmp;
	
	if (operand_index == 1)
	{
		defined_value1 = iterator_var;
		defined_value = lookForDefine(extractBase(operand1), ea, func);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
	}
	else if (operand_index == 0)
	{
		defined_value1 = lookForDefine(operand1, ea, func);
		if (defined_value1 == "") defined_value1 = allocate_new_variable();
		if (extractBase(operand0) == reg)
		{
			defined_value = iterator_var;
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		}
		else
		{
			tmp = replace_all_iter_var(operand0, reg, iterator_var);
			x64_my_insn[ea2x64_my_insn[ea]].operand0 = tmp;
			x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ reg,iterator_var });

			defined_value = lookForDefine(extractBase(operand1), ea, func);
		}
	}
}

void iter_get_left_displ_val(ea_t ea, func_t* func, std::string &defined_value, std::string reg, std::string iterator_var, std::string operand0)
{
	std::string tmp;
	tmp = extractBase(operand0);
	if (tmp == reg)
	{
		defined_value = iterator_var;
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = operand0;
		return;
	}
	else
	{
		tmp = replace_all_iter_var(operand0, reg,iterator_var);
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = tmp;
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.insert({ reg,iterator_var });
		defined_value = lookForDefine(extractBase(operand0), ea, func);
		return;
	}

}

void iter_get_right_displ_val(ea_t ea, func_t* func, std::string& defined_value1, std::string reg, std::string iterator_var, std::string operand1)
{
	std::string tmp;
	if (extractBase(operand1) == reg)
	{
		defined_value1 = iterator_var;
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = operand1;
		return;
	}
	else {
		defined_value1 = lookForDefine(extractBase(operand1), ea, func);
		tmp = replace_all_iter_var(operand1, reg, iterator_var);
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = tmp;
		x64_my_insn[ea2x64_my_insn[ea]].parameters1.insert({ reg,iterator_var });
		return;
	}
}*/