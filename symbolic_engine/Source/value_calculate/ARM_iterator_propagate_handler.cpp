#include "../../Headers/value_calculate/ARM_iterator_propagate_handler.h"
void ARM_re_update_each_insn(ea_t ea, func_t* func)
{
	if (ea == 0x44c80)
		int bp = 0;
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();

	int op0_type = 0, op1_type = 0, op2_type = 0,op3_type=0;
	std::string operand0, operand1, operand2,operand3;
	int ea_operand_num = count_ea_operands(ea);
	if (ea_operand_num == 1)
	{

		op0_type = get_optype(ea, 0);
		operand0 = ARM_get_operand(ea, 0);

	}
	else if (ea_operand_num == 2)
	{

		op0_type = get_optype(ea, 0);
		operand0 = ARM_get_operand(ea, 0);
		op1_type = get_optype(ea, 1);
		operand1 = ARM_get_operand(ea, 1);

	}
	else if (ea_operand_num == 3)
	{

		op0_type = get_optype(ea, 0);
		operand0 = ARM_get_operand(ea, 0);
		op1_type = get_optype(ea, 1);
		operand1 = ARM_get_operand(ea, 1);
		op2_type = get_optype(ea, 2);
		operand2 = ARM_get_operand(ea, 2);
	}
	else if (ea_operand_num == 4)
	{

		op0_type = get_optype(ea, 0);
		operand0 = ARM_get_operand(ea, 0);
		op1_type = get_optype(ea, 1);
		operand1 = ARM_get_operand(ea, 1);
		op2_type = get_optype(ea, 2);
		operand2 = ARM_get_operand(ea, 2);
		op3_type= get_optype(ea, 3);
		operand3= ARM_get_operand(ea, 3);
	}



	if (Mnem.find('B')==0&&Mnem!="BIC"&& Mnem != "BIC" && Mnem != "BFI")
	{
			if(op0_type==1)
				ARM_sub_iter_handler(Mnem, operand0, "", "", "", 82/*"B reg"*/);
			else 
				ARM_create_new_tmp_x64_my_instruction("", "");
		return;
	}
	/*else if (Mnem == "jnz" || Mnem == "jmp" || Mnem == "jz")
	{
		ARM_create_new_tmp_ARM_my_instruction("", "");
		return;
	}*/
	
	//MOV reg,reg 
	if (op0_type == 1 && op1_type == 1 && Mnem.find("MOV") != -1) { ARM_sub_iter_handler(Mnem,operand0, operand1, "","", 0/*"MOV reg,reg"*/); }

	//MOV reg, reg,shift num/reg
	else if (op0_type == 1 && op1_type == 8 && Mnem.find("MOV") != -1) { ARM_sub_iter_handler(Mnem, operand0, ARM_translate_shift(operand1), "", "", 1/*"MOV reg, reg,shift num/reg"*/); }

	//MOV reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MOV") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 2/*"MOV reg,num"*/); }

	//MVN reg,reg
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MVN") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 3/*MVN reg,reg*/);return; }

	//MVN reg, reg, shift num/reg
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MVN") != -1) { ARM_sub_iter_handler(Mnem, operand0, "!" + ARM_translate_shift(operand1), "", "", 4/*MVN reg, reg, shift num/reg*/);return; }

	//MVN reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MVN") != -1) { ARM_sub_iter_handler(Mnem, operand0, "!" + operand1.replace(0, 1, ""), "", "", 5/*MVN reg,num*/);return; }

	//MVT reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MVT") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 6/*MVT reg,num*/);return; }

	//LDR, reg, [reg {,num}]       LDR, reg, [reg {,num}]!        LDR, reg, [reg], num   
	else if (op0_type == 1 && op1_type == 4 && Mnem.find("LDR") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 7/*LDR, reg, [reg {,num}] */);return; }

	//LDR, reg, [reg, +/-reg {,shift}]        LDR, reg, [reg, +/-reg {,shift}] !        LDR, reg, [reg], +/-reg {,shift} 
	else if (op0_type == 1 && op1_type == 3 && Mnem.find("LDR") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 8/*LDR, reg, [reg, reg, {,shift}] */);return; }

	//LDR, reg, label 
	else if (op0_type == 1 && op1_type == 2 && Mnem.find("LDR") == 0) { ARM_sub_iter_handler(Mnem, operand0, operand1, std::to_string(ea), "", 9/*LDR, reg, label */);return; }

	//LDRD, reg, reg, label 
	else if (op0_type == 1 && op1_type == 1 && op2_type == 2 && Mnem.find("LDRD") == 0) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 10/*LDRD, reg, reg, label  */);return; }

	//LDRD, reg, reg, [reg {,num}], LDRD, reg, reg, [reg], num, LDRD, reg, reg, [reg ,num]! 
	else if (op0_type == 1 && op1_type == 1 && op2_type == 4 && Mnem.find("LDRD") == 0) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,"", 96/*LDRD, reg, reg, [reg {,num}], LDRD, reg, reg, [reg], num, LDRD, reg, reg, [reg ,num]!    */);return ; }

	//ADR, reg, label 
	else if (op0_type == 1 && (op1_type == 2) && Mnem.find("ADR") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 11/*LDR, reg, reg, label  */);return; }

	//ADR, reg, num 
	else if (op0_type == 1 && (op1_type == 5) && Mnem.find("ADR") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 102/*LDR, reg, reg, num  */);return; }

	//ADD PC, table_reg, offset_reg
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && operand0 == "PC" && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 17/*"ADD PC, table_reg, offset_reg*/);return; }

	//ADD reg, PC, reg
	else if ((Mnem.find("ADD") != -1||Mnem.find("ADC")!=-1) && operand1 == "PC" && op0_type==1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 83/*"ADD reg, PC, reg*/);return; }
	
	//STREX
	else if (op0_type == 1 && op1_type == 1 && op2_type == 4 && Mnem.find("STREX") == 0) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 84/*STR, reg, reg [] */);return; }

	//STR, reg, [reg {,num}] 
	else if (op0_type == 1 && op1_type == 4 && ea_operand_num == 2 && Mnem.find("STR") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 12/*STR, reg, [reg {,num}] */);return; }

	//STR, reg, [reg, reg {,shift}] 
	else if (op0_type == 1 && op1_type == 3 && ea_operand_num == 2 && Mnem.find("STR") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 13/*STR, reg, [reg, reg, {,shift}]*/);return; }

	//STRD reg, reg, [reg {,num}]   STRD reg, reg, [reg, num]!    STRD reg, reg, [reg] num     
	else if (op0_type == 1 && op1_type == 1 &&op2_type==4 && Mnem.find("STRD") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 97/*STRD reg, reg, [reg {,num}]   STRD reg, reg, [reg, num]!    STRD reg, reg, [reg] num */);return; }

	//LDM reg, {reg-reg}
	else if (op0_type == 1 && op1_type == 9 && Mnem.find("LDM") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 14/*LDM reg, {reg-reg}*/);return; }

	//STM reg, {reg-reg}
	else if (op0_type == 1 && op1_type == 9 && Mnem.find("STM") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 15/*STM reg, {reg-reg}*/);return; }

	//SWP reg, reg, [reg]
	else if (op0_type == 1 && op1_type == 1 && op2_type == 4 && Mnem.find("SWP") != -1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 16/*SWP reg, reg, [reg]*/);return; }


	//TST reg, reg
	else if ((Mnem.find("TST") != -1 || Mnem.find("TEQ") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 18/*"TST reg,reg*/); }

	//TST rax,1
	else if ((Mnem.find("TST") != -1 || Mnem.find("TEQ") != -1) && op0_type == 1 && op1_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 19/*"TST reg,num*/); }

	//TST, reg, reg,shift num/reg
	else if ((Mnem.find("TST") != -1 || Mnem.find("TEQ") != -1) && op0_type == 1 && op1_type == 8) { ARM_sub_iter_handler(Mnem, operand0, ARM_translate_shift(operand1), "", "", 20/*"TST reg, reg,shift num/reg*/); }

	//SEL reg, reg, reg
	//else if (Mnem.find("SEL")!=-1 && op0_type == 1 && op1_type == 1 && op2_type==1) { ARM_sub_iter_handler(ea, func, operand0, operand1, operand2, ?/*"test [],reg*/); }

	//CMP reg,reg
	else if ((Mnem.find("CMP") != -1 || Mnem.find("CMN") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 18/*"CMP reg,reg*/); }

	//CMP reg,num
	else if ((Mnem.find("CMP") != -1 || Mnem.find("CMN") != -1) && op0_type == 1 && op1_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 19/*"CMP reg,num*/); }

	//CMP reg, reg,shift num
	else if ((Mnem.find("CMP") != -1 || Mnem.find("CMN") != -1) && op0_type == 1 && op1_type == 8) { ARM_sub_iter_handler(Mnem, operand0, ARM_translate_shift(operand1), "", "", 20/*"CMP reg, reg,shift num*/); }

	//ADD reg, reg, reg
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && operand0 != "PC" && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 21/*"ADD reg, reg, reg*/); }

	//ADD reg, reg, reg,shift num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 22/*"ADD reg, reg, reg,shift num*/); }

	//ADD reg, reg, num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 23/*"ADD reg, reg, num*/); }

	//ADD reg, reg
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 24/*"ADD reg, reg*/); }

	//ADD reg, reg,shift num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 8) { ARM_sub_iter_handler(Mnem, operand0, ARM_translate_shift(operand1), "", "", 25/*"ADD reg, reg,shift num*/); }

	//ADD reg, num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 26/*"ADD reg, num*/); }


	//SUB reg, reg, reg
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 27/*"SUB reg, reg, reg*/); }

	//SUB reg, reg, reg,shift num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 28/*"SUB reg, reg, reg,shift num*/); }

	//SUB reg, reg, num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 29/*"SUB reg, reg, num*/); }

	//SUB reg, reg
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 30/*"SUB reg, reg*/); }

	//SUB reg, reg,shift num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 8) { ARM_sub_iter_handler(Mnem, operand0, ARM_translate_shift(operand1), "", "", 31/*"SUB reg, reg,shift num*/); }

	//SUB reg, num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 32/*"SUB reg, num*/); }

	//RSB reg, reg, reg
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 33/*"RSB reg, reg, reg*/); }

	//RSB reg, reg, reg,shift num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 34/*"RSB reg, reg, reg,shift num*/); }

	//RSB reg, reg, num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 35/*"RSB reg, reg, num*/); }

	//RSB reg, reg
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 36/*"RSB reg, reg*/); }

	//RSB reg, reg,shift num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 8) { ARM_sub_iter_handler(Mnem, operand0, ARM_translate_shift(operand1), "", "", 37/*"RSB reg, reg,shift num*/); }

	//RSB reg, num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1.replace(0, 1, ""), "", "", 38/*"RSB reg, num*/); }

	//AND reg, reg, reg
	else if (Mnem.find("AND") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 39/*"AND reg, reg, reg*/); }

	//AND reg, reg, num
	else if (Mnem.find("AND") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 40/*"AND reg, reg, num*/); }

	//AND reg, reg, reg,shift num
	else if (Mnem.find("AND") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 41/*"AND reg, reg, reg,shift num*/); }

	//ORR reg, reg, reg
	else if (Mnem.find("ORR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 42/*"ORR reg, reg, reg*/); }

	//ORR reg, reg, num
	else if (Mnem.find("ORR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 43/*"ORR reg, reg, num*/); }

	//ORR reg, reg, reg,shift num
	else if (Mnem.find("ORR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 44/*"ORR reg, reg, reg,shift num*/); }

	//EOR reg, reg, reg
	else if (Mnem.find("EOR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 45/*"EOR reg, reg, reg*/); }

	//EOR reg, reg, num
	else if (Mnem.find("EOR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 46/*"EOR reg, reg, num*/); }

	//EOR reg, reg, reg,shift num
	else if (Mnem.find("EOR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 47/*"EOR reg, reg, reg,shift num*/); }

	//BIC reg, reg, reg
	else if (Mnem.find("BIC") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 48/*"BIC reg, reg, reg*/); }

	//BIC reg, reg, num
	else if (Mnem.find("BIC") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 49/*"BIC reg, reg, num*/); }

	//BIC reg, reg, reg,shift num
	else if (Mnem.find("BIC") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 50/*"BIC reg, reg, reg,shift num*/); }

	//ORN reg, reg, reg
	else if (Mnem.find("ORN") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 51/*"ORN reg, reg, reg*/); }

	//ORN reg, reg, num
	else if (Mnem.find("ORN") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 52/*"ORN reg, reg, num*/); }

	//ORN reg, reg, reg,shift num
	else if (Mnem.find("ORN") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, ARM_translate_shift(operand2), "", 53/*"ORN reg, reg, reg,shift num*/); }


	//REV reg, reg
	else if ((Mnem.find("REV") != -1 || Mnem.find("RBIT") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 54/*"ORN reg, reg, reg,shift num*/); }

	//ASR reg, reg, reg
	else if ((Mnem.find("ASR") != -1 || Mnem.find("LSR") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 55/*"ASR reg, reg, reg,shift num*/); }

	//ASR reg, reg, num
	else if ((Mnem.find("ASR") != -1 || Mnem.find("LSR") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 56/*"ASR reg, reg, reg,shift num*/); }

	//LSL reg, reg, reg
	else if ((Mnem.find("LSL") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 57/*"LSL reg, reg, reg,shift num*/); }

	//LSL reg, reg, num
	else if ((Mnem.find("LSL") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 58/*"LSL reg, reg, reg,shift num*/); }

	//RRX reg, reg, reg
	else if ((Mnem.find("RRX") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 59/*"RRX reg, reg, reg,shift num*/); }

	//RRX reg, reg, num
	else if ((Mnem.find("RRX") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 60/*"RRX reg, reg, reg,shift num*/); }

	//MUL  reg,reg
	else if (Mnem.find("MUL") == 0 && op0_type == 1 && op1_type == 1 && ea_operand_num == 2) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 61/*"MUL reg,reg*/); }

	//MUL  reg,reg, reg
	else if (Mnem.find("MUL") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 62/*"MUL reg,reg, reg*/); }

	//MLA reg, reg, reg, reg
	else if (Mnem.find("MLA") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,operand3, 63/*"MLA reg, reg, reg, reg*/); }

	//MLS reg, reg, reg, reg
	else if (Mnem.find("MLS") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 64/*"MLS reg, reg, reg, reg*/); }

	//UMULL reg, reg, reg, reg
	else if ((Mnem.find("UMULL") == 0 || Mnem.find("SMULL") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 65/*"UMULL reg, reg, reg, reg*/); }

	//UMLAL reg, reg, reg, reg
	else if ((Mnem.find("UMLAL") == 0 || Mnem.find("SMLAL") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 66/*"UMLAL reg, reg, reg, reg*/); }

	//SMULxy reg,reg,reg
	else if ((Mnem.find("SMULT") == 0 || Mnem.find("SMULB") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,"", 67/*"SMULxy reg,reg,reg*/); }

	//SMLAxy reg, reg, reg, reg
	else if ((Mnem.find("SMLAT") == 0 || Mnem.find("SMLAB") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,operand3, 68/*"SMLAxy reg, reg, reg, reg*/); }

	//SMULWy reg, reg, reg
	else if (Mnem.find("SMULW") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,"", 69/*"SMULWy reg, reg, reg*/); }

	//SMLAWy reg, reg, reg, reg
	else if (Mnem.find("SMLAW") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 70/*"SMLAWy reg, reg, reg, reg*/); }

	//SMLALxy reg, reg, reg, reg
	else if ((Mnem.find("SMLALT") == 0 || Mnem.find("SMLALB") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 71/*"SMLALxy reg, reg, reg, reg*/); }

	//SMUAD reg, reg, reg
	else if (Mnem.find("SMUAD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,"", 72/*"SMUAD reg, reg, reg*/); }

	//SMUSD reg, reg, reg
	else if (Mnem.find("SMUSD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,"", 73/*"SMUSD reg, reg, reg*/); }

	//SMMUL reg, reg, reg
	else if (Mnem.find("SMMUL") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2,"", 74/*"SMMUL reg, reg, reg*/); }

	//SMMLA reg, reg, reg, reg
	else if (Mnem.find("SMMLA") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 75/*"SMMLA reg, reg, reg, reg*/); }

	//SMMLS reg, reg, reg, reg
	else if (Mnem.find("SMMLS") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 76/*"SMMLS reg, reg, reg, reg*/); }

	//SMLAD reg, reg, reg, reg
	else if (Mnem.find("SMLAD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 77/*"SMLAD reg, reg, reg, reg*/); }

	//SMLSD reg, reg, reg, reg
	else if (Mnem.find("SMLSD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 78/*"SMLSD reg, reg, reg, reg*/); }

	//SMLALD reg, reg, reg, reg
	else if (Mnem.find("SMLALD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 79/*"SMLALD reg, reg, reg, reg*/); }

	//SMLSLD reg, reg, reg, reg
	else if (Mnem.find("SMLSLD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 80/*"SMLSLD reg, reg, reg, reg*/); }

	//UMAAL reg, reg, reg, reg
	else if (Mnem.find("UMAAL") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, operand3, 81/*"SMLSLD reg, reg, reg, reg*/); }

	//ROR reg, reg, reg
	else if ((Mnem.find("ROR") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 85/*"ROR reg, reg, reg,reg*/); }

	//ROR reg, reg, num
	else if ((Mnem.find("ROR") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_sub_iter_handler(Mnem, operand0, operand1, operand2, "", 86/*"ROR reg, reg, reg,shift num*/); }

	//CLZ reg, reg
	else if ((Mnem.find("CLZ") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 98/*"CLZ reg, reg*/); }

	//CTZ reg, reg
	else if ((Mnem.find("CTZ") != -1) && op0_type == 1 && op1_type == 1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 101/*"CTZ reg, reg*/); }

	//UTX reg, reg
	else if(Mnem.find("UTX")!=-1 && op0_type==1 && op1_type==1) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 99/*UTX reg, reg*/); }

	//UTX reg, reg, ror #8/#16/#24
	else if (Mnem.find("UTX") != -1 && op0_type == 1 && op1_type == 8) { ARM_sub_iter_handler(Mnem, operand0, operand1, "", "", 100/*UTX reg, reg, ror #8/#16/#24*/); }

	else//Unknonw Mnems
	{
		ARM_create_new_tmp_ARM_my_instruction(operand0, "");
	
	}
	return;
}


int ARM_sub_iter_handler(std::string Mnem, std::string operand0, std::string operand1, std::string operand2, std::string operand3, int mode)
{
	std::string defined_value, defined_value1,defined_value2,defined_value3,tmp,tmp2,tmp3;
	std::string num;
	int comma;
	char label[100];
	ea_t ea1;
	qstring buffer;
	func_t* func;
	ARM_create_new_tmp_x64_my_instruction("","");
	switch (mode) {
	case 0:/*"MOV reg,reg"*/
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand(defined_value1, 0);
		return 0;
	case 1://MOV reg, reg,shift num/reg
		defined_value1 = ARM_iter_process_shift_operand(operand1,1);
		ARM_iter_propagate_to_operand(defined_value1, 0);
		return 0;
	case 2://MOV reg,num
		ARM_iter_propagate_to_operand(operand1, 0);
		return 0;
	case 3://MVN reg,reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("!" + defined_value1, 0);
		return 0;
	case 4://MVN reg, reg, shift num/reg
		defined_value1 = ARM_iter_process_shift_operand(operand1, 1);
		ARM_iter_propagate_to_operand("!"+defined_value1, 0);
		return 0;
	case 5://MVN reg,num
		ARM_iter_propagate_to_operand("!" + operand1, 0);
		return 0;
	case 6://MVT reg,num
		tmp = ARM_iter_lookForDefine(operand0);
		if(tmp=="") { warning("error: Strange! Register should have been defined!"); }
		defined_value = operand1 + "<<16" + tmp;
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 7://LDR, reg, [reg {,num}]        LDR, reg, [reg {,num}]!        LDR, reg, [reg], num   
		if (operand1.find("#(") != -1)//if the offset is translated by IDA to #(label-offset), we need to translate it back to number
		{
			operand1 = ARM_numerize_offset(operand1);
		}
		if (ARM_is_regiter_offset(operand1))
			ARM_iter_LDR_type4_register_offset(operand1);
		else if (ARM_is_pre_indexed(operand1))
			ARM_iter_LDR_type4_pre_indexed(operand1);
		else if (ARM_is_post_indexed(operand1))
			ARM_iter_LDR_type4_post_indexed(operand1);
		return 0;
	case 8://LDR, reg, [reg, +/-reg {,shift}]          LDR, reg, [reg, +/-reg {,shift}] !        LDR, reg, [reg], +/-reg {,shift} 
		if (ARM_is_regiter_offset(operand1))
			ARM_iter_LDR_type3_register_offset(operand1);
		else if (ARM_is_pre_indexed(operand1))
			ARM_iter_LDR_type3_pre_indexed(operand1);
		else if (ARM_is_post_indexed(operand1))
			ARM_iter_LDR_type3_post_indexed(operand1);
		return 0;
	case 9://LDR, reg, label
		//tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = operand1;
		//tmp = debug_iter_sinsn[tmp_ARM_my_insn.size() - 1];
		//tmp = operand1.substr(operand1.find("=(") + 2, operand1.find('-') - operand1.find("=(") - 2);//get the label
		//qstrncpy(label, tmp.c_str(), tmp.size());
		//ea1 = get_name_ea(BADADDR, label);//get the address of that string
		//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
		//tmp = filter_specific_string(buffer.c_str());
		ea1 = atoi(operand2.c_str());//We have hide ea to operand2.
		func = get_func(ea1);
		//tmp = ARM_get_label_value(operand1,func);
		operand1= ARM_get_operand(ea1, 1);
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = operand1;
		
		return 0;
	case 10://LDRD, reg, reg, label 
		qstrncpy(label, operand2.c_str(), operand2.size());
		//ea1 = get_name_ea(BADADDR, label);//get the address of that string
		//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
		//tmp = filter_specific_string(buffer.c_str());
		tmp = get_label_value(label);
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp;
	

		get_strlit_contents(&buffer, ea1+ DWORD_LEN, -1, STRTYPE_C);//get the string content
		tmp = buffer.c_str();
		if (!tmp.empty())//If we successfully got the string content
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = '"'+tmp+'"';
		else//if unsuccessful
			tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = ARM_translate_LDRD_STRD_second_op(operand2);;
		return 0;
	case 11://ADR, reg, label
		qstrncpy(label, operand1.c_str(), operand1.size()+1);
		tmp = label;
		ea1 = get_name_ea(BADADDR, label);//get the address of that string
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = dec2hex(ea1);
		//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
		//tmp = buffer.c_str();
		//if (!tmp.empty())//If we successfully got the string content
		//	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = '"'+tmp+'"';
		//else//if unsuccessful
		//	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = operand1;
		return 0;
	case 12://STR, reg, [reg {,num}]           STR, reg, [reg {,num}]!        STR, reg, [reg], num   
		if (operand1.find("#(") != -1)//if the offset is translated by IDA to #(label-offset), we need to translate it back to number
		{
			operand1 = ARM_numerize_offset(operand1);
		}
		if (ARM_is_regiter_offset(operand1))
			ARM_iter_STR_type4_register_offset(operand0, operand1);
		else if (ARM_is_pre_indexed(operand1))
			ARM_iter_STR_type4_pre_indexed(operand0, operand1);
		else if (ARM_is_post_indexed(operand1))
			ARM_iter_STR_type4_post_indexed(operand0, operand1);
		return 0;
	case 13://STR, reg, [reg, reg {,shift}]            STR, reg, [reg, +/-reg {,shift}] !        STR, reg, [reg], +/-reg {,shift} 
		if (ARM_is_regiter_offset(operand1))
			ARM_iter_STR_type3_register_offset(operand0, operand1);
		else if (ARM_is_pre_indexed(operand1))
			ARM_iter_STR_type3_pre_indexed(operand0, operand1);
		else if (ARM_is_post_indexed(operand1))
			ARM_iter_STR_type3_post_indexed(operand0, operand1);
		return 0;
	case 14://LDM reg, {reg-reg}
		if (operand0.find('!') == operand0.size() - 1)
			operand0 = operand0.substr(0, operand0.size() - 1);
		ARM_iter_process_LDM(operand0, operand1);
		return 0;
	case 15://STM reg, {reg-reg}
		if (operand0.find('!') == operand0.size() - 1)
			operand0 = operand0.substr(0, operand0.size() - 1);
		ARM_iter_process_STM(operand0, operand1);
		return 0;
	case 16://SWP reg, reg, [reg]
		tmp2 = ARM_extract_bracket_base(operand2);
		defined_value2 = ARM_iter_lookForDefine(tmp2);
		if(defined_value2=="") { warning("error: Strange! Register should have been defined!"); }
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters2.insert({ tmp2, defined_value2 });
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = "[" + defined_value2 + "]";
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = defined_value1;
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand2 = tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 + "=" + defined_value1;
		return 0;
	case 17://ADD PC, table_reg, offset_reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		ARM_iter_propagate_to_operand(defined_value1+"+"+defined_value2, 0);
		return 0;
	case 18://CMP reg,reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if(defined_value1=="") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 19://CMP reg,num
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand( defined_value, 0);
		return 0;
	case 20://CMP reg, reg,shift num/reg
		ARM_iter_process_shift_operand(operand1, 1);
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 21://ADD reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2, "+");
		if (Mnem.find("ADC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "+CF)";
		}
		return 0;
	case 22://ADD reg, reg, reg,shift num/reg
		ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2,  "+");
		if (Mnem.find("ADC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "+CF)";
		}
		return 0;
	case 23://ADD reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  "+");
		if (Mnem.find("ADC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "+CF)";
		}
		return 0;
	case 24://ADD reg, reg
		ARM_iter_arithmatic_propagate_reg_reg(operand0, operand1, "+");
		if (Mnem.find("ADC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "+CF)";
		}
		return 0;
	case 25://ADD reg, reg,shift num
		ARM_iter_arithmatic_propagate_reg_shift(operand0, operand1, "+");
		if (Mnem.find("ADC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "+CF)";
		}
		return 0;
	case 26://ADD reg, num
		ARM_iter_arithmatic_propagate_reg_num(operand0, operand1, "+");
		if (Mnem.find("ADC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "+CF)";
		}
		return 0;
	case 27://SUB reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2,  "-");
		if (Mnem.find("SBC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "-CF)";
		}
		return 0;
	case 28://SUB reg, reg, reg,shift num/reg
		ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2,  "-");
		if (Mnem.find("SBC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "-CF)";
		}
		return 0;
	case 29://SUB reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  "-");
		if (Mnem.find("SBC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "-CF)";
		}
		return 0;
	case 30://SUB reg, reg
		ARM_iter_arithmatic_propagate_reg_reg(operand0, operand1, "-");
		if (Mnem.find("SBC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "-CF)";
		}
		return 0;
	case 31://SUB reg, reg,shift num
		ARM_iter_arithmatic_propagate_reg_shift(operand0, operand1,  "-");
		if (Mnem.find("SBC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "-CF)";
		}
		return 0;
	case 32://SUB reg, num
		ARM_iter_arithmatic_propagate_reg_num(operand0, operand1, "-");
		if (Mnem.find("SBC") != -1)
		{
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.substr(0, tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0.size() - 1);
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 += "-CF)";
		}
		return 0;
	case 33://RSB reg, reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		ARM_iter_propagate_to_operand("("+defined_value2 + "-" + defined_value1+")", 0);
		return 0;
	case 34://RSB reg, reg, reg,shift num/reg
		defined_value2 = ARM_iter_process_shift_operand(operand2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("("+defined_value2 + "-" + defined_value1+")", 0);
		return 0;
	case 35://RSB reg, reg, num
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("("+operand2 + "-" + defined_value1+")", 0);
		return 0;
	case 36://RSB reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters0.insert({"original",defined_value });
		ARM_iter_propagate_to_operand("("+defined_value1 + "-" + defined_value+")", 0);
		return 0;
	case 37://RSB reg, reg,shift num/reg
		defined_value1 = ARM_iter_process_shift_operand(operand1, 1);
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand("("+defined_value1 + "-" + defined_value+")", 0);
		return 0;
	case 38://RSB reg, num
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters0.insert({ "original",defined_value });
		ARM_iter_propagate_to_operand("("+operand1 + "-" + defined_value+")", 0);
		return 0;
	case 39://AND reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2, "&");
		return 0;
	case 40://AND reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  "&");
		return 0;
	case 41://AND reg, reg, reg,shift num/reg
		ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2, "&");
		return 0;
	case 42://ORR reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2, "|");
		return 0;
	case 43://ORR reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2, "|");
		return 0;
	case 44://ORR reg, reg, reg,shift num/reg
		ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2, "|");
		return 0;
	case 45://EOR reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2,  "^");
		return 0;
	case 46://EOR reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  "^");
		return 0;
	case 47://EOR reg, reg, reg,shift num/reg
		ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2,  "^");
		return 0;
	case 48://BIC reg, reg, reg
		//ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2,  "&!");
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		ARM_iter_propagate_to_operand("(" + defined_value2 + "&(!(" + defined_value1 + ")))", 0);
		return 0;
	case 49://BIC reg, reg, num
		//ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  "&!");
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("(" + defined_value1 + "&(!(" + operand2 + ")))", 0);
		return 0;
	case 50://BIC reg, reg, reg,shift num/reg
		//ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2,  "&!");
		defined_value2 = ARM_iter_process_shift_operand(operand2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("(" + defined_value1 + "&(!(" + defined_value2 + ")))", 0);
		return 0;
	case 51://ORN reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2,  "|!");
		return 0;
	case 52://ORN reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2, "|!");
		return 0;
	case 53://ORN reg, reg, reg,shift num/reg
		ARM_iter_arithmatic_propagate_reg_reg_shift(operand1, operand2, "|!");
		return 0;
	case 54://REV reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("~" + defined_value1, 0);
		return 0;
	case 55://ASR reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2, ">>");
		return 0;
	case 56://ASR reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  ">>");
		return 0;
	case 57://LSL reg, reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2,  "<<");
		return 0;
	case 58://LSL reg, reg, num
		ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2,  "<<");
		return 0;
	case 59://RRX reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		defined_value = "(" + defined_value1 + ">>1)&fffffff|((" + defined_value1 + "&1)<<31)";
		ARM_iter_propagate_to_operand(defined_value, 0);
		//ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, "1",  ">>");
		return 0;
	case 60://RRX reg, reg, num
		//ARM_iter_arithmatic_propagate_reg_reg_num(operand1, operand2, ">>");
		return 0;
	case 61://MUL  reg,reg
		ARM_iter_arithmatic_propagate_reg_reg(operand0, operand1, "*");
		return 0;
	case 62://MUL  reg,reg, reg
		ARM_iter_arithmatic_propagate_reg_reg_reg(operand1, operand2, "*");
		return 0;
	case 63://MLA reg, reg, reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand("("+defined_value1 + "*" + defined_value2 + "+" + defined_value3+")", 0);
		return 0;
	case 64://MLS reg, reg, reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand("("+defined_value1 + "*" + defined_value2 + "-" + defined_value3+")", 0);
		return 0;
	case 65://UMULL reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand( "((" + defined_value2 + "*" + defined_value3 + ")|ffffffff00000000)", 1);
		ARM_iter_propagate_to_operand( "((" + defined_value2 + "*" + defined_value3 + ")|ffffffff)", 0);
		return 0;
	case 66://UMLAL reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1 + "+((" + defined_value2 + "*" + defined_value3 + ")|ffffffff00000000)", 1);
		ARM_iter_propagate_to_operand(defined_value + "+((" + defined_value2 + "*" + defined_value3 + ")|ffffffff)", 0);
		return 0;
	case 67://SMULxy reg,reg,reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		if (Mnem == "SMULTB")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		else if (Mnem == "SMULTT")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		else if (Mnem == "SMULBB")
		{
			defined_value1 = "("+defined_value1+"|ffffffff)";
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		else if (Mnem == "SMULBT")
		{
			defined_value1 = "("+defined_value1+"|ffffffff)";
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		ARM_iter_propagate_to_operand(defined_value1 + "*" + defined_value2, 0);
		return 0;
	case 68://SMLAxy reg, reg, reg, reg	
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		if (Mnem == "SMLATB")
		{
			defined_value1 = "("+defined_value1+"|ffffffff00000000)";
			defined_value2 = "("+defined_value2+"|ffffffff£©";
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
		ARM_iter_propagate_to_operand(defined_value1 + "*" + defined_value2 + "+" + defined_value3, 0);
		return 0;
	case 69://SMULWy reg, reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		if (Mnem == "SMULWT")
		{
			defined_value2 = "£¨"+defined_value2+"|ffffffff00000000£©";
		}
		else if (Mnem == "SMULWB")
		{
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		ARM_iter_propagate_to_operand(defined_value1 + "*" + defined_value2, 0);
		return 0;
	case 70://SMLAWy reg, reg, reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		if (Mnem == "SMLAWT")
		{
			defined_value2 = "("+defined_value2+"|ffffffff00000000)";
		}
		else if (Mnem == "SMLAWB")
		{
			defined_value2 = "("+defined_value2+"|ffffffff)";
		}
		ARM_iter_propagate_to_operand(defined_value1 + "*" + defined_value2 + "+" + defined_value3, 0);
		return 0;
	case 71://SMLALxy reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
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
			defined_value2 = "("+defined_value2+"|ffffffff)";
			defined_value3 = "("+defined_value3+"|ffffffff)";
		}
		else if (Mnem == "SMLALBT")
		{
			defined_value2 = "("+defined_value2+"|ffffffff)";
			defined_value3 = "("+defined_value3+"|ffffffff00000000)";
		}
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand("((" + defined_value2 + "*" + defined_value3 + "+" + defined_value1 + "<<32|" + defined_value + ")|ffffffff00000000)", 1);
		ARM_iter_propagate_to_operand("((" + defined_value2 + "*" + defined_value3 + "+" + defined_value1 + "<<32|" + defined_value + ")|ffffffff)", 0);
		return 0;
	case 72://SMUAD reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand(defined_value1 + "|ffffffff*" + defined_value2 + "|ffffffff+" + defined_value1 + "|ffffffff00000000*" + defined_value2 + "|ffffffff00000000", 0);
		return 0;
	case 73://SMUSD reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand(defined_value1 + "|ffffffff*" + defined_value2 + "|ffffffff-" + defined_value1 + "|ffffffff00000000*" + defined_value2 + "|ffffffff00000000", 0);
		return 0;
	case 74://SMMUL reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("((" + defined_value1 + "*" + defined_value2 + ")|ffffffff00000000)", 0);
		return 0;
	case 75://SMMLA reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand("((" + defined_value1 + "*" + defined_value2 + ")|ffffffff00000000)+" + defined_value3, 0);
		return 0;
	case 76://SMMLS reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand( defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand(defined_value3 + "<<32-" + "((" + defined_value1 + "*" + defined_value2 + ")|ffffffff00000000)+", 0);
		return 0;
	case 77://SMLAD reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand(defined_value1 + "|ffffffff00000000)*" + defined_value2 + "|ffffffff00000000)+" + defined_value1 + "|ffffffff)*" + defined_value2 + "|ffffffff+" + defined_value3, 0);
		return 0;
	case 78://SMLSD reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		ARM_iter_propagate_to_operand(defined_value1 + "|ffffffff*" + defined_value2 + "|ffffffff-" + defined_value1 + "|ffffffff00000000*" + defined_value2 + "|ffffffff00000000+" + defined_value3, 0);
		return 0;
	case 79://SMLALD reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value3, 3);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand("((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff+" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff)", 0);
		ARM_iter_propagate_to_operand("((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff+" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff00000000)", 1);
		return 0;
	case 80://SMLSLD reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand( defined_value3, 3);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand( "((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff-" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff)", 0);
		ARM_iter_propagate_to_operand( "((" + defined_value2 + "|ffffffff*" + defined_value3 + "|ffffffff-" + defined_value2 + "|ffffffff00000000*" + defined_value3 + "|ffffffff00000000" + defined_value1 + "<<32|" + defined_value + ")|ffffffff00000000)", 1);
		return 0;
	case 81://UMAAL reg, reg, reg, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand( defined_value2, 2);
		tmp3 = operand3;
		defined_value3 = ARM_iter_lookForDefine(tmp3);
		if (defined_value3 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand( defined_value3, 3);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand("((" + defined_value2 + "*" + defined_value3 + "+" + defined_value + "+" + defined_value1 + ")|ffffffff)", 0);
		ARM_iter_propagate_to_operand("((" + defined_value2 + "*" + defined_value3 + "+" + defined_value + "+" + defined_value1 + ")|ffffffff00000000)", 1);
		return 0;
	case 82://B reg
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 83: //ADD reg, PC, reg
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value2, 2);
		ARM_iter_propagate_to_operand(defined_value2, 0);
		return 0;
	case 84: //STREX reg, reg, [reg {, offset}]
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand("0", 0);
		tmp2 = ARM_extract_bracket_base(operand2);
		defined_value2 = ARM_iter_lookForDefine(tmp2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value2= ARM_translate_type4_register_offset(operand2, defined_value2);
		ARM_iter_propagate_to_operand("["+defined_value2+"]="+defined_value1, 2);
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,defined_value2 });
		return 0;
	case 85://ROR reg, reg, reg
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value2 = ARM_iter_lookForDefine(operand2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "("+defined_value1 + ">>" + defined_value2 + "|" + defined_value1 + "<<" + "(32-" + defined_value2 + "))";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 86://ROR reg, reg, num
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "("+defined_value1 + ">>" + operand2 + "|" + defined_value1 + "<<" + "(32-" + operand2 + "))";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 87://MOVT reg,num
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "(("+defined_value + "&ffff0000)|(" + operand1 + "<<16" + "))";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 88://MOVW reg,num
		//defined_value = ARM_iter_lookForDefine(operand0);
		defined_value = operand1;
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 89: //MOVW reg,reg  
		//defined_value = ARM_iter_lookForDefine(operand0);
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = defined_value1;
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 90://unknown Mnem reg, reg
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "UNKNOWN(" + defined_value + "," + defined_value1 + ")";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 91: //unknown Mnem reg, num
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "UNKNOWN(" + defined_value + "," + operand1 + ")";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 92://unknown Mnem reg, reg,shift
		defined_value = ARM_iter_lookForDefine(operand0);
		if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value1 = ARM_iter_process_shift_operand(operand1, 1);
		defined_value = "UNKNOWN(" + defined_value + "," + defined_value1 + ")";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 93:/*RBIT reg, reg*/
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "(" + defined_value1 + "&80000000h)>>31|(" + defined_value1 + "&40000000h)>>29|(" + defined_value1 + "&20000000h)>>27|("\
			+ defined_value1 + "&10000000h)>>25|(" + defined_value1 + "&8000000h)>>23|(" + defined_value1 + "&4000000h)>>21|(" + defined_value1 + "&2000000h)>>19|("\
			+ defined_value1 + "&1000000h)>>17|(" + defined_value1 + "&800000h)>>15|(" + defined_value1 + "&400000h)>>13|(" + defined_value1 + "&200000h)>>11|("\
			+ defined_value1 + "&100000h)>>9|(" + defined_value1 + "&80000h)>>7|(" + defined_value1 + "&40000h)>>5|(" + defined_value1 + "&20000h)>>3|("\
			+ defined_value1 + "&10000h)>>1|(" + defined_value1 + "&8000h)<<1|(" + defined_value1 + "&4000h)<<3|(" + defined_value1 + "&2000h)<<5|(" + defined_value1\
			+ "&1000h)<<7|(" + defined_value1 + "&800h)<<9|(" + defined_value1 + "&400h)<<11|(" + defined_value1 + "&200h)<<13|(" + defined_value1 + "&100h)<<15|(" + \
			defined_value1 + "&80h)<<17|(" + defined_value1 + "&40h)<<19|(" + defined_value1 + "&20h)<<21|(" + defined_value1 + "&10h)<<23|(" + defined_value1 + "&8h)<<25|("\
			+ defined_value1 + "4h)<<27|(" + defined_value1 + "&2h)<<29|(" + defined_value1 + "&1h)<<31";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 94:/*REV16 reg, reg*/
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "(" + defined_value1 + "&ff00ff00)>>8|(" + defined_value1 + "&00ff00ff)<<8";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 95:/*REVSH reg, reg*/
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		defined_value = "(" + defined_value1 + "&ff00)>>8|(" + defined_value1 + "&ff)<<8|(" + defined_value1 + "&80h)&ffff";
		ARM_iter_propagate_to_operand(defined_value, 0);
		return 0;
	case 96://LDRD, reg, reg, [reg {,num}], LDRD, reg, reg, [reg], num, LDRD, reg, reg, [reg ,num]! 
		if (ARM_is_regiter_offset(operand2))
			ARM_iter_LDRD_type4_register_offset(operand2);
		else if (ARM_is_pre_indexed(operand2))
			ARM_iter_LDRD_type4_pre_indexed(operand2);
		else if (ARM_is_post_indexed(operand2))
			ARM_iter_LDRD_type4_post_indexed(operand2);
		return 0;
	case 97:/*STRD reg, reg, [reg{ ,num }]   STRD reg, reg, [reg, num]!STRD reg, reg, [reg] num*/
		if (ARM_is_regiter_offset(operand2))
			ARM_iter_STRD_type4_register_offset(operand0, operand1,operand2);
		else if (ARM_is_pre_indexed(operand2))
			ARM_iter_STRD_type4_pre_indexed(operand0, operand1,operand2);
		else if (ARM_is_post_indexed(operand2))
			ARM_iter_STRD_type4_post_indexed(operand0, operand1,operand2);
		return 0;
	case 98:/*CLZ reg, reg*/
		defined_value1= ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		//tmp = std::to_string(ARM_BIT - 1) + "-log2(" + defined_value1 + ")";
		tmp = "bsr(" + defined_value1 + ')';
		ARM_iter_propagate_to_operand(tmp, 0);
		return 0;
	case 99:/*UTX reg, reg*/
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		ARM_iter_propagate_to_operand(defined_value1, 0);
		return 0;
	case 100:/*UTX reg, reg, ror #8 / #16 / #24*/
		defined_value1 = ARM_iter_process_shift_operand(operand1, 1);
		ARM_iter_propagate_to_operand(defined_value1, 1);
		if (Mnem.find("UXTB") != -1)
			defined_value1 = defined_value1 + "&ff";
		else if(Mnem.find("UXTH") != -1)
			defined_value1 = defined_value1 + "&ffff";
		ARM_iter_propagate_to_operand(defined_value1, 0);
		return 0;
	case 101:/*CTZ reg, reg*/
		defined_value1 = ARM_iter_lookForDefine(operand1);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		ARM_iter_propagate_to_operand(defined_value1, 1);
		//tmp = std::to_string(ARM_BIT - 1) + "-log2(" + defined_value1 + ")";
		tmp = "bsf(" + defined_value1 + ')';
		ARM_iter_propagate_to_operand(tmp, 0);
		return 0;
	case 102://ADR, reg, num
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = operand1;
		return 0;
	}
}

void ARM_create_new_tmp_ARM_my_instruction(std::string operand, std::string operand1)
{
	struct ARM_my_instruction new_one;
	new_one.operand0 = operand;
	new_one.operand1 = operand1;
	tmp_ARM_my_insn.push_back(new_one);
}


std::string ARM_iter_lookForDefine(std::string operand)
{
	bool operandIsR0_R1 = false;
	qstring Mnem = "";
	std::string equivilant_operand, return_val;
	int which_op = -1;
	if (operand == "R0"||operand=="R1")
		operandIsR0_R1 = true;
	for (int i = tmp_ARM_insn_record.size() - 2;i >= 0;i--) {
		print_insn_mnem(&Mnem, tmp_ARM_insn_record[i]);
		if (Mnem.find("PUSH")!=-1 || Mnem.find("POP")!=-1)
		{
			continue;
		}
		else if (Mnem.find("B")==0 && Mnem!="BIC" && Mnem != "BFC" && Mnem != "BFI")
		{
			if (operandIsR0_R1 == true)//When the look-up word is r0-r1, this can potentially be the return value of calling subroutine
			{
				return_val = "RETURN_" + dec2hex(tmp_ARM_insn_record[i]);
				return return_val;
			}
			else if (ARM_get_operand(tmp_ARM_insn_record[i], 0) == operand)//otherwise, the calling function's name is a register and this register is what we are looking for
			{
				return_val = tmp_ARM_my_insn[i].operand0;
				return return_val;
			}
			continue;
		}
		std::string operand0 = ARM_get_operand(tmp_ARM_insn_record[i], 0);
		std::string operand1 = ARM_get_operand(tmp_ARM_insn_record[i], 1);
		std::string operand2 = ARM_get_operand(tmp_ARM_insn_record[i], 2);
		std::string operand3 = ARM_get_operand(tmp_ARM_insn_record[i], 3);
		int type0 = get_optype(tmp_ARM_insn_record[i], 0);
		if (type0==1 && (operand0.find('!') == operand0.size() - 1))//if the operand is a register and ends with a '!'
			operand0 = operand0.substr(0, operand0.size() - 1);
		int type1 = get_optype(tmp_ARM_insn_record[i], 1);
		if (type1 == 1 && (operand1.find('!') == operand1.size() - 1))//if the operand is a register and ends with a '!'
			operand1 = operand1.substr(0, operand1.size() - 1);
		if (operand1.find(';') != -1) operand1 = operand1.substr(0, operand1.find(';'));
		if (operand0==operand)
		{
			return_val = tmp_ARM_my_insn[i].operand0; which_op = 0;
		}
		else if (operand1==operand)
		{
			return_val = tmp_ARM_my_insn[i].operand1; which_op = 1;
		}
		else if (operand2 == operand)
		{
			return_val = tmp_ARM_my_insn[i].operand2; which_op = 2;
		}
		else if (operand3 == operand)
		{
			return_val = tmp_ARM_my_insn[i].operand3; which_op = 3;
		}
		else {
			if (ARM_contain_register(operand0, operand))
			{
				return_val = tmp_ARM_my_insn[i].parameters0[operand]; which_op = 0;
			}
			
			else if (ARM_contain_register(operand1, operand))
			{
				return_val = tmp_ARM_my_insn[i].parameters1[operand]; which_op = 1;
			}
			else if (ARM_contain_register(operand2, operand))
			{
				return_val = tmp_ARM_my_insn[i].parameters2[operand]; which_op = 2;
			}
			else if (ARM_contain_register(operand3, operand))
			{
				return_val = tmp_ARM_my_insn[i].parameters3[operand]; which_op = 3;
			}
			else if (get_optype(tmp_ARM_insn_record[i], 1) == 9)//if the operand is in form {r0-r9}
			{
				for (const auto each_pair : tmp_ARM_my_insn[i].parameters1)//for each key value pair stored in .parameters1
					if (each_pair.first == operand)//if there is some register we are looking for
					{
						which_op = 1;
						return_val = each_pair.second;
						return return_val;
					}
			}
		}
		if (return_val != "") return return_val;
		else if (return_val == "" && which_op != -1 && ARM_is_use_stmt(Mnem, tmp_ARM_insn_record[i], which_op))
			continue;
		else if (return_val == "" && which_op != -1 && !ARM_is_use_stmt(Mnem, tmp_ARM_insn_record[i], which_op))
			return return_val;
	}
	return return_val = "";
}

void ARM_iter_propagate_to_operand(std::string defined_value, int index)
{
	if (index == 0)
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value;
	else if (index == 1)
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = defined_value; 
	else if (index == 2)
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = defined_value;
	else if (index == 3)
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand3 = defined_value;
}

void ARM_create_new_tmp_x64_my_instruction(std::string operand, std::string operand1)
{
	struct ARM_my_instruction new_one;
	new_one.operand0 = operand;
	new_one.operand1 = operand1;
	tmp_ARM_my_insn.push_back(new_one);
}

std::string ARM_iter_process_shift_operand(std::string operand, int index)
{
	std::string defined_value2;
	std::string shift_mnem = ARM_extract_shift_mnem(operand);
	std::string tmp1 = ARM_extract_shift_base(operand, shift_mnem);
	std::string defined_value1 = ARM_iter_lookForDefine(tmp1);
	if(defined_value1=="") { warning("error: Strange! Register should have been defined!"); }
	if (index == 1)
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,defined_value1 });//shift base
	else if (index == 2)
		tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp1,defined_value1 });//shift base
	std::string tmp2 = ARM_extract_shift_offset(operand, shift_mnem);
	if (is_ARM_register(tmp2))
	{
		defined_value2 = ARM_iter_lookForDefine(tmp2);
		if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
		if (index == 1)
			tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });//shift offset
		else if (index == 2)
			tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters2.insert({ tmp2,defined_value2 });//shift offset
	}
	else
		defined_value2 = tmp2;
	return "("+defined_value1 + shift_mnem + defined_value2+")";
}

void ARM_iter_LDR_type4_register_offset(std::string operand1)//LDR, reg, [reg {,num}] 
{
	std::string tmp1, defined_value1, tmp;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if(defined_value1=="") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,defined_value1 });
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = "["+tmp+"]";
	ARM_iter_look_for_displ(1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
}
void ARM_iter_LDR_type4_pre_indexed(std::string operand1)// LDR, reg, [reg {,num}]! 
{
	std::string tmp1, defined_value1, tmp;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = "["+tmp+"]";
	ARM_iter_look_for_displ(1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
}

void ARM_iter_LDR_type4_post_indexed(std::string operand1)//LDR, reg, [reg], num   
{
	std::string tmp1, defined_value1, tmp;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = "[" + defined_value1 + "]";
	ARM_iter_look_for_displ(1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
}


void ARM_iter_LDRD_type4_register_offset(std::string operand2)//LDRD, reg, reg, [reg {,num}] 
{
	std::string tmp2, defined_value2, tmp;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }

	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = ARM_translate_LDRD_STRD_second_op(tmp);//update operand1
	ARM_iter_look_for_displ(2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = "[" + tmp + "]";//update operand0
	ARM_iter_look_for_displ(2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,defined_value2 });


}
void ARM_iter_LDRD_type4_pre_indexed(std::string operand2)// LDRD, reg, reg, [reg {,num}]! 
{
	std::string tmp2, defined_value2, tmp;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = ARM_translate_LDRD_STRD_second_op(tmp);//update operand1
	ARM_iter_look_for_displ(2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = "[" + tmp + "]";//update operand0
	ARM_iter_look_for_displ(2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,tmp });
}

void ARM_iter_LDRD_type4_post_indexed(std::string operand2)//LDRD, reg, reg, [reg], num   
{
	std::string tmp2, defined_value2, tmp;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = ARM_translate_LDRD_STRD_second_op(defined_value2);//update operand1
	ARM_iter_look_for_displ(2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;

	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = "[" + defined_value2  + "]";//update operand0
	ARM_iter_look_for_displ(2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;

	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = tmp;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,tmp });
}

void ARM_iter_LDR_type3_register_offset(std::string operand1)  //LDR, reg, [reg, +/-reg {,shift}] 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if(defined_value1=="") { warning("error: Strange! Register should have been defined!"); }
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,defined_value1 });
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_iter_translate_type3_register_offset(operand1, defined_value1, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = "["+tmp+"]";
	ARM_iter_look_for_displ(1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
}

void ARM_iter_LDR_type3_pre_indexed(std::string operand1)  //LDR, reg, [reg, +/-reg {,shift}] !
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_iter_translate_type3_register_offset(operand1, defined_value1, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = "["+tmp+"]";
	ARM_iter_look_for_displ(1);;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
}

void ARM_iter_LDR_type3_post_indexed(std::string operand1) // LDR, reg, [reg], +/-reg {,shift} 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_iter_translate_type3_register_offset(operand1, defined_value1, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = "[" + defined_value1 + "]";
	ARM_iter_look_for_displ(1);;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
}

void ARM_iter_STR_type4_register_offset(std::string operand0, std::string operand1)//STR, reg, [reg {,num}]  
{
	std::string tmp1, defined_value1, tmp, defined_value;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,defined_value1 });
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value;
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = "["+tmp + "]=" + defined_value;
}

void ARM_iter_STR_type4_pre_indexed(std::string operand0, std::string operand1)// STR, reg, [reg {,num}]! 
{
	std::string tmp1, defined_value1, tmp, defined_value;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value;
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = "["+tmp+"]" + "=" + defined_value;
}

void ARM_iter_STR_type4_post_indexed(std::string operand0, std::string operand1) //STR, reg, [reg], num
{
	std::string tmp1, defined_value1, tmp, defined_value;
	defined_value = ARM_iter_lookForDefine(operand0);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value;
	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp = ARM_translate_type4_register_offset(operand1, defined_value1);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = "["+defined_value1+"]" + "=" + defined_value;
}

void ARM_iter_STRD_type4_register_offset(std::string operand0, std::string operand1, std::string operand2)//STRD reg, reg, [reg {,num}]  
{
	std::string tmp2, defined_value2, tmp, defined_value;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,defined_value2 });//update operand2

	defined_value = ARM_iter_lookForDefine(operand1);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = defined_value;//update operand1
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ ARM_translate_LDRD_STRD_second_op(tmp2) ,defined_value });//update operand2 second []

	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = defined_value;//update operand0
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = "[" + tmp + "]=" + defined_value;//update operand2 first []
}

void ARM_iter_STRD_type4_pre_indexed(std::string operand0, std::string operand1, std::string operand2)// STRD reg, reg, [reg num]! 
{
	std::string tmp2, defined_value2, tmp, defined_value;
	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);

	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = defined_value;//update operand0
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,tmp });
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = "[" + tmp + "]" + "=" + defined_value;//update operand2 first []

	defined_value = ARM_iter_lookForDefine(operand1);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = defined_value;//update operand1
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ ARM_translate_LDRD_STRD_second_op(tmp),defined_value });//update operand2 second []
}

void ARM_iter_STRD_type4_post_indexed(std::string operand0, std::string operand1, std::string operand2) //STRD reg, reg, [reg], num
{
	std::string tmp2, defined_value2, tmp, defined_value;

	tmp2 = ARM_extract_bracket_base(operand2);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp = ARM_translate_type4_register_offset(operand2, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ tmp2,tmp });//update operand2

	defined_value = ARM_iter_lookForDefine(operand0);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = defined_value;//update operand1
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters2.insert({ ARM_translate_LDRD_STRD_second_op(defined_value2), defined_value });//update operand2 second []

	defined_value = ARM_iter_lookForDefine(operand0);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand0 = defined_value;//update operand0
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 = "[" + defined_value2 + "]" + "=" + defined_value;//update operand2 first []
}

void ARM_iter_STR_type3_register_offset(std::string operand0, std::string operand1) //STR, reg, [reg, +/-reg {,shift}] 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp = ARM_iter_lookForDefine(operand0);
	if (tmp == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp;

	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,defined_value1 });
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_iter_translate_type3_register_offset(operand1, defined_value1, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = "["+tmp + "]=" + tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0;
}

void ARM_iter_STR_type3_pre_indexed(std::string operand0, std::string operand1) // STR, reg, [reg, +/-reg {,shift}] ! 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp = ARM_iter_lookForDefine(operand0);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp;

	tmp1 = ARM_extract_bracket_base(operand1);
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_iter_translate_type3_register_offset(operand1, defined_value1, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = "["+tmp+"]" + "=" + tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0;
}

void ARM_iter_STR_type3_post_indexed(std::string operand0, std::string operand1)// STR, reg, [reg], +/-reg {,shift} 
{
	std::string tmp1, defined_value1, defined_value2, tmp, tmp2;
	bool minus;
	tmp = ARM_iter_lookForDefine(operand0);
	if (tmp == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = tmp;

	tmp1 = ARM_extract_bracket_base(operand1);
	if (tmp1 == "") { warning("error: Strange! Register should have been defined!"); }
	defined_value1 = ARM_iter_lookForDefine(tmp1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp2 = ARM_extract_bracket_second_register(operand1, minus);
	defined_value2 = ARM_iter_lookForDefine(tmp2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp2,defined_value2 });
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand1 = "["+tmp1+"]" + "=" + tmp;
	if (minus)
		defined_value2 = "-" + defined_value2;
	tmp = ARM_iter_translate_type3_register_offset(operand1, defined_value1, defined_value2);
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ tmp1,tmp });
}

void ARM_iter_process_LDM(std::string operand0, std::string operand1)
{

	std::string defined_value;
	int i;
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value;
	std::vector <std::string> reg_list;
	reg_list = ARM_get_reg_list(operand1);
	for (i = 0;i < reg_list.size();i++)
	{
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ reg_list[i],defined_value + "+" + std::to_string(i * DWORD_LEN) });
	}
	if (ARM_is_pre_indexed(operand0))
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value + "+" + std::to_string(i * DWORD_LEN);
}

void ARM_iter_process_STM(std::string operand0, std::string operand1)
{
	std::string defined_value, defined_value1;
	int i;
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value;
	std::vector <std::string> reg_list;
	reg_list = ARM_get_reg_list(operand1);
	for (i = 0;i < reg_list.size();i++)
	{
		defined_value1 = ARM_iter_lookForDefine(reg_list[i]);
		if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters1.insert({ reg_list[i],defined_value1 });
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].parameters0.insert({ defined_value + "+" + std::to_string(i * DWORD_LEN),defined_value1 });
	}
	if (ARM_is_pre_indexed(operand0))
		tmp_ARM_my_insn[tmp_ARM_my_insn.size()-1].operand0 = defined_value + "+" + std::to_string(i * DWORD_LEN);
}


void ARM_iter_arithmatic_propagate_reg_reg_reg(std::string operand1, std::string operand2, std::string Mnem)
{
	std::string defined_value1, defined_value2;
	defined_value1 = ARM_iter_lookForDefine(operand1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand(defined_value1, 1);
	defined_value2 = ARM_iter_lookForDefine(operand2);
	if (defined_value2 == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand(defined_value2, 2);
	ARM_iter_propagate_to_operand("("+defined_value2 + Mnem + defined_value1+")", 0);
}

void ARM_iter_arithmatic_propagate_reg_reg_shift(std::string operand1, std::string operand2, std::string Mnem)
{
	std::string defined_value1, defined_value2;
	defined_value2 = ARM_iter_process_shift_operand(operand2, 2);
	defined_value1 = ARM_iter_lookForDefine(operand1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand(defined_value1, 1);
	ARM_iter_propagate_to_operand("("+defined_value1 + Mnem + defined_value2+")", 0);
}
void ARM_iter_arithmatic_propagate_reg_reg_num(std::string operand1, std::string operand2, std::string Mnem)
{
	std::string defined_value1;
	defined_value1 = ARM_iter_lookForDefine(operand1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand(defined_value1, 1);
	ARM_iter_propagate_to_operand("("+defined_value1 + Mnem + operand2+")", 0);
}

void ARM_iter_arithmatic_propagate_reg_reg(std::string operand0, std::string operand1,std::string Mnem)
{
	std::string defined_value, defined_value1;
	defined_value1 = ARM_iter_lookForDefine(operand1);
	if (defined_value1 == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand(defined_value1, 1);
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters0.insert({ "original",defined_value });
	ARM_iter_propagate_to_operand("("+defined_value + Mnem + defined_value1+")", 0);
}

void ARM_iter_arithmatic_propagate_reg_shift(std::string operand0, std::string operand1,  std::string Mnem)
{
	std::string defined_value1, defined_value;
	defined_value1 = ARM_iter_process_shift_operand(operand1, 1);
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand("("+defined_value + Mnem + defined_value1+")", 0);
}

void ARM_iter_arithmatic_propagate_reg_num(std::string operand0, std::string operand1, std::string Mnem)
{
	std::string defined_value;
	defined_value = ARM_iter_lookForDefine(operand0);
	if (defined_value == "") { warning("error: Strange! Register should have been defined!"); }
	ARM_iter_propagate_to_operand("("+defined_value + Mnem + operand1+")", 0);
}

std::string ARM_iter_translate_type3_register_offset(std::string operand, std::string defined_value1, std::string defined_value2)
{
	int last_comma = operand.rfind(',');
	int first_comma = operand.find(',');
	if (last_comma > first_comma)
	{
		operand = ARM_translate_shift(operand);
		std::string shift_mnem = ARM_extract_shift_mnem(operand);
		std::string tmp2 = ARM_extract_shift_offset(operand, shift_mnem);
		if (is_ARM_register(tmp2))
		{
			std::string tmp = ARM_iter_lookForDefine(tmp2);
			if (tmp == "") { warning("error: Strange! Register should have been defined!"); }
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].parameters1.insert({ tmp2,tmp });
			if (defined_value2.find('-') != 0)
				return  defined_value1 + "+" + defined_value2 + shift_mnem + "(" + tmp + ")" ;
			else if (defined_value2.find('-') == 0)
				return defined_value1 + defined_value2 + shift_mnem + "(" + tmp + ")" ;
		}
		else
		{
			if (defined_value2.find('-') != 0)
				return defined_value1 + "+" + defined_value2 + shift_mnem + tmp2;
			else if (defined_value2.find('-') == 0)
				return defined_value1 + defined_value2 + shift_mnem + tmp2 ;
		}
	}
	else if (last_comma == first_comma)
		return operand;
}

//In a loop of instructions, find the last instruction in tmp_ARM_insn_record's operand_num th operand's defination in the previous instructions.
void ARM_iter_look_for_displ(int operand_num)
{
	std::string target_to_lookup;
	if (operand_num == 1)//If we need to look up the defination of operand1 in previous instructions in loop.
		target_to_lookup = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1;
	else if(operand_num == 2)//If we need to look up the defination of operand2 in previous instructions in loop.
		target_to_lookup = tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2;
	std::string defination_looked_up = "";
	int equation_index;
	for (int i = tmp_ARM_insn_record.size() - 2;i >= 0;i--) //look for previous define for this disp
	{
		/*if (tmp_ARM_my_insn[i].operand0.find(tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 + "=") == 0)
		{
			equation_index = tmp_ARM_my_insn[i].operand0.find('=');
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 = tmp_ARM_my_insn[i].operand0.substr(equation_index + 1, tmp_ARM_my_insn[i].operand0.size()-1-equation_index);
			return;
		}
		else*/ if (tmp_ARM_my_insn[i].operand1.find(tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 + "=") == 0)
		{
			equation_index = tmp_ARM_my_insn[i].operand1.find('=');
			defination_looked_up ="="+ tmp_ARM_my_insn[i].operand1.substr(equation_index + 1, tmp_ARM_my_insn[i].operand1.size() - 1 - equation_index);
			break;
		}
	}
	std::string disp_content = strip_disp(target_to_lookup);
	if (is_hex_string(disp_content))//look for data section for this disp, if the content in the disp is an address
	{
		ea_t ea1 = stoi(disp_content, 0, 16);
		//qstring buffer;
		//get_strlit_contents(&buffer, ea1, -1, STRTYPE_C);//get the string content
		if (ea1 <= 0)
			return;
		int content = get_32bit(ea1);
		std::string content_string = dec2hex(content);
		if (!content_string.empty())//if we successfully got the content
			defination_looked_up = content_string;
	}
	if (defination_looked_up != "")//If the disp has been defined previously
	{
		if (operand_num == 1)//If we need to look up the defination of operand1 in previous instructions in loop.
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand1 += "="+defination_looked_up;
		else if (operand_num == 2)//If we need to look up the defination of operand2 in previous instructions in loop.
			tmp_ARM_my_insn[tmp_ARM_my_insn.size() - 1].operand2 += "="+defination_looked_up;
	}
}