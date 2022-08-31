#include "../../Headers/cross_arch_preprocessor/ARM_preprocessor.h"

int ARM_findUpdate(ea_t ea, func_t* func)
{
	arm_convert_operand2offset_type(ea);
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	std::string Mnem = Mnemq.c_str();
	if (ea == 0x118e8)
		int breakp = 1;
	int op0_type = 0, op1_type = 0, op2_type = 0, op3_type=0;
	std::string operand0, operand1, operand2, operand3;
	int ea_operand_num = count_ea_operands(ea);
	ARM_unname_all_regs(func);
	if (ea_operand_num == 1)
	{
		operand0 = ARM_get_operand(ea, 0);
		op0_type = get_optype(ea, 0);
		msg("%x operand0=%s, operand0 type=%d \n", ea, operand0, op0_type);
	}
	else if (ea_operand_num == 2)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		msg("%x, operand0=%s, operand0 type=%d \n operand1=%s, operand1_type=%d \n", ea, operand0, op0_type,operand1,op1_type);
	}
	else if (ea_operand_num == 3)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = ARM_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
		msg("%x, operand0=%s, operand0 type=%d \n operand1=%s, operand1_type=%d \n operand2=%s, operand2_type=%d \n", ea, operand0, op0_type, operand1, op1_type, operand2, op2_type);
	}

	else if (ea_operand_num == 4)
	{
		operand0 = ARM_get_operand(ea, 0);
		operand1 = ARM_get_operand(ea, 1);
		op0_type = get_optype(ea, 0);
		op1_type = get_optype(ea, 1);
		operand2 = ARM_get_operand(ea, 2);
		op2_type = get_optype(ea, 2);
		operand3= ARM_get_operand(ea, 3);
		op3_type = get_optype(ea, 3);
		msg("%x, operand0=%s, operand0 type=%d \n operand1=%s, operand1_type=%d \n operand2=%s, operand2_type=%d \n", ea, operand0, op0_type, operand1, op1_type, operand2, op2_type);
	}


	if (Mnem.find('B')==0 && op0_type==1 && Mnem!="BIC" && Mnem!="BFC" && Mnem!="BFI")// B reg
	{
			ARM_subfindupdate(ea, func, operand0,"","", 82/*B reg*/);
		return 0;
	}
	//MOVT reg,num
	if (op0_type == 1 && op1_type == 5 && Mnem.find("MOVT") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 87/*"MOVT reg,num"*/); }

	//MOVW reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MOVW") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 88/*"MOVW reg,num"*/); }

	//MOVW reg,reg  
	else if (op0_type == 1 && op1_type == 1 && Mnem.find("MOVW") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 89/*"MOVW reg,reg"*/); }

	//MOV reg,reg 
	else if (op0_type == 1 && op1_type == 1 && Mnem.find("MOV")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1,"", 0/*"MOV reg,reg"*/); }

	//MOV reg, reg,shift num/reg
	else if (op0_type == 1 && op1_type == 8 && Mnem.find("MOV")!=-1) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1),"", 1/*"MOV reg, reg,shift num/reg"*/); }

	//MOV reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MOV")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0,1,""), "", 2/*"MOV reg,num"*/); }

	//MVN reg,reg
	else if (op0_type == 1 && op1_type == 1 && Mnem.find("MVN")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 3/*MVN reg,reg*/);return 0; }

	//MVN reg, reg, shift num/reg
	else if (op0_type == 1 && op1_type == 8 && Mnem.find("MVN")!=-1) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1), "", 4/*MVN reg, reg, shift num/reg*/);return 0; }

	//MVN reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MVN")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0,1,""), "", 5/*MVN reg,num*/);return 0; }

	//MVT reg,num
	else if (op0_type == 1 && op1_type == 5 && Mnem.find("MVT")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0, 1, ""), "", 6/*MVT reg,num*/);return 0; }
	 
	//LDR, reg, [reg {,num}]       LDR, reg, [reg {,num}]!        LDR, reg, [reg], num   
	else if (op0_type==1 && op1_type==4 && ea_operand_num==2 && Mnem.find("LDR")!=-1){ ARM_subfindupdate(ea, func, operand0, operand1, "", 7/*LDR, reg, [reg {,num}] */);return 0; }

	//LDR, reg, [reg, +/-reg {,shift}]        LDR, reg, [reg, +/-reg {,shift}] !        LDR, reg, [reg], +/-reg {,shift} 
	else if (op0_type == 1 && op1_type == 3 && ea_operand_num==2 && Mnem.find("LDR") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 8/*LDR, reg, [reg, reg, {,shift}] */);return 0; }

	//LDR, reg, label 
	else if (op0_type == 1 && op1_type == 2 && ea_operand_num==2 && Mnem.find("LDR") == 0) { ARM_subfindupdate(ea, func, operand0, operand1, "", 9/*LDR, reg, label */);return 0; }

	//LDRD, reg, reg, label 
	else if (op0_type == 1 && op1_type == 1 && op2_type==2 && Mnem.find("LDRD") ==0) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 10/*LDRD, reg, reg, label  */);return 0; }

	//LDRD, reg, reg, [reg {,num}], LDRD, reg, reg, [reg], num, LDRD, reg, reg, [reg ,num]!  
	else if (op0_type == 1 && op1_type == 1 && op2_type == 4 && Mnem.find("LDRD") == 0) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 96/*LDRD, reg, reg, [reg {,num}]   */);return 0; }

	//ADR, reg, label 
	else if (op0_type == 1 && (op1_type == 2) && Mnem.find("ADR") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 11/*LDR, reg, reg, label  */);return 0; }

	//ADR, reg, num
	else if (op0_type == 1 && (op1_type == 5) && Mnem.find("ADR") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 102/*LDR, reg, reg, num  */);return 0; }

	//ADD PC, table_reg, offset_reg
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && operand0 == "PC" && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 17/*"ADD PC, table_reg, offset_reg*/); }

	//ADD reg, PC, reg
	else if (Mnem.find("ADD") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1 && operand1 == "PC") { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 83/*"ADD reg, PC, reg*/); }

	//STREX, reg, reg, [reg {, shift}]
	else if (op0_type == 1 && op1_type == 1 && op2_type == 4 && Mnem.find("STREX") == 0) { ARM_subfindupdate(ea, func, operand0, operand1,operand2, 84/*STR, reg, reg, [reg {,shift}] */);return 0; }
	//STR, reg, [reg {,num}] 
	else if (op0_type == 1 && op1_type == 4 && ea_operand_num == 2 && Mnem.find("STR") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 12/*STR, reg, [reg {,num}] */);return 0; }

	//STR, reg, [reg, reg {,shift}] 
	else if (op0_type == 1 && op1_type == 3 && ea_operand_num == 2 && Mnem.find("STR") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 13/*STR, reg, [reg, reg, {,shift}]*/);return 0; }

	//STRD reg, reg, [reg {,num}]  STRD reg, reg, [reg ,num]!     STRD reg, reg, [reg],num 
	else if (op0_type == 1 && op1_type == 1 && op2_type==4&& Mnem.find("STRD") != -1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 97/*STRD reg, reg, [reg {,num}]  STRD reg, reg, [reg ,num]!     STRD reg, reg, [reg],num  */);return 0; }

	//LDM reg, {reg-reg}
	else if (op0_type==1 && op1_type==9 && Mnem.find("LDM")!=-1) { ARM_subfindupdate(ea, func, operand0,operand1, "", 14/*LDM reg, {reg-reg}*/);return 0; }

	//STM reg, {reg-reg}
	else if (op0_type == 1 && op1_type == 9 && Mnem.find("STM")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 15/*STM reg, {reg-reg}*/);return 0; }

	//SWP reg, reg, [reg]
	else if (op0_type==1 && op1_type==1 && op2_type==4 && Mnem.find("SWP")!=-1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 16/*SWP reg, reg, [reg]*/);return 0; }


	//TST reg, reg
	else if ((Mnem.find("TST")!=-1||Mnem.find("TEQ")!=-1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0,operand1,"", 18/*"TST reg,reg*/); }

	//TST rax,1
	else if ((Mnem.find("TST")!=-1 || Mnem.find("TEQ") != -1) && op0_type == 1 && op1_type == 5) { ARM_subfindupdate(ea, func, operand0,operand1.replace(0,1,""),"", 19/*"TST reg,num*/); }

	//TST, reg, reg,shift num/reg
	else if ((Mnem.find("TST")!=-1 || Mnem.find("TEQ") != -1) && op0_type == 1 && op1_type == 8) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1),"", 20/*"TST reg, reg,shift num/reg*/); }

	//SEL reg, reg, reg
	//else if (Mnem.find("SEL")!=-1 && op0_type == 1 && op1_type == 1 && op2_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, ?/*"test [],reg*/); }

	//CMP reg,reg
	else if ((Mnem.find("CMP")!=-1||Mnem.find("CMN")!=-1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "",  18/*"CMP reg,reg*/); }

	//CMP reg,num
	else if ((Mnem.find("CMP")!=-1 || Mnem.find("CMN") != -1) && op0_type == 1 && op1_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0,1,""), "", 19/*"CMP reg,num*/); }

	//CMP reg, reg,shift num/reg
	else if ((Mnem.find("CMP")!=-1 || Mnem.find("CMN") != -1) && op0_type == 1 && op1_type == 8) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1), "", 20/*"CMP reg, reg,shift num*/); }

	//ADD reg, reg, reg
	else if ((Mnem.find("ADD") != -1|| Mnem.find("ADC") != -1) && op0_type == 1 && operand0!="PC" && op1_type == 1 && op2_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 21/*"ADD reg, reg, reg*/); }

	//ADD reg, reg, reg,shift num/reg
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2),  22/*"ADD reg, reg, reg,shift num*/); }

	//ADD reg, reg, num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 1 && op2_type==5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 23/*"ADD reg, reg, num*/); }

	//ADD reg, reg
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 24/*"ADD reg, reg*/); }

	//ADD reg, reg,shift num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 8) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1), "", 25/*"ADD reg, reg,shift num*/); }

	//ADD reg, num
	else if ((Mnem.find("ADD") != -1 || Mnem.find("ADC") != -1) && op0_type == 1 && op1_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0,1,""), "", 26/*"ADD reg, num*/); }


	//SUB reg, reg, reg
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 27/*"SUB reg, reg, reg*/); }

	//SUB reg, reg, reg,shift num/reg
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 28/*"SUB reg, reg, reg,shift num*/); }

	//SUB reg, reg, num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1 && op2_type==5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 29/*"SUB reg, reg, num*/); }

	//SUB reg, reg
	else if ((Mnem.find("SUB")!=-1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 30/*"SUB reg, reg*/); }

	//SUB reg, reg,shift num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 8) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1), "", 31/*"SUB reg, reg,shift num*/); }

	//SUB reg, num
	else if ((Mnem.find("SUB") != -1 || Mnem.find("SBC") != -1) && op0_type == 1 && op1_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0, 1, ""), "", 32/*"SUB reg, num*/); }

	//RSB reg, reg, reg
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 33/*"RSB reg, reg, reg*/); }

	//RSB reg, reg, reg,shift num/reg
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 34/*"RSB reg, reg, reg,shift num*/); }

	//RSB reg, reg, num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 35/*"RSB reg, reg, num*/); }

	//RSB reg, reg
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 36/*"RSB reg, reg*/); }

	//RSB reg, reg,shift num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 8) { ARM_subfindupdate(ea, func, operand0, ARM_translate_shift(operand1), "", 37/*"RSB reg, reg,shift num*/); }

	//RSB reg, num
	else if ((Mnem.find("RSB") != -1 || Mnem.find("RSC") != -1) && op0_type == 1 && op1_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1.replace(0, 1, ""), "", 38/*"RSB reg, num*/); }

	//AND reg, reg, reg
	else if (Mnem.find("AND") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 39/*"AND reg, reg, reg*/); }

	//AND reg, reg, num
	else if (Mnem.find("AND") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 40/*"AND reg, reg, num*/); }

	//AND reg, reg, reg,shift num/reg
	else if (Mnem.find("AND") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 41/*"AND reg, reg, reg,shift num*/); }

	//ORR reg, reg, reg
	else if (Mnem.find("ORR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 42/*"ORR reg, reg, reg*/); }

	//ORR reg, reg, num
	else if (Mnem.find("ORR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 43/*"ORR reg, reg, num*/); }

	//ORR reg, reg, reg,shift num/reg
	else if (Mnem.find("ORR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 44/*"ORR reg, reg, reg,shift num/reg*/); }

	//EOR reg, reg, reg
	else if (Mnem.find("EOR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 45/*"EOR reg, reg, reg*/); }

	//EOR reg, reg, num
	else if (Mnem.find("EOR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 46/*"EOR reg, reg, num*/); }

	//EOR reg, reg, reg,shift num/reg
	else if (Mnem.find("EOR") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 47/*"EOR reg, reg, reg,shift num*/); }

	//BIC reg, reg, reg
	else if (Mnem.find("BIC") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 48/*"BIC reg, reg, reg*/); }

	//BIC reg, reg, num
	else if (Mnem.find("BIC") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 49/*"BIC reg, reg, num*/); }

	//BIC reg, reg, reg,shift num/reg
	else if (Mnem.find("BIC") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 50/*"BIC reg, reg, reg,shift num*/); }

	//ORN reg, reg, reg
	else if (Mnem.find("ORN") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 51/*"ORN reg, reg, reg*/); }

	//ORN reg, reg, num
	else if (Mnem.find("ORN") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 52/*"ORN reg, reg, num*/); }

	//ORN reg, reg, reg,shift num
	else if (Mnem.find("ORN") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 53/*"ORN reg, reg, reg,shift num*/); }

	//RBIT reg, reg
	else if ( Mnem.find("RBIT") != -1 && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 93/*RBIT reg, reg*/); }

	//REV16 reg, reg
	else if ((Mnem.find("REV16") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 94/*REV16 reg, reg*/); }

	//REVSH reg, reg
	else if ((Mnem.find("REVSH") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 95/*REVSH reg, reg*/); }

	//REV reg, reg
	else if ((Mnem.find("REV") != -1 ) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 54/*REV reg, reg*/); }

	//ASR reg, reg, reg
	else if ((Mnem.find("ASR") != -1 || Mnem.find("LSR") != -1) && op0_type == 1 && op1_type == 1 && op2_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 55/*"ASR reg, reg, reg,shift num*/); }

	//ASR reg, reg, num
	else if ((Mnem.find("ASR") != -1 || Mnem.find("LSR") != -1 ) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 56/*"ASR reg, reg, reg,shift num*/); }

	//LSL reg, reg, reg
	else if ((Mnem.find("LSL") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 57/*"LSL reg, reg, reg,shift num*/); }

	//LSL reg, reg, num
	else if ((Mnem.find("LSL") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 58/*"LSL reg, reg, reg,shift num*/); }

	//RRX reg, reg, reg
	else if ((Mnem.find("RRX") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 59/*"RRX reg, reg, reg,shift num*/); }

	//RRX reg, reg, num
	else if ((Mnem.find("RRX") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 60/*"RRX reg, reg, reg,shift num*/); }

	//MUL  reg,reg
	else if (Mnem.find("MUL")==0 && op0_type == 1 && op1_type == 1 && ea_operand_num == 2) { ARM_subfindupdate(ea, func, operand0, operand1, "", 61/*"MUL reg,reg*/); }

	//MUL  reg,reg, reg
	else if (Mnem.find("MUL") == 0 && op0_type == 1 && op1_type == 1 && op2_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 62/*"MUL reg,reg, reg*/); }

	//MLA reg, reg, reg, reg
	else if (Mnem.find("MLA")==0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 63/*"MLA reg, reg, reg, reg*/); }

	//MLS reg, reg, reg, reg
	else if (Mnem.find("MLS") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 64/*"MLS reg, reg, reg, reg*/); }

	//UMULL reg, reg, reg, reg
	else if ((Mnem.find("UMULL") == 0 || Mnem.find("SMULL") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 65/*"UMULL reg, reg, reg, reg*/); }

	//UMLAL reg, reg, reg, reg
	else if ((Mnem.find("UMLAL") == 0 || Mnem.find("SMLAL") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 66/*"UMLAL reg, reg, reg, reg*/); }

	//SMULxy reg,reg,reg
	else if ((Mnem.find("SMULT")==0||Mnem.find("SMULB")==0) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 67/*"SMULxy reg,reg,reg*/); }

	//SMLAxy reg, reg, reg, reg
	else if ((Mnem.find("SMLAT") == 0 || Mnem.find("SMLAB") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 68/*"SMLAxy reg, reg, reg, reg*/); }

	//SMULWy reg, reg, reg
	else if (Mnem.find("SMULW") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 69/*"SMULWy reg, reg, reg*/); }

	//SMLAWy reg, reg, reg, reg
	else if (Mnem.find("SMLAW") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 70/*"SMLAWy reg, reg, reg, reg*/); }

	//SMLALxy reg, reg, reg, reg
	else if ((Mnem.find("SMLALT") == 0||Mnem.find("SMLALB") == 0) && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 71/*"SMLALxy reg, reg, reg, reg*/); }

	//SMUAD reg, reg, reg
	else if (Mnem.find("SMUAD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 72/*"SMUAD reg, reg, reg*/); }

	//SMUSD reg, reg, reg
	else if (Mnem.find("SMUSD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 73/*"SMUSD reg, reg, reg*/); }

	//SMMUL reg, reg, reg
	else if (Mnem.find("SMMUL") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 74/*"SMMUL reg, reg, reg*/); }

	//SMMLA reg, reg, reg, reg
	else if (Mnem.find("SMMLA") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 75/*"SMMLA reg, reg, reg, reg*/); }

	//SMMLS reg, reg, reg, reg
	else if (Mnem.find("SMMLS") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 76/*"SMMLS reg, reg, reg, reg*/); }

	//SMLAD reg, reg, reg, reg
	else if (Mnem.find("SMLAD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 77/*"SMLAD reg, reg, reg, reg*/); }

	//SMLSD reg, reg, reg, reg
	else if (Mnem.find("SMLSD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 78/*"SMLSD reg, reg, reg, reg*/); }

	//SMLALD reg, reg, reg, reg
	else if (Mnem.find("SMLALD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 79/*"SMLALD reg, reg, reg, reg*/); }

	//SMLSLD reg, reg, reg, reg
	else if (Mnem.find("SMLSLD") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 80/*"SMLSLD reg, reg, reg, reg*/); }

	//UMAAL reg, reg, reg, reg
	else if (Mnem.find("UMAAL") == 0 && op0_type == 1 && op1_type == 1 && op2_type == 1 && op3_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, operand2, 81/*"SMLSLD reg, reg, reg, reg*/); }
	
	//ROR reg, reg, reg
	else if ( (Mnem.find("ROR") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 85/*"ROR reg, reg, reg,reg*/); }

	//ROR reg, reg, num
	else if ((Mnem.find("ROR") != -1) && op0_type == 1 && op1_type == 1 && op2_type == 5) { ARM_subfindupdate(ea, func, operand0, operand1, ARM_translate_shift(operand2), 86/*"ROR reg, reg, reg,shift num*/); }

	//CLZ reg, reg
	else if ((Mnem.find("CLZ") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 98/*"CLZ reg, reg*/); }

	//CTZ reg, reg
	else if ((Mnem.find("CTZ") != -1) && op0_type == 1 && op1_type == 1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 101/*"CTZ reg, reg*/); }

	//UXT reg, reg
	else if (Mnem.find("UXT") != -1 && op0_type==1 && op1_type==1) { ARM_subfindupdate(ea, func, operand0, operand1, "", 99/*UXT reg, reg*/); }

	//UXT reg, reg, ror #8/#16/#24
	else if (Mnem.find("UXT") != -1 && op0_type == 1 && op1_type == 8) { ARM_subfindupdate(ea, func, operand0, operand1, "", 100/*UXT reg, reg*/); }

	//unknown Mnem reg, reg
	else if (op0_type == 1 && op1_type == 1 && ea_operand_num){ARM_subfindupdate(ea, func, operand0, operand1, "", 90);}

	//unknown Mnem reg, num
	else if (op0_type == 1 && op1_type == 5 && ea_operand_num) { ARM_subfindupdate(ea, func, operand0, operand1, "", 91); }

	//unknown Mnem reg, reg,shift
	else if (op0_type == 1 && op1_type == 8 && ea_operand_num) { ARM_subfindupdate(ea, func, operand0, operand1, "", 92); }
	return 0;
}

void ARM_random_infer_this_insn_propagate_next(func_t* func, ea_t ea)
{
	if (ea == 0x9a5e8)
		int bp = 1;
	/*if (ARM_is_pop_insn(ea))
	{
		//init_IR_reserve_insns(func);
		//translate_loop_insns(ea,func); 
		//init_ARM_my_insn_IR(func);
		//ARM_translate_return_value(ea, func);
		//ARM_translate_each_insn(func);
		//ARM_print_to_file(ea, func);
		//print_path(ea,func);
		return;
	}*/
	ARM_clear_ARM_my_insn(ea);
	if (ARM_is_add_pc_insn(ea))//If the instruction is like ADD PC, PC, .... This means after this instruction there might be many many branches (more than two)
	{
		if (ARM_Mnem_not_support(ea))//If we found the instruction not calculatable, quit.
		{
			add_uncalculatable_function(ea);
			return;
		}
		ARM_findUpdate(ea, func);//Calculate symbolic value for this instruction ea
		if (ARM_is_symbolic_value_explosion(ea))//If we found the instruction not calculatable, quit.
		{
			add_uncalculatable_function(ea);
			return;
		}
		std::vector <ea_t> next_eas;
		ea_t next_ea;
		next_ea = get_first_cref_from(ea);
		if (!ARM_is_code_ea(next_ea))
			next_ea = -1;
		while (next_ea != -1)//Get a list of branching instructions following instruction ADD PC, PC, ...
		{
			next_eas.push_back(next_ea);
			next_ea= get_next_cref_from(ea, next_ea);
			if (!ARM_is_code_ea(next_ea))
				next_ea = -1;
		}
		for (int i = 0;i < next_eas.size();i++)//For each branch
		{
			if (next_eas[i] != -1 && next_eas[i] != BADADDR && next_eas[i] >= func->start_ea && next_eas[i] <= func->end_ea)//Go to next ea
			{

				if (insn_has_not_been_touched(next_eas[i], func))
				{
					insn_last_insn[next_eas[i]] = ea;
					ARM_random_infer_this_insn_propagate_next(func, next_eas[i]);
				}

			}
		}
	}
	else if (ARM_is_conditional_insn(ea))
	{
		if (insn_has_not_been_touched(ea, func))
		{
			ARM_infer_conditional_block(ea, func);
		}
	}
	else {
		ea_t next_ea, next_ea1;
		if (ARM_Mnem_not_support(ea))//If we found the instruction not calculatable, quit.
		{
			add_uncalculatable_function(ea);
			return;
		}
		ARM_findUpdate(ea, func);//Calculate symbolic value for this instruction ea
		if (ARM_is_symbolic_value_explosion(ea))//If we found the instruction not calculatable, quit.
		{
			add_uncalculatable_function(ea);
			return;
		}
		//ARM_translate_one_insn(ea, func);
		next_ea = get_first_cref_from(ea);
		next_ea1 = get_next_cref_from(ea, next_ea);
		if (next_ea1 > func->end_ea || next_ea1 < func->start_ea)
			next_ea1 = -1;
		if (next_ea != -1 && next_ea1 != -1)
			random_swap(next_ea, next_ea1);
		put_loop_first(next_ea, next_ea1, ea, func);
		if (next_ea != -1 && is_in_loop(ea, next_ea, func))//If next_ea and ea forms a loop, we need to recalculate for this whole loop.
		{

			//ARM_recalculate_loop(ea, next_ea, func);
			if (insn_not_recalculate_yet(next_ea))
			{
				ARM_recalculate_for_while_v1(ea, next_ea, func);
				recalculated_yet_map.insert({ next_ea ,1 });
			}
			//ARM_recalculate_for_while(ea, next_ea, func);
			//ARM_process_loop(ea, next_ea, func);
			next_ea = -1;
		}

		if (next_ea1 != -1 && is_in_loop(ea, next_ea1, func))//If next_ea1 and ea forms a loop, we need to recalculate for this whole loop.
		{

			//ARM_recalculate_loop(ea, next_ea, func);
			if (insn_not_recalculate_yet(next_ea1))
			{
				ARM_recalculate_for_while_v1(ea, next_ea1, func);
				recalculated_yet_map.insert({ next_ea1 ,1 });
			}
			//ARM_recalculate_for_while(ea, next_ea1, func);
			//ARM_process_loop(ea, next_ea, func);
			next_ea1 = -1;

		}


		if (next_ea != -1 && next_ea != BADADDR && next_ea >= func->start_ea && next_ea <= func->end_ea)//Go to next ea
		{

			if (insn_has_not_been_touched(next_ea, func) && next_ea!=ea)//if next ea has never been touched. Also, if next ea points to ea itself, we should not continue execute.
			{
				insn_last_insn[next_ea] = ea;
				ARM_random_infer_this_insn_propagate_next(func, next_ea);
			}

		}
		if (next_ea1 != -1 && next_ea1 >= func->start_ea && next_ea1 <= func->end_ea)//Go to next ea
		{

			if (insn_has_not_been_touched(next_ea1, func) && next_ea1 != ea)//if next ea has never been touched. Also, if next ea points to ea itself, we should not continue execute.
			{
				insn_last_insn[next_ea1] = ea;
				ARM_random_infer_this_insn_propagate_next(func, next_ea1);
			}
		}
	}
	
}

//Parameter 1 ea should be the leading conditional instruction. We need to find the rest of the conditional instructions
//within this block (i.e., before jump or next flag-setting instruction). We should tailor the flags as per the flags used
//in this block (i.e., if only N used, we only set N=0/1, if N and V used, we set N=0/1 and V=0/1).
void ARM_infer_conditional_block(ea_t ea,func_t *func)
{
	if (ea == 0x1f18)
		int breakp = 0;
	ea_t block_end;
	ea_t next_ea;
	ea_t tmp;
	std::vector<ea_t> instructions;
	std::vector<char> flags_set;
	block_end = ARM_find_conditional_block_end(ea,func);//Firstly find the ending of this conditional block. i.e., the leading instruction of next instruction
	flags_set = ARM_extract_flags_used_in_block(ea, block_end);//Check which flags are used in the conditional block.
	std::vector <std::map <char, int>> flag_combination;
	flag_combination = ARM_combine_flags(flags_set);//Combine possible flags.
	int random = rand() % flag_combination.size();
	//Select one possible flag combination, we propagate symbolic value within this conditional block.
	//if(index!=0)//We do the cleaning only from the second time
	//ARM_iterate_clean_ARM_my_insn(ea, func);
	ARM_infer_conditional_block_with_one_possibility(ea, block_end, flag_combination[random], func);
	next_ea = block_end;
	for (tmp = ea;tmp < block_end;tmp = get_first_cref_from(tmp))//Get the conditional blocks in forward order
	{
		instructions.push_back(tmp);
	}
	if (insn_has_not_been_touched(next_ea, func))//For the last insn of the block, we infer it only if it has not been inffered before.
	{
		insn_last_insn[next_ea] = instructions[instructions.size() - 1];
		ARM_random_infer_this_insn_propagate_next(func, next_ea);
	}

	
	
}

ea_t ARM_find_conditional_block_end(ea_t ea,func_t *func)
{
	qstring Mnemq;
	std::string Mnem;
	ea= get_first_cref_from(ea);
	for (ea_t index = ea;index < func->end_ea;index= get_first_cref_from(index))
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		if(Mnem.find("CMP")!=-1|| Mnem.find("CMN") != -1|| Mnem.find("TST") != -1|| Mnem.find("TEQ") != -1\
			|| Mnem.find("SUBS") != -1|| Mnem.find("ADDS") != -1||Mnem.find("ANDS") != -1|| Mnem.find("EORS") != -1\
			||(Mnem.find('B')==0&&Mnem.find("BIC")==-1))
		{
			return index;
		}
	}
	return func->end_ea;
}

//Detect which flag are used within a conditional block. Flags can be N,Z,C,V.
//Parameter 1: The first conditional instruction.
//Parameter 2: The first instruction outside this conditional block.
std::vector<char> ARM_extract_flags_used_in_block(ea_t block_start, ea_t block_end)
{
	std::vector<char> flags_used;
	qstring Mnemq;
	std::string Mnem;
	if (block_start == 0x1f10)
		int breakp = 1;
	for (ea_t index = block_start;index < block_end;index= get_first_cref_from(index))
	{
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		if (Mnem.find("EQ") != -1 || Mnem.find("NE") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'Z') == flags_used.end())
				flags_used.push_back('Z');
		}
		else if (Mnem.find("CS") != -1 || Mnem.find("HS") != -1 || Mnem.find("CC") != -1 || Mnem.find("LO") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'C') == flags_used.end())
				flags_used.push_back('C');
		}
		else if (Mnem.find("MI") != -1 || Mnem.find("PL") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'N') == flags_used.end())
				flags_used.push_back('N');
		}
		else if (Mnem.find("VS") != -1 || Mnem.find("VC") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'V') == flags_used.end())
				flags_used.push_back('V');
		}
		else if (Mnem.find("HI") != -1 || Mnem.find("LS") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'C') == flags_used.end())
				flags_used.push_back('C');
			if (std::find(flags_used.begin(), flags_used.end(), 'Z') == flags_used.end())
			flags_used.push_back('Z');
		}
		else if (Mnem.find("GE") != -1 || Mnem.find("LT") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'N') == flags_used.end())
				flags_used.push_back('N');
			if (std::find(flags_used.begin(), flags_used.end(), 'V') == flags_used.end())
				flags_used.push_back('V');
		}
		else if (Mnem.find("GT") != -1 || Mnem.find("LE") != -1)
		{
			if (std::find(flags_used.begin(), flags_used.end(), 'Z') == flags_used.end())
				flags_used.push_back('Z');
			if (std::find(flags_used.begin(), flags_used.end(), 'N') == flags_used.end())
			flags_used.push_back('N');
			if (std::find(flags_used.begin(), flags_used.end(), 'V') == flags_used.end())
			flags_used.push_back('V');
		}
	}
	return flags_used;
}

//Given a flags_set e.g. "N","V", returns all possible conbinations for all flags.
std::vector <std::map <char, int>> ARM_combine_flags(std::vector<char> flags_set)
{
	std::map<char, int> tmp;
	std::vector <std::map <char, int>> flags_combinations;
	std::vector <std::map <char, int>> new_flags_combinations;
	int already_combinations_num;
	flags_combinations.push_back({ {flags_set[0],0} });
	flags_combinations.push_back({ {flags_set[0],1} });
	for (int index = 1;index < flags_set.size();index++)//For each character in flags_set, i.e., "N", "Z"
	{
		new_flags_combinations.clear();
		already_combinations_num = flags_combinations.size();
		for (int index1 = 0;index1 < already_combinations_num;index1++)//For each already combination of flags
		{
			tmp=flags_combinations[index1];
			tmp.insert({ flags_set[index],0 });
			new_flags_combinations.push_back(tmp);
			tmp = flags_combinations[index1];
			tmp.insert({ flags_set[index],1 });
			new_flags_combinations.push_back(tmp);
		}
		flags_combinations = new_flags_combinations;
	}
	return flags_combinations;
}

//For each possible flag combination, we propagate this combination within a conditional block.
//Parameter 1: first conditional instruction.
//Parameter 2: first instruction outside of this conditional block.
//Parameter 3: one possible flags combinations.
void ARM_infer_conditional_block_with_one_possibility(ea_t block_start, ea_t block_end, std::map <char, int> flag_combination,func_t * func)
{
	qstring Mnemq;
	std::string Mnem;
	ea_t last_ea=block_start;
	last_ea= get_first_cref_from(block_start);
	for (ea_t index = block_start;index < block_end;index= get_first_cref_from(index))
	{
		if (!insn_has_not_been_touched(index, func))//If instruction has been infered by some other branches, we dont infer it and the remanent of the conditional block
			break;
		if(index!= block_start)
			insn_last_insn[index] = last_ea;
		last_ea = index;
		print_insn_mnem(&Mnemq, index);
		Mnem = Mnemq.c_str();
		if (!ARM_is_conditional_insn(index))//None-conditional instruction
			ARM_findUpdate(index, func);
		else if (ARM_flag_satisfy_condition(flag_combination, Mnem))//Flag satisfy condition, then execute.
			ARM_findUpdate(index, func);
		else//Flag not satisfy condition, then simply propagate their values.
			ARM_propagate_insn_value(index, func);
		ARM_translate_one_insn(index, func);
	}
}

bool ARM_flag_satisfy_condition(std::map <char, int> flag_combination, std::string Mnem)
{
	if (Mnem.find("EQ") != -1)//Z=1
	{
		if (flag_combination['Z'] == 1)
			return true;
		else if (flag_combination['Z'] == 0)
			return false;
	}
	else if (Mnem.find("NE") != -1)//Z=0
	{
		if (flag_combination['Z'] == 0)
			return true;
		else if (flag_combination['Z'] == 1)
			return false;
	}
	else if (Mnem.find("CS") != -1 || Mnem.find("HS") != -1)//C=1
	{
		if (flag_combination['C'] == 1)
			return true;
		else if (flag_combination['C'] == 0)
			return false;
	}
	else if (Mnem.find("CC") != -1 || Mnem.find("LO") != -1)//C=0
	{
		if (flag_combination['C'] == 0)
			return true;
		else if (flag_combination['C'] == 1)
			return false;
	}
	else if (Mnem.find("MI") != -1)//N=1
	{
		if (flag_combination['N'] == 1)
			return true;
		else if (flag_combination['N'] == 0)
			return false;
	}
	else if (Mnem.find("PL") != -1)//N=0
	{
		if (flag_combination['N'] == 0)
			return true;
		else if (flag_combination['N'] == 1)
			return false;
	}
	else if (Mnem.find("VS") != -1)//V=1
	{
		if (flag_combination['V'] == 1)
			return true;
		else if (flag_combination['V'] == 0)
			return false;
	}
	else if (Mnem.find("VC") != -1)//V=0
	{
		if (flag_combination['V'] == 0)
			return true;
		else if (flag_combination['V'] == 1)
			return false;
	}
	else if (Mnem.find("HI") != -1)//C=1,Z=0
	{
		if (flag_combination['C'] == 1 && flag_combination['Z'] == 0)
			return true;
		else 
			return false;
	}
	else if (Mnem.find("LS") != -1)//C=0,Z=1
	{
		if (flag_combination['C'] == 0 && flag_combination['Z'] == 1)
			return true;
		else
			return false;
	}
	else if (Mnem.find("GE") != -1)//N=V
	{
		if (flag_combination['N'] ==flag_combination['V'])
			return true;
		else
			return false;
	}
	else if (Mnem.find("LT") != -1)//N!=V
	{
		if (flag_combination['N'] != flag_combination['V'])
			return true;
		else
			return false;
	}
	else if (Mnem.find("GT") != -1)//Z=1, N=V
	{
		if (flag_combination['N'] ==1 && flag_combination['N'] == flag_combination['V'])
			return true;
		else
			return false;
	}
	else if (Mnem.find("LE") != -1)//Z=0, N!=V differ
	{
		if (!(flag_combination['N'] == 0 && flag_combination['N'] != flag_combination['V']))
			return true;
		else
			return false;
	}
}

void ARM_iterate_clean_ARM_my_insn(ea_t ea, func_t* func)
{
	//Iterate until we reach the last instruction executed im this thread
	//Double insurance in case when the execution propagate to the last instruction and this instruction is not pop (thus has value)
	if (insn_last_insn[ea] == 0 || ea == func->end_ea)
		return;
	std::vector <ea_t> childre_list = find_first_child_of(ea);
	ARM_my_insn[ea2ARM_my_insn[ea]].operand0 = "";
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters0.clear();
	ARM_my_insn[ea2ARM_my_insn[ea]].operand1 = "";
	ARM_my_insn[ea2ARM_my_insn[ea]].parameters1.clear();
	insn_last_insn[ea] = 0;
	for (int index = 0;index < childre_list.size();index++)
	{
		ARM_iterate_clean_ARM_my_insn(childre_list[index], func);
	}
}

//We need to record for each conditional jump, the two destination and their relation ship with the flags.
void ARM_analyze_conditional_jump(func_t* func)
{
	qstring Mnemq;
	std::string Mnem;
	qstring disasm;
	ea_t next_ea, far_ea;
	ea_t last_cmp_IR, next_key_IR, next_key_IR1;
	std::string disasm_str;
	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find('B') == 0 && ARM_contains_conditional_compare(ea))//If the instruction is a conditional jump instruction.
		{
			int loc_position;
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasm_str = disasm.c_str();
			if (disasm_str.find("loc_") != -1)
			{
				loc_position = disasm_str.find("loc_");
				far_ea = stoi(disasm_str.substr(loc_position + 4, disasm_str.length() - 1 - loc_position - 3), 0, 16);
			}
			else if (disasm_str.find("locret_") != -1)
			{
				loc_position = disasm_str.find("locret_");
				far_ea = stoi(disasm_str.substr(loc_position + 7, disasm_str.length() - 1 - loc_position - 6), 0, 16);
			}
			next_ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT);
			if (ea == 0x21b4)
				int breakp = 0;
			last_cmp_IR = ARM_find_backward4cmp(ea, func);
			next_key_IR = ARM_find_forward4key_IR(next_ea, func);
			next_key_IR1 = ARM_find_forward4key_IR(far_ea, func);
			ARM_generate_conditional_jump_map4between_insns(last_cmp_IR, ea,next_key_IR, next_key_IR1, Mnem);
			ARM_generate_conditional_jump_map(last_cmp_IR, next_key_IR, next_key_IR1, Mnem);
		}
		else if (ARM_is_conditional_insn(ea))//Instruction is like MOVEEQ, MOVNE but not like BNE
		{
			//The CMP-->MOVEQ flags should be recorded at runtime.
		}
	}
}

void ARM_generate_conditional_jump_map(ea_t ea, ea_t next_ea, ea_t far_ea, std::string Mnem)
{
	std::string key;
	char address1 [10], address2 [10], address3[10];
	if (Mnem == "BEQ")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1) + "-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==1" });
		key = std::string(address1) + "-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==0" });
	}
	else if (Mnem == "BNE")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==1" });
	}
	else if (Mnem == "BCS"||Mnem=="BHS")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==0" });
	}
	else if (Mnem == "BCC" || Mnem == "BLO")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==1" });
	}	
	else if (Mnem == "BMI")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N==0" });
	}
	else if (Mnem == "BPL")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N==1" });
	}
	else if (Mnem == "BVS")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"V==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"V==0" });
	}
	else if (Mnem == "BVC")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"V==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"V==1" });
	}
	else if (Mnem == "BHI")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==1 & Z==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==0 | Z==1" });
	}
	else if (Mnem == "BLS")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==0 | Z==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==1 & Z==0" });
	}
	else if (Mnem == "BGE")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N==V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N!=V" });
	}
	else if (Mnem == "BLT")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N!=V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N==V" });
	}
	else if (Mnem == "BGT")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==0 & N==V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==1 | N!=V" });
	}
	else if (Mnem == "BLE")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==1 & N!=V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==0 | N==V" });
	}

}

//There are some situations like this:
//										CMP rax,1
//										STR rax,[]
//										BNE ...
//In this situation, except connecting CMP and two key IR after BNE, we also need to connect the instructions in betwwen to 
//two key IR after BNE.
//Paramteter1: cmp address
//Parameter2: BNE address
//Parameter3: direct following address after BNE
//Parameter4: address pointed by BNE
//Parameter5: Mnem of jump address
void ARM_generate_conditional_jump_map4between_insns(ea_t last_cmp, ea_t jump_ea,ea_t next_IR, ea_t far_IR, std::string Mnem)
{
	for (ea_t index = get_first_cref_from(last_cmp);index < jump_ea && index != BADADDR; index = get_first_cref_from(index))
	{
		ARM_generate_conditional_jump_map(index, next_IR, far_IR, Mnem);
	}
}