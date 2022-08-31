#include "../../Headers/cross_arch_preprocessor/x64_preprocessor.h"
std::map <std::string, int> x64_Mnem2index = {
	{"call []",48},{"call reg",49},{"call label",146}, {"push reg",5},{"push []",147}, {"pop reg",6}, {"mov reg,reg",0},{"mov reg,label",97},{"mov reg,[]",1},{"mov reg,num",4},
	{"mov [],num",2},{"mov [],reg",3},{"lea reg,[]",7},{"lea reg,label",8},{"test reg,reg",9},{"test reg,num",10},{"test reg,label",10},{"test [],num",11},{"test [],label",11},
	{"test [],reg",12},{"test reg,[]",53},{"xor reg,reg",56},{"xor reg,num",57},{"xor reg,label",115},{"xor [],num",58},{"xor [],label",116},{"xor reg,[]",59},{"xor [],reg",96},
	{"cmp reg,reg",9},{"cmp reg,num",10},{"cmp [],num",11},{"cmp [],reg",12},{"cmp reg,[]",53},{"cmp reg,label",10},{"cmp [],label",11},{"add reg,reg",14},
	{"add reg,[]",15},{"add reg,num",16},{"add reg,label",117},{"add [],reg",17},{"add [],num",18},{"add [],label",118},{"sub reg,reg",19},{"sub reg,[]",20},
	{"sub reg,num",21},{"sub reg,label",119},
	{"sub [],reg",22},{"sub [],num",23},{"sub [],label",120},{"imul reg,reg",24},{"imul reg,[]",25},{"imul reg,reg,num",26},{"imul reg,[],num",27},{"imul reg,label,num",148},
	{"mul reg",31},{"mul label",149},
	{"imul reg",31} ,{"mul []",32},{"imul []",32},{"div reg,reg",29},{"idiv reg,reg",29},{"div reg,[]",30},{"idiv reg,[]",30},{"div reg,label",145},{"idiv reg,label",145} ,
	{"rol reg,num",34},{"rol reg,label",121},{"rol reg,reg",104},
	{"rol [],num",35},{"rol [],label",122},{"rol [],reg",98},{"ror reg,num",36},{"ror reg,label",123},{"ror [],num",37},{"ror [],label",124},{"ror [],reg",99},
	{"ror reg,reg",105},{"shl reg,num",60},{"shl reg,label",125},{"shl reg,reg",106},{"shl [],num",61},{"shl [],label",126},{"shl [],reg",100},
	{"sal reg,num",60},{"sal reg,label",125},{"sal reg,reg",106},{"sal [],num",61},{"sal [],label",126},{"sal [],reg",100}, {"shr reg,num",62},
	{"shr reg,label",127},{"shr reg,reg",107},{"shr [],num",63},{"shr [],label",128},{"shr [],reg",101},{"sar reg,num",62},
	{"sar reg,label",127},{"sar reg,reg",107},{"sar [],num",63},{"sar [],label",128},{"sar [],reg",101},
	{"and reg,reg",38},{"and reg,[]",39},{"and reg,num",40},
	{"and reg,label",129},{"and [],reg",41},{"and [],num",42},{"and [],label",130},{"or reg,reg",43},{"or reg,[]",44},{"or reg,num",45},{"or reg,label",131},
	{"or [],reg",46},{"or [],num",47},{"or [],label",132},{"punpck reg,reg",50},{"inc reg",51},{"inc []",108},{"dec reg",52},{"dec []",109},{"not reg",54},
	{"not []",110},{"neg reg",55},{"neg []",111},{"set reg",64},{"set []",103},{"cmov reg,label",133},{"cmov reg,reg",65},{"cmov reg,[]",66},{"sbb reg,reg",67},
	{"sbb reg,[]",68},{"sbb reg,num",69},{"sbb reg,label",134},{"sbb [],reg",70},{"sbb [],num",71},{"sbb [],label",135},{"adc reg,reg",75},
	{"adc reg,[]",76},{"adc reg,num",77},{"adc reg,label",137},{"adc [],reg",78},{"adc [],num",79},{"adc [],label",136},{"xchg reg,reg",91},{"xchg reg,[]",92},
	{"xchg [],reg",93},{"cmpxchg [],reg",94},{"cmpxchg reg,reg",95},{"scas",74},{"stos",73},{"movs",140},{"bsr reg,reg",141},{"bsf reg,reg",142},
	{"mov label,reg",143},{"mov label,num",144}

};
int x64_findUpdate(ea_t ea, func_t* func) {
	if (ea == 0x1c31d4)
	{
		int breakpoint = 1;
	}
	x64_convert_operand2offset_type(ea);
	qstring Mnemq;
	print_insn_mnem(&Mnemq, ea);
	qstring disasm;
	generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
	std::string Mnem = Mnemq.c_str();
	
	int op0_type = 0, op1_type = 0, op2_type = 0,index=-1;
	std::string operand0, operand1, operand2;
	int ea_operand_num = count_ea_operands(ea);
	std::string keyword;
	x64_unname_all_regs(func);
	std::string operand1___ = x64_get_operand(ea+4, 0);
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

	//x64_recover_renamed_register(ea,&operand0,&operand1,&operand2, op0_type,op1_type,op2_type, ea_operand_num);
	if(Mnem.find('j')==0)
	{
		return 0;
	}
	else if (Mnem == "nop")
	{
		return 0;
	}
	else if (Mnem.find("cdq") != -1|| Mnem.find("cqo") != -1 || Mnem.find("cbw") != -1 || Mnem.find("cwd") != -1)
	{
		return 0;
	}
	else if (Mnem=="call" && op0_type==7)
	{
		return 0;
	}
	else
	{
		keyword = x64_get_root(Mnem)+" ";
		if (ea_operand_num >= 1)
		{
			if (op0_type == 3 || op0_type == 4)
				keyword += "[]";
			else if (op0_type == 1)
				keyword += "reg";
			else if(op0_type==2)
				keyword += "label";
		}
		if (ea_operand_num >= 2)
		{
			if (op1_type == 3 || op1_type == 4)
				keyword += ",[]";
			else if (op1_type == 1)
				keyword += ",reg";
			else if(op1_type == 2)
				keyword += ",label";
			else if(op1_type == 5)
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
		keyword = x64_rectify_specific_Mnem(Mnem,keyword,ea,op1_type);
		if(x64_Mnem2index.find(keyword)!= x64_Mnem2index.end())//recongnize instruction
			index = x64_Mnem2index[keyword];
		else if (x64_Mnem2index.find(keyword) == x64_Mnem2index.end())//do not recongnize instruction
		{
		//unknown mnem  
		if (ea_operand_num == 1 && op0_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 80/*"unknown reg*/); }
		else if (ea_operand_num == 1 && (op0_type == 3 || op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 81/*"unknown []*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 82/*"unknown reg,reg*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, "", 83/*"unknown reg,[]*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 84/*"unknown reg,num*/); }
		else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 138/*"unknown reg,label*/); }
		else if (ea_operand_num == 2 && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 85/*"unknown [],reg*/); }
		else if (ea_operand_num == 2 && (op0_type == 3 || op0_type == 4) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 86/*"unknown [],num*/); }
		else if (ea_operand_num == 2 && (op0_type == 3 || op0_type == 4) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 139/*"unknown [],label*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && op2_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 87/*"unknown reg, reg, reg*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && (op2_type == 5)) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 88/*"unknown reg, reg, num*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && (op2_type == 3 || op2_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 114/*"unknown reg, reg, []*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && (op1_type == 3 || op1_type == 4) && op2_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 89/*"unknown reg, [], reg*/); }
		else if (ea_operand_num == 3 && op0_type == 1 && (op1_type == 3 || op1_type == 4) && op2_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 90/*"unknown reg, [], num*/); }
		}
	}
	switch (index)
	{
	case 48:x64_subfindupdate(ea, func, operand0, "", "", 48/*call [rax]*/);break;
	case 49:x64_subfindupdate(ea, func, operand0, "", "", 49/*call rax*/);break;
	case 146:x64_subfindupdate(ea, func, operand0, "", "", 146/*call label*/);break;
	case 5:x64_subfindupdate(ea, func, operand0, "", "", 5/*push*/); break;
	case 147:x64_subfindupdate(ea, func, operand0, "", "", 5/*push*/); break;
	case 6: x64_subfindupdate(ea, func, operand0, "", "", 6/*pop*/); break;
	case 0: x64_subfindupdate(ea, func, operand0, operand1, "", 0/*"mov reg,reg"*/);break;
	case 97:x64_subfindupdate(ea, func, operand0, operand1, "", 97/*"mov reg,cs:xxx"*/);break;
	case 1:x64_subfindupdate(ea, func, operand0, operand1, "", 1/*"mov reg,[]"*/);break;
	case 4:x64_subfindupdate(ea, func, operand0, operand1, "", 4/*mov reg, num*/);break;
	case 2:x64_subfindupdate(ea, func, operand0, operand1, "", 2/*"mov [],num"*/);break;
	case 3:x64_subfindupdate(ea, func, operand0, operand1, "", 3/*"mov [],reg"*/);break;
	case 7:x64_subfindupdate(ea, func, operand0, operand1, "", 7/*"lea reg,[]")*/);break;
	case 8:x64_subfindupdate(ea, func, operand0, operand1, "", 8/*"lea reg,str"*/);break;
	case 9:x64_subfindupdate(ea, func, operand0, operand1, "", 9/*"test reg,reg*/);break;
	case 10:x64_subfindupdate(ea, func, operand0, operand1, "", 10/*"test reg,num*/);break;
	case 11:x64_subfindupdate(ea, func, operand0, operand1, "", 11/*"test [],num*/);break;
	case 12:x64_subfindupdate(ea, func, operand0, operand1, "", 12/*"test [],reg*/);break;
	//case 13:x64_subfindupdate(ea, func, operand0, operand1, "", 13/*"xor eax,eax*/);break;
	case 56:x64_subfindupdate(ea, func, operand0, operand1, "", 56/*"xor eax,ebx*/);break;
	case 57:x64_subfindupdate(ea, func, operand0, operand1, "", 57/*"xor reg, num*/);break;
	case 115:x64_subfindupdate(ea, func, operand0, operand1, "", 115/*"xor reg, label*/);break;
	case 58:x64_subfindupdate(ea, func, operand0, operand1, "", 58/*"xor [], num*/);break;
	case 116:x64_subfindupdate(ea, func, operand0, operand1, "", 116/*"xor [], label*/);break;
	case 59:x64_subfindupdate(ea, func, operand0, operand1, "", 59/*"xor reg, []*/);break;
	case 96:x64_subfindupdate(ea, func, operand0, operand1, "", 96/*"xor [], reg*/);break;
	case 53:x64_subfindupdate(ea, func, operand0, operand1, "", 53/*"cmp reg, []*/);break;
	case 14:x64_subfindupdate(ea, func, operand0, operand1, "", 14/*"add reg,reg*/);break;
	case 15:x64_subfindupdate(ea, func, operand0, operand1, "", 15/*"add reg,[]*/);break;
	case 16:x64_subfindupdate(ea, func, operand0, operand1, "", 16/*"add reg,num*/);break;
	case 117:x64_subfindupdate(ea, func, operand0, operand1, "", 117/*"add reg,label*/);break;
	case 17:x64_subfindupdate(ea, func, operand0, operand1, "", 17/*"add [],reg*/);break;
	case 18:x64_subfindupdate(ea, func, operand0, operand1, "", 18/*"add [],num*/);break;
	case 118:x64_subfindupdate(ea, func, operand0, operand1, "", 118/*"add [],label*/);break;
	case 19:x64_subfindupdate(ea, func, operand0, operand1, "", 19/*"sub reg,reg*/);break;
	case 20:x64_subfindupdate(ea, func, operand0, operand1, "", 20/*"sub reg,[]*/);break;
	case 21:x64_subfindupdate(ea, func, operand0, operand1, "", 21/*"sub reg,num*/);break;
	case 119:x64_subfindupdate(ea, func, operand0, operand1, "", 119/*"sub reg,label*/);break;
	case 22:x64_subfindupdate(ea, func, operand0, operand1, "", 22/*"sub [],reg*/);break;
	case 23:x64_subfindupdate(ea, func, operand0, operand1, "", 23/*"sub [],num*/);break;
	case 120:x64_subfindupdate(ea, func, operand0, operand1, "", 120/*"sub [],label*/);break;
	case 24:x64_subfindupdate(ea, func, operand0, operand1, "", 24/*"imul reg,reg*/);break;
	case 25:x64_subfindupdate(ea, func, operand0, operand1, "", 25/*"imul reg,[]*/);break;
	case 26:x64_subfindupdate(ea, func, operand0, operand1, operand2, 26/*"imul reg,reg,num*/);break;
	case 27:x64_subfindupdate(ea, func, operand0, operand1, operand2, 27/*"imul reg,[],num*/);break;
	case 148:x64_subfindupdate(ea, func, operand0, operand1, operand2, 148/*"imul reg,label,num*/);break;
	case 31:x64_subfindupdate(ea, func, operand0, "", "", 31/*"mul/imul reg*/);break;
	case 32:x64_subfindupdate(ea, func, operand0, "", "", 32/*"mul/imul []*/);break;
	case 149:x64_subfindupdate(ea, func, operand0, "", "", 149/*"mul/imul label*/);break;
	case 29:x64_subfindupdate(ea, func, operand0, "", "", 29/*"div reg*/);break;
	case 30:x64_subfindupdate(ea, func, operand0, "", "", 30/*"div []*/);break;
	case 145:x64_subfindupdate(ea, func, operand0, "", "", 145/*"div label*/);break;
	case 34:x64_subfindupdate(ea, func, operand0, operand1, "", 34/*"rol reg,num/cl*/);break;
	case 121:x64_subfindupdate(ea, func, operand0, operand1, "", 121/*"rol reg,label*/);break;
	case 104:x64_subfindupdate(ea, func, operand0, operand1, "", 104/*"rol reg,reg*/);break;
	case 35:x64_subfindupdate(ea, func, operand0, operand1, "", 35/*"rol [],num/cl*/);break;
	case 122:x64_subfindupdate(ea, func, operand0, operand1, "", 122/*"rol [],label*/);break;
	case 98:x64_subfindupdate(ea, func, operand0, operand1, "", 98/*"rol [],reg*/);break;
	case 36:x64_subfindupdate(ea, func, operand0, operand1, "", 36/*"ror reg,num/cl*/);break;
	case 123:x64_subfindupdate(ea, func, operand0, operand1, "", 123/*"ror reg,label*/);break;
	case 37:x64_subfindupdate(ea, func, operand0, operand1, "", 37/*"ror [],num/cl*/);break;
	case 124:x64_subfindupdate(ea, func, operand0, operand1, "", 124/*"ror [],label*/);break;
	case 99: x64_subfindupdate(ea, func, operand0, operand1, "", 99/*"ror [],reg*/);break;
	case 105:x64_subfindupdate(ea, func, operand0, operand1, "", 105/*"ror reg,reg*/);break;
	case 60:x64_subfindupdate(ea, func, operand0, operand1, "", 60/*"shl reg,num*/);break;
	case 125:x64_subfindupdate(ea, func, operand0, operand1, "", 125/*"shl reg,label*/);break;
	case 106:x64_subfindupdate(ea, func, operand0, operand1, "", 106/*"shl reg,reg*/);break;
	case 61:x64_subfindupdate(ea, func, operand0, operand1, "", 61/*"shl [],num*/);break;
	case 126: x64_subfindupdate(ea, func, operand0, operand1, "", 126/*"shl [],label*/);break;
	case 100:x64_subfindupdate(ea, func, operand0, operand1, "", 100/*"shl [],reg*/);break;
	case 62:x64_subfindupdate(ea, func, operand0, operand1, "", 62/*"shr reg,num*/);break;
	case 127:x64_subfindupdate(ea, func, operand0, operand1, "", 127/*"shr reg,label*/);break;
	case 107:x64_subfindupdate(ea, func, operand0, operand1, "", 107/*"shr reg,reg*/);break;
	case 63:x64_subfindupdate(ea, func, operand0, operand1, "", 63/*"shr [],num*/);break;
	case 128:x64_subfindupdate(ea, func, operand0, operand1, "", 128/*"shr [],label*/);break;
	case 101:x64_subfindupdate(ea, func, operand0, operand1, "", 101/*"shr [],reg*/);break;
	case 38:x64_subfindupdate(ea, func, operand0, operand1, "", 38/*"and reg,reg*/);break;
	case 39:x64_subfindupdate(ea, func, operand0, operand1, "", 39/*"and reg,[]*/);break;
	case 40:x64_subfindupdate(ea, func, operand0, operand1, "", 40/*"and reg,num*/);break;
	case 129:x64_subfindupdate(ea, func, operand0, operand1, "", 129/*"and reg,label*/);break;
	case 41:x64_subfindupdate(ea, func, operand0, operand1, "", 41/*"and [],reg*/);break;
	case 42:x64_subfindupdate(ea, func, operand0, operand1, "", 42/*"and [],num*/);break;
	case 130:x64_subfindupdate(ea, func, operand0, operand1, "", 130/*"and [],label*/);break;
	case 43:x64_subfindupdate(ea, func, operand0, operand1, "", 43/*"or reg,reg*/);break;
	case 44:x64_subfindupdate(ea, func, operand0, operand1, "", 44/*"or reg,[]*/);break;
	case 45:x64_subfindupdate(ea, func, operand0, operand1, "", 45/*"or reg,num*/);break;
	case 131:x64_subfindupdate(ea, func, operand0, operand1, "", 131/*"or reg,label*/);break;
	case 46:x64_subfindupdate(ea, func, operand0, operand1, "", 46/*"or [],reg*/);break;
	case 47:x64_subfindupdate(ea, func, operand0, operand1, "", 47/*"or [],num*/);break;
	case 132:x64_subfindupdate(ea, func, operand0, operand1, "", 132/*"or [],label*/);break;
	case 50:x64_subfindupdate(ea, func, operand0, operand1, "", 50/*punpck xmm0,xmm1*/);break;
	case 51:x64_subfindupdate(ea, func, operand0, "", "", 51/*inc reg*/);break;
	case 108:x64_subfindupdate(ea, func, operand0, "", "", 108/*inc []*/);break;
	case 52:x64_subfindupdate(ea, func, operand0, "", "", 52/*dec reg*/);break;
	case 109:x64_subfindupdate(ea, func, operand0, "", "", 109/*dec []*/);break;
	case 54:x64_subfindupdate(ea, func, operand0, "", "", 54/*not reg*/);break;
	case 110:x64_subfindupdate(ea, func, operand0, "", "", 110/*not []*/);break;
	case 55:x64_subfindupdate(ea, func, operand0, "", "", 55/*neg reg*/);break;
	case 111:x64_subfindupdate(ea, func, operand0, "", "", 111/*neg []*/);break;
	case 64:x64_subfindupdate(ea, func, operand0, "", "", 64/*set reg*/);break;
	case 103:x64_subfindupdate(ea, func, operand0, "", "", 103/*set []*/);break;
	case 133:x64_subfindupdate(ea, func, operand0, operand1, "", 133/*cmov reg, label*/);break;
	case 65:x64_subfindupdate(ea, func, operand0, operand1, "", 65/*cmov reg, reg*/);break;
	case 66:x64_subfindupdate(ea, func, operand0, operand1, "", 66/*cmov reg, []*/);break;
	case 67:x64_subfindupdate(ea, func, operand0, operand1, "", 67/*"sbb reg,reg*/);break;
	case 68:x64_subfindupdate(ea, func, operand0, operand1, "", 68/*"sbb reg,[]*/);break;
	case 69:x64_subfindupdate(ea, func, operand0, operand1, "", 69/*"sbb reg,num*/);break;
	case 134:x64_subfindupdate(ea, func, operand0, operand1, "", 134/*"sbb reg,label*/);break;
	case 70:x64_subfindupdate(ea, func, operand0, operand1, "", 70/*"sbb [],reg*/);break;
	case 71:x64_subfindupdate(ea, func, operand0, operand1, "", 71/*"sbb [],num*/);break;
	case 135: x64_subfindupdate(ea, func, operand0, operand1, "", 135/*"sbb [],label*/);break;
	case 75:x64_subfindupdate(ea, func, operand0, operand1, "", 75/*"adc reg,reg*/);break;
	case 76:x64_subfindupdate(ea, func, operand0, operand1, "", 76/*"adc reg,[]*/);break;
	case 77:x64_subfindupdate(ea, func, operand0, operand1, "", 77/*"adc reg,num*/);break;
	case 137:x64_subfindupdate(ea, func, operand0, operand1, "", 137/*"adc reg,label*/);break;
	case 78: x64_subfindupdate(ea, func, operand0, operand1, "", 78/*"adc [],reg*/);break;
	case 79:x64_subfindupdate(ea, func, operand0, operand1, "", 79/*"adc [],num*/);break;
	case 136:x64_subfindupdate(ea, func, operand0, operand1, "", 136/*"adc [],label*/);break;
	case 91:x64_subfindupdate(ea, func, operand0, operand1, "", 91/*"xchg reg,reg*/);break;
	case 92:x64_subfindupdate(ea, func, operand0, operand1, "", 92/*"xchg reg, []*/);break;
	case 93:x64_subfindupdate(ea, func, operand0, operand1, "", 93/*"xchg [],reg*/);break;
	case 94:x64_subfindupdate(ea, func, operand0, operand1, "", 94/*"cmpxchg [], reg*/);break;
	case 95: x64_subfindupdate(ea, func, operand0, operand1, "", 95/*"cmpxchg reg, reg*/);break;
	case 73: x64_subfindupdate(ea, func, operand0,"", "", 73/*"stos*/);break;
	case 74: x64_subfindupdate(ea, func, operand0, "", "", 74/*"scas*/);break;
	case 140: x64_subfindupdate(ea, func, operand0, "", "", 140/*"movs*/);break;
	case 141: x64_subfindupdate(ea, func, operand0, operand1, "", 141/*"bsr reg,reg*/);break;
	case 142: x64_subfindupdate(ea, func, operand0, operand1, "", 142/*"bsf reg,reg*/);break;
	case 143: x64_subfindupdate(ea, func, operand0, operand1, "", 143/*"mov label,reg*/);break;
	case 144: x64_subfindupdate(ea, func, operand0, operand1, "", 144/*"mov label,num*/);break;

		//{
			//warning("%s op_type0=%d", operand0, op0_type);
		//	if (op0_type == 3 || op0_type == 4)
				
		//	else if (op0_type == 1)
		//		x64_subfindupdate(ea, func, operand0, "", "", 49/*call rax*/);
		//	return 0;
		//}
		/*else if (Mnem.find('j') == 0)
		{
			ea_t next_ea;
			qstring disasm, disasm1;
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			next_ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT);
			ea_t msg_index, msg_index1;
			msg_index = get_first_cref_from(ea);
			msg_index1 = get_next_cref_from(ea, msg_index);
			return 0;
		}*/
		//else if (Mnem == "push") { x64_subfindupdate(ea, func, operand0, "", "", 5/*push*/); return 0; }
		//else if (Mnem == "pop") { x64_subfindupdate(ea, func, operand0, "", "", 6/*pop*/); return 0; }
		//else if (op0_type == 5) { return 0; }           //like push 12, 
		//else if (Mnem == "nop") { return 0; }

		//mov eax,ebx, find defination for ebx
		//if (op0_type == 1 && op1_type == 1 && Mnem.find("mov") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 0/*"mov reg,reg"*/); }

		//mov eax,cs:xxx
		//else if (op0_type == 1 && op1_type == 2 && Mnem.find("mov") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 97/*"mov reg,cs:xxx"*/); }

		// mov rax, [rbx+14], find defination for rbx
		//else if (op0_type == 1 && (op1_type == 4 || op1_type == 3) && Mnem.find("mov") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 1/*"mov reg,[]"*/); }

		//mov eax, 1
		//else if (op0_type == 1 && op1_type == 5 && Mnem.find("mov") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 4/*mov reg, num*/);return 0; }

		//mov [rax+5], 1
		//else if ((op0_type == 4 || op0_type == 3) && op1_type == 5 && Mnem.find("mov") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 2/*"mov [],num"*/);return 0; }

		// mov [rbx+14], rax find defination for rbx
		//else if ((op0_type == 4 || op0_type == 3) && op1_type == 1 && Mnem.find("mov") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 3/*"mov [],reg"*/); }

		//lea rax, [rbx+rsi]
		//else if (op0_type == 1 && (op1_type == 4 || op1_type == 3) && Mnem == "lea") { x64_subfindupdate(ea, func, operand0, operand1, "", 7/*"lea reg,[]")*/); }

		//lea rax, "string"
		//else if (op0_type == 1 && op1_type == 2 && Mnem == "lea") { x64_subfindupdate(ea, func, operand0, operand1, "", 8/*"lea reg,str"*/); }

		//test rax,rax or test rax,rbx
		//else if (Mnem == "test" && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 9/*"test reg,reg*/); }

		//test rax,num/label

		//else if (Mnem == "test" && op0_type == 1 && (op1_type == 5 || op1_type == 2)) { x64_subfindupdate(ea, func, operand0, operand1, "", 10/*"test reg,num*/); }

		//test [],num/label
		//else if (Mnem == "test" && (op0_type == 4 || op0_type == 3) && (op1_type == 5 || op1_type == 2)) { x64_subfindupdate(ea, func, operand0, operand1, "", 11/*"test [],num*/); }

		//test [],reg
		//else if (Mnem == "test" && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 12/*"test [],reg*/); }

		//xor rax, rax
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 1 && operand0 == operand1) { x64_subfindupdate(ea, func, operand0, operand1, "", 13/*"xor eax,eax*/); }

		//xor rax, rbx
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 56/*"xor eax,ebx*/); }

		//xor reg, num
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 57/*"xor reg, num*/); }

		//xor reg, label
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 115/*"xor reg, label*/); }

		//xor [],num
		//else if (Mnem.find("xor") != -1 && (op0_type == 3 || op0_type == 4) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 58/*"xor [], num*/); }

		//xor [],label
		//else if (Mnem.find("xor") != -1 && (op0_type == 3 || op0_type == 4) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 116/*"xor [], label*/); }

		//xor reg, []
		//else if (Mnem.find("xor") != -1 && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, "", 59/*"xor reg, []*/); }

		//xor [], reg
		//else if (Mnem.find("xor") != -1 && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 96/*"xor [], reg*/); }

		//cmp reg,reg
		//else if (Mnem == "cmp" && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 9/*"cmp reg,reg*/); }

		//cmp reg,num
		//else if (Mnem == "cmp" && op0_type == 1 && (op1_type == 5 || op1_type == 2)) { x64_subfindupdate(ea, func, operand0, operand1, "", 10/*"cmp reg,num*/); }

		//cmp [],num
		//else if (Mnem == "cmp" && (op0_type == 4 || op0_type == 3) && (op1_type == 5 || op1_type == 2)) { x64_subfindupdate(ea, func, operand0, operand1, "", 11/*"cmp [],num*/); }

		//cmp [],reg
		//else if (Mnem == "cmp" && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 12/*"cmp [],reg*/); }

		//cmp reg, []
		//else if (Mnem == "cmp" && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, "", 53/*"cmp reg, []*/); }

		//add reg,reg
		//else if (Mnem.find("add") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 14/*"add reg,reg*/); }

		//add reg,[]
		//else if (Mnem.find("add") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, operand1, "", 15/*"add reg,[]*/); }

		//add reg,num
		//else if (Mnem.find("add") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 16/*"add reg,num*/); }

		//add reg,label
		//else if (Mnem.find("add") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 117/*"add reg,label*/); }

		//add [],reg
		//else if (Mnem.find("add") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 17/*"add [],reg*/); }

		//add [],num
		//else if (Mnem.find("add") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 18/*"add [],num*/); }

		//add [],label
		//else if (Mnem.find("add") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 118/*"add [],label*/); }

		//sub  reg,reg
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 19/*"sub reg,reg*/); }

		//sub reg,[]
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, operand1, "", 20/*"sub reg,[]*/); }

		//sub reg,num
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 21/*"sub reg,num*/); }

		//sub reg,label
		//else if (Mnem.find("sub") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 119/*"sub reg,label*/); }

		//sub [],reg
		//else if (Mnem.find("sub") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 22/*"sub [],reg*/); }

		//sub [],num
		//else if (Mnem.find("sub") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 23/*"sub [],num*/); }

		//sub [],label
		//else if (Mnem.find("sub") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 120/*"sub [],label*/); }

		//imul  reg,reg
		//else if (Mnem.find("imul") != -1 && op0_type == 1 && op1_type == 1 && ea_operand_num == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 24/*"imul reg,reg*/); }

		//imul reg,[]
		//else if (Mnem.find("imul") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3) && ea_operand_num == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 25/*"imul reg,[]*/); }

		//imul reg,reg,num
		//else if (Mnem.find("imul") != -1 && op0_type == 1 && op1_type == 1 && op2_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 26/*"imul reg,reg,num*/); }

		//imul reg,[],num
		//else if (Mnem.find("imul") != -1 && (op0_type == 1 && (op1_type == 4 || op1_type == 3) && op2_type == 5)) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 27/*"imul reg,[],num*/); }

		//mul/imul reg
		//else if (Mnem.find("mul") != -1 && ea_operand_num == 2 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 31/*"mul/imul reg*/); }

		//mul/imul []
		//else if (Mnem.find("mul") != -1 && ea_operand_num == 2 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 32/*"mul/imul []*/); }

		//div/idiv  reg
		//else if (Mnem.find("div") != -1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 29/*"div reg*/); }

		//div/idiv []
		//else if (Mnem.find("div") != -1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, "", "", 30/*"div []*/); }

		//rol reg,num
		//else if (Mnem.find("rol") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 34/*"rol reg,num/cl*/); }

		//rol reg,label
		//else if (Mnem.find("rol") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 121/*"rol reg,label*/); }

		//rol reg,reg
		//else if (Mnem.find("rol") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 104/*"rol reg,reg*/); }

		//rol [],num
		//else if (Mnem.find("rol") != -1 && (op0_type == 4 || op1_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 35/*"rol [],num/cl*/); }

		//rol [],label
		//else if (Mnem.find("rol") != -1 && (op0_type == 4 || op1_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 122/*"rol [],label*/); }

		//rol [],reg
		//else if (Mnem.find("rol") != -1 && (op0_type == 4 || op1_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 98/*"rol [],reg*/); }

		//ror reg,num
		//else if (Mnem.find("ror") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 36/*"ror reg,num/cl*/); }

		//ror reg,label
		//else if (Mnem.find("ror") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 123/*"ror reg,label*/); }

		//ror [],num
		//else if (Mnem.find("ror") != -1 && (op0_type == 4 || op1_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 37/*"ror [],num/cl*/); }

		//ror [],label
		//else if (Mnem.find("ror") != -1 && (op0_type == 4 || op1_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 124/*"ror [],label*/); }

		//ror [],reg
		//else if (Mnem.find("ror") != -1 && (op0_type == 4 || op1_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 99/*"ror [],reg*/); }

		//ror reg,reg
		//else if (Mnem.find("ror") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 105/*"ror reg,reg*/); }

		//shl reg,num
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 60/*"shl reg,num*/); }

		//shl reg,label
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 125/*"shl reg,label*/); }

		//shl reg,reg
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 106/*"shl reg,reg*/); }

		//shl [],num
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 61/*"shl [],num*/); }

		//shl [],label
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 126/*"shl [],label*/); }

		//shl [],reg
		//else if ((Mnem.find("shl") != -1 || Mnem.find("sal") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 100/*"shl [],reg*/); }

		//shr reg,num
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 62/*"shr reg,num*/); }

		//shr reg,label
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 127/*"shr reg,label*/); }

		//shr reg,reg
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 107/*"shr reg,reg*/); }

		//shr [],num
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 63/*"shr [],num*/); }

		//shr [],label
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 128/*"shr [],label*/); }

		//shr [],reg
		//else if ((Mnem.find("shr") != -1 || Mnem.find("sar") != -1) && (op0_type == 4 || op1_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 101/*"shr [],reg*/); }

		//and  reg,reg
		//else if (Mnem.find("and") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 38/*"and reg,reg*/); }

		//and reg,[]
		//else if (Mnem.find("and") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, operand1, "", 39/*"and reg,[]*/); }

		//and reg,num
		//else if (Mnem.find("and") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 40/*"and reg,num*/); }

		//and reg,label
		//else if (Mnem.find("and") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 129/*"and reg,label*/); }

		//and [],reg
		//else if (Mnem.find("and") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 41/*"and [],reg*/); }

		//and [],num
		//else if (Mnem.find("and") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 42/*"and [],num*/); }

		//and [],label
		//else if (Mnem.find("and") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 130/*"and [],label*/); }

		//or  reg,reg
		//else if (Mnem.find("or") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 43/*"or reg,reg*/); }

		//or reg,[]
		//else if (Mnem.find("or") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, operand1, "", 44/*"or reg,[]*/); }

		//or reg,num
		//else if (Mnem.find("or") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 45/*"or reg,num*/); }

		//or reg,label
		//else if (Mnem.find("or") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 131/*"or reg,label*/); }

		//or [],reg
		//else if (Mnem.find("or") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 46/*"or [],reg*/); }

		//or [],num
		//else if (Mnem.find("or") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 47/*"or [],num*/); }

		//or [],label
		//else if (Mnem.find("or") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 132/*"or [],label*/); }

		//punpck
		//else if (Mnem.find("punpck") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 50/*punpck xmm0,xmm1*/); }

		//inc reg
		//else if (Mnem == "inc" && op0_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 51/*inc reg*/); }

		//inc []
		//else if (Mnem == "inc" && (op0_type == 3 || op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 108/*inc []*/); }

		//dec reg
		//else if (Mnem == "dec" && op0_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 52/*dec reg*/); }

		//dec []
		//else if (Mnem == "dec" && (op0_type == 3 || op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 109/*dec []*/); }

		//not neg
		//else if (Mnem == "not" && op0_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 54/*not reg*/); }

		//not []
		//else if (Mnem == "not" && (op0_type == 3 || op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 110/*not []*/); }

		//neg reg
		//else if (Mnem == "neg" && op0_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 55/*neg reg*/); }

		//neg []
		//else if (Mnem == "neg" && (op0_type == 3 || op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 111/*neg []*/); }

		//set reg
		//else if (Mnem.find("set") != -1 && op0_type == 1) { x64_subfindupdate(ea, func, operand0, "", "", 64/*set reg*/); }

		//set []
		//else if (Mnem.find("set") != -1 && (op0_type == 3 || op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 103/*set []*/); }

		//cmov reg, label
		//else if (Mnem == "cmov" && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 133/*cmov reg, label*/); }

		//cmov reg, reg
		//else if (Mnem == "cmov" && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 65/*cmov reg, reg*/); }

		//cmov reg,[]
		//else if (Mnem == "cmov" && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, "", 66/*cmov reg, []*/); }

		//sbb  reg,reg
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 67/*"sbb reg,reg*/); }

		//sbb reg,[]
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, operand1, "", 68/*"sbb reg,[]*/); }

		//sbb reg,num
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 69/*"sbb reg,num*/); }

		//sbb reg,label
		//else if (Mnem.find("sbb") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 134/*"sbb reg,label*/); }

		//sbb [],reg
		//else if (Mnem.find("sbb") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 70/*"sbb [],reg*/); }

		//sbb [],num
		//else if (Mnem.find("sbb") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 71/*"sbb [],num*/); }

		//sbb [],label
		//else if (Mnem.find("sbb") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 135/*"sbb [],label*/); }

		//scas
		//else if (Mnem.find("scas") != -1) {}

		//stos
		//else if (Mnem.find("stos") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 73/*"stos num*/); }

		//rep
		//else if (Mnem.find("rep") == 0) { x64_subfindupdate(ea, func, operand0, operand1, "", 74/*"rep*/); }

		//adc  reg,reg
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 75/*"adc reg,reg*/); }

		//adc reg,[]
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && (op1_type == 4 || op1_type == 3)) { x64_subfindupdate(ea, func, operand0, operand1, "", 76/*"adc reg,[]*/); }

		//adc reg,num
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 77/*"adc reg,num*/); }

		//adc reg,label
		//else if (Mnem.find("adc") != -1 && op0_type == 1 && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 137/*"adc reg,label*/); }

		//adc [],reg
		//else if (Mnem.find("adc") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 78/*"adc [],reg*/); }

		//adc [],num
		//else if (Mnem.find("adc") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 79/*"adc [],num*/); }

		//adc [],label
		//else if (Mnem.find("adc") != -1 && (op0_type == 4 || op0_type == 3) && op1_type == 2) { x64_subfindupdate(ea, func, operand0, operand1, "", 136/*"adc [],label*/); }

		//xchg reg,reg
		//else if (Mnem == "xchg" && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 91/*"xchg reg,reg*/); }

		//xchg reg, []
		//else if (Mnem == "xchg" && op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, "", 92/*"xchg reg, []*/); }

		//xchg [],reg
		//else if (Mnem == "xchg" && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 93/*"xchg [],reg*/); }

		//cmpxchg [], reg
		//else if (Mnem == "cmpxchg" && (op0_type == 3 || op0_type == 4) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 94/*"cmpxchg [], reg*/); }

		//cmpxchg reg, reg
		//else if (Mnem == "cmpxchg" && op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 95/*"cmpxchg reg, reg*/); }

		//cdqe
		//else if (Mnem.find("cdq") != -1) { ; }
	}
	//unknown mnem  
 	//else if (ea_operand_num == 1 && op0_type==1){ x64_subfindupdate(ea, func, operand0, "", "", 80/*"unknown reg*/); }
	//else if (ea_operand_num == 1 && (op0_type == 3|| op0_type == 4)) { x64_subfindupdate(ea, func, operand0, "", "", 81/*"unknown []*/); }
	//else if(ea_operand_num == 2 && op0_type==1 && op1_type==1) { x64_subfindupdate(ea, func, operand0, operand1, "", 82/*"unknown reg,reg*/); }
	//else if (ea_operand_num == 2 && op0_type == 1 && (op1_type == 3||op1_type==4)) { x64_subfindupdate(ea, func, operand0, operand1, "", 83/*"unknown reg,[]*/); }
	//else if (ea_operand_num == 2 && op0_type == 1 && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 84/*"unknown reg,num*/); }
	//else if (ea_operand_num == 2 && (op0_type == 3||op0_type==4) && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, "", 85/*"unknown [],reg*/); }
	//else if (ea_operand_num == 2 && (op0_type == 3||op0_type==4) && op1_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, "", 86/*"unknown [],num*/); }
	//else if (ea_operand_num == 3 && op0_type==1 && op1_type==1 && op2_type==1) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 87/*"unknown reg, reg, reg*/); }
	//else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && (op2_type == 5)) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 88/*"unknown reg, reg, num*/); }
	//else if (ea_operand_num == 3 && op0_type == 1 && op1_type == 1 && (op2_type == 3|| op2_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 114/*"unknown reg, reg, []*/); }
	//else if (ea_operand_num == 3 && op0_type == 1 && (op1_type == 3||op1_type==4) && op2_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 89/*"unknown reg, [], reg*/); }
	//else if (ea_operand_num == 3 && op0_type == 1 && (op1_type == 3 || op1_type == 4) && op2_type == 5) { x64_subfindupdate(ea, func, operand0, operand1, operand2, 90/*"unknown reg, [], num*/); }
	return 0;

}




/*void x64_infer_this_insn_propagate_next(func_t* func, ea_t ea)
{
	if (x64_is_pop_insn(ea))
	{
		//init_IR_reserve_insns(func);
		//translate_loop_insns(ea,func); 
		init_x64_my_insn_IR(func);
		x64_translate_return_value(ea, func);
		x64_translate_each_insn(ea, func);
		x64_print_to_file(ea, func);
		//reset_iter_source();
		//print_path(ea,func);
		return;
	}

	x64_my_insn[ea2x64_my_insn[ea]].operand0 = "";
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.clear();
	x64_my_insn[ea2x64_my_insn[ea]].operand1 = "";
	x64_my_insn[ea2x64_my_insn[ea]].parameters1.clear();
	ea_t next_ea, next_ea1;
	x64_findUpdate(ea, func);
	next_ea = get_first_cref_from(ea);
	next_ea1 = get_next_cref_from(ea, next_ea);

	if (next_ea != -1 && is_in_loop(ea, next_ea, func))
	{


		x64_recalculate_for_while(ea, next_ea, func);
		next_ea = -1;
	}

	if (next_ea1 != -1 && is_in_loop(ea, next_ea1, func))
	{


		x64_recalculate_for_while(ea, next_ea1, func);
		next_ea1 = -1;

	}


	if (next_ea != -1 && next_ea != BADADDR && next_ea >= func->start_ea && next_ea <= func->end_ea)
	{

		insn_last_insn[next_ea] = ea;
		x64_infer_this_insn_propagate_next(func, next_ea);


		if (next_ea1 != -1 && next_ea1 >= func->start_ea && next_ea1 <= func->end_ea)
		{

			insn_last_insn[next_ea1] = ea;
			x64_infer_this_insn_propagate_next(func, next_ea1);

		}
	}


}*/

void x64_random_infer_this_insn_propagate_next(func_t* func, ea_t ea)
{
	if (ea == 0x4ac707)
		int breakp = 1;
	if (x64_is_switch_jump(ea))//In this case, there are more than 2 branches after this insn.
	{
		std::vector <ea_t> next_eas;
		ea_t next_ea;
		next_ea = get_first_cref_from(ea);
		while (next_ea != -1)//Get a list of branching instructions following instruction ADD PC, PC, ...
		{
			next_eas.push_back(next_ea);
			next_ea = get_next_cref_from(ea, next_ea);
		}
		for (int i = 0;i < next_eas.size();i++)//For each branch
		{
			if (next_eas[i] != -1 && next_eas[i] != BADADDR && next_eas[i] >= func->start_ea && next_eas[i] <= func->end_ea)//Go to next ea
			{

				if (insn_has_not_been_touched(next_eas[i], func))
				{
					insn_last_insn[next_eas[i]] = ea;
					x64_random_infer_this_insn_propagate_next(func, next_eas[i]);
				}

			}
		}
	}
	else
	{
		/*if (x64_is_pop_insn(ea))
		{
			//reset_iter_source();
			//print_path(ea,func);
			return;
		}*/
		x64_my_insn[ea2x64_my_insn[ea]].operand0 = "";
		x64_my_insn[ea2x64_my_insn[ea]].parameters0.clear();
		x64_my_insn[ea2x64_my_insn[ea]].operand1 = "";
		x64_my_insn[ea2x64_my_insn[ea]].parameters1.clear();
		ea_t next_ea, next_ea1;
		if (x64_Mnem_not_support(ea))//If we found the instruction not calculatable, quit.
		{
			add_uncalculatable_function(ea);
			return;
		}
		x64_findUpdate(ea, func);
		if (x64_is_symbolic_value_explosion(ea))//If we found the instruction not calculatable, quit.
		{
			add_uncalculatable_function(ea);
			return;
		}
		next_ea = get_first_cref_from(ea);
		if (next_ea >= func->end_ea || next_ea < func->start_ea)
			next_ea = -1;
		next_ea1 = get_next_cref_from(ea, next_ea);
		if (next_ea1 >= func->end_ea || next_ea1 < func->start_ea)
			next_ea1 = -1;
		if (next_ea != -1 && next_ea1 != -1)
			random_swap(next_ea, next_ea1);
		put_loop_first(next_ea, next_ea1, ea, func);
		if (ea == 0x1e55)
			int bp = 1;
		if (next_ea != -1 && is_in_loop(ea, next_ea, func))
		{
			//x64_recalculate_loop(ea, next_ea, func);
			if (insn_not_recalculate_yet(next_ea))
			{
				x64_recalculate_for_while_v1(ea, next_ea, func);
				recalculated_yet_map.insert({ next_ea ,1 });
			}
			//x64_process_loop(ea, next_ea, func);
			//x64_mark_redundant_insns(ea, next_ea, func);
			//x64_iteralize_operands(ea, next_ea, func);
			next_ea = -1;
		}

		if (next_ea1 != -1 && is_in_loop(ea, next_ea1, func))
		{
			//x64_recalculate_loop(ea, next_ea, func);
			if (insn_not_recalculate_yet(next_ea1))
			{
				x64_recalculate_for_while_v1(ea, next_ea1, func);
				recalculated_yet_map.insert({ next_ea1 ,1 });
			}
			//x64_process_loop(ea, next_ea, func);
			//x64_mark_redundant_insns(ea, next_ea, func);
			//x64_iteralize_operands(ea, next_ea, func);
			next_ea1 = -1;

		}


		if (next_ea != -1 && next_ea != BADADDR && next_ea >= func->start_ea && next_ea <= func->end_ea)
		{

			if (insn_has_not_been_touched(next_ea, func))
			{
				insn_last_insn[next_ea] = ea;
 				x64_random_infer_this_insn_propagate_next(func, next_ea);
			}
		}

		if (next_ea1 != -1 && next_ea1 >= func->start_ea && next_ea1 <= func->end_ea)
		{

			if (insn_has_not_been_touched(next_ea1, func))
			{
				insn_last_insn[next_ea1] = ea;
				x64_random_infer_this_insn_propagate_next(func, next_ea1);
			}

		}
	}
	
}

//For cmov instruction, we create two threads to propagate value.
void x64_random_infer_cinditional_insn(func_t* func, ea_t ea)
{
	ea_t next_ea;
	next_ea = get_first_cref_from(ea);
	insn_last_insn[next_ea] = ea;
    //First thread
	x64_findUpdate_cmov("0",ea, func);
	x64_random_infer_this_insn_propagate_next(func, next_ea);
	//Second thread
	if (ea == 0x2a5a)
		int breakp = 1;
	x64_findUpdate_cmov("1", ea, func);
	x64_iterate_clean_x64_my_insn(ea, func);
	x64_random_infer_this_insn_propagate_next(func, next_ea);
}

void x64_findUpdate_cmov(std::string thread_num, ea_t ea, func_t *func)
{
	int op0_type = 0, op1_type = 0, op2_type = 0;
	std::string operand0, operand1, operand2;
	int ea_operand_num = count_ea_operands(ea);

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
	/*cmov reg, reg*/
	if (op0_type == 1 && op1_type == 1) { x64_subfindupdate(ea, func, operand0, operand1, thread_num, 65/*cmov reg, reg*/); }
	/*cmov reg, []*/
	else if (op0_type == 1 && (op1_type == 3 || op1_type == 4)) { x64_subfindupdate(ea, func, operand0, operand1, thread_num, 66/*cmov reg, []*/); }
}

void x64_iterate_clean_x64_my_insn(ea_t ea, func_t* func)
{
	//Iterate until we reach the last instruction executed im this thread
	//Double insurance in case when the execution propagate to the last instruction and this instruction is not pop (thus has value)
	if (insn_last_insn[ea] == 0 || ea == func->end_ea)
		return;
	std::vector <ea_t> childre_list= find_first_child_of(ea);
	x64_my_insn[ea2x64_my_insn[ea]].operand0 = "";
	x64_my_insn[ea2x64_my_insn[ea]].parameters0.clear();
	x64_my_insn[ea2x64_my_insn[ea]].operand1 = "";
	x64_my_insn[ea2x64_my_insn[ea]].parameters1.clear();
	insn_last_insn[ea] = 0;
	for (int index = 0;index < childre_list.size();index++)
	{
		x64_iterate_clean_x64_my_insn(childre_list[index],func);
	}
}

//We need to record for each conditional jump, the two destination and their relation ship with the flags.
void x64_analyze_conditional_jump(func_t* func)
{
	qstring Mnemq;
	std::string Mnem;
	qstring disasm;
	ea_t next_ea,far_ea;
	ea_t last_cmp_IR, next_key_IR, next_key_IR1;
	std::string disasm_str;
	for (ea_t ea = func->start_ea;ea < func->end_ea && ea != BADADDR; ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT))
	{
		print_insn_mnem(&Mnemq, ea);
		Mnem = Mnemq.c_str();
		if (Mnem.find('j') == 0 && Mnem!="jmp")//If the instruction is a conditional jump instruction.
		{
			generate_disasm_line(&disasm, ea, GENDSM_REMOVE_TAGS);
			disasm_str = disasm.c_str();
			int loc_position = disasm_str.find("loc_");
			far_ea = stoi(disasm_str.substr(loc_position + 4, disasm_str.length() - 1 - loc_position - 3),0,16);
			next_ea = find_code(ea, SEARCH_DOWN | SEARCH_NEXT);
			last_cmp_IR = x64_find_backward4cmp(ea,func);
			next_key_IR = x64_find_forward4key_IR(next_ea,func);
			next_key_IR1 = x64_find_forward4key_IR(far_ea,func);
			x64_generate_conditional_jump_map4between_insns(last_cmp_IR,ea, next_key_IR, next_key_IR1,Mnem);
			x64_generate_conditional_jump_map(last_cmp_IR, next_key_IR, next_key_IR1, Mnem);
		}
	}
}

//For one instruction, we just create a mapping between two addresses with corresponding flags.
void x64_generate_conditional_jump_map(ea_t ea, ea_t next_ea, ea_t far_ea, std::string Mnem)
{
	std::string key;
	char address1[10], address2[10], address3[10];
	if (Mnem == "jo")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"V==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"V==0" });
	}
	else if (Mnem == "jno")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"V==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"V==1" });
	}
	else if (Mnem == "js")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N==0" });
	}
	else if (Mnem == "jns")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N==1" });
	}
	else if (Mnem == "je"|| Mnem == "jz")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==0" });
	}
	else if (Mnem == "jne" || Mnem == "jnz")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==1" });
	}
	else if (Mnem == "jb" || Mnem == "jnae"||Mnem=="jc")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==0" });
	}
	else if (Mnem == "jnb" || Mnem == "jae" || Mnem == "jnc")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==1" });
	}
	else if (Mnem == "jbe" || Mnem == "jna")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==1 | Z==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==0 & Z==0" });
	}
	else if (Mnem == "ja" || Mnem == "jnbe")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"C==0 & Z==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"C==1 | Z==1" });
	}
	else if (Mnem == "jl" || Mnem == "jnge")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N!=V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N==V" });
	}
	else if (Mnem == "jge" || Mnem == "jnl")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"N==V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"N!=V" });
	}
	else if (Mnem == "jle" || Mnem == "jng")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==1 | N!=V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==0 & N==V" });
	}
	else if (Mnem == "jg" || Mnem == "jnle")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"Z==0 & N==V" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"Z==1 | N!=V" });
	}
	else if (Mnem == "jp" || Mnem == "jpe")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"P==1" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"P==0" });
	}
	else if (Mnem == "jnp" || Mnem == "jpo")
	{
		itoa(ea, address1, 16);
		itoa(far_ea, address2, 16);
		itoa(next_ea, address3, 16);
		key = std::string(address1)+"-->" + std::string(address2);
		conditional_jump_map.insert({ key,"P==0" });
		key = std::string(address1)+"-->" + std::string(address3);
		conditional_jump_map.insert({ key,"P==1" });
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
void x64_generate_conditional_jump_map4between_insns(ea_t last_cmp, ea_t jump_ea, ea_t next_IR, ea_t far_IR, std::string Mnem)
{
	for (ea_t index = get_first_cref_from(last_cmp);index < jump_ea && index != BADADDR; index = get_first_cref_from(index))
	{
		x64_generate_conditional_jump_map(index, next_IR, far_IR, Mnem);
	}
}