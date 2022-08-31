#include "../../Headers/IR/x64_IR_iterator.h"

bool x64_contain_iterators(ea_t ea)
{
	if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITER(") != -1)
		return true;
	if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find("ITER(") != -1)
		return true;
	return false;
}

bool x64_contain_iterators_v1(ea_t ea)
{
	if (x64_my_insn[ea2x64_my_insn[ea]].parameters0.find("loop_origin") != x64_my_insn[ea2x64_my_insn[ea]].parameters0.end())
		return true;
	return false;
}


void x64_iterator_handler(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type)
{
	
	/*if (is_iterator_source_insn(ea))
	{
		if (Mnem.find("add") != -1)
		{
			if (op1_type == 5 && op2_type == 0)//add reg,num
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "+" + x64_get_operand(ea, 1);
			else if (op2_type == 5)//add reg,reg,num
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "+" + x64_get_operand(ea, 2);
			else if (op2_type = 0)//add reg,reg/[]/string
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "+" + x64_my_insn[ea2x64_my_insn[ea]].operand1;
			else if (op2_type!=0)//add reg, reg, reg/[]/string
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "+" + x64_my_insn[ea2x64_my_insn[ea]].operand1;
		}
		else if (Mnem.find("sub") != -1)
		{
			if (op1_type == 5 && op2_type == 0)//add reg,num
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "-" + x64_get_operand(ea, 1);
			else if (op2_type == 5)//add reg,reg,num
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "-" + x64_get_operand(ea, 2);
			else if (op2_type = 0)//add reg,reg/[]/string
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "-" + x64_my_insn[ea2x64_my_insn[ea]].operand1;
			else if (op2_type != 0)//add reg, reg, reg/[]/string
				x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + "-" + x64_my_insn[ea2x64_my_insn[ea]].operand1;
		}
	}*/
	/*if (Mnem.find("mov") != -1 && right_op_is_iterator(ea))
	{ 
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + extract_iterator_var(ea, 1);
	}*/
	if (Mnem.find("mov") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 1);
	}
	else if (Mnem.find("lea") != -1 && right_op_contain_iterator(ea))
	{
		int left_bracket_index = x64_get_operand(ea, 1).find('[');
		if(left_bracket_index==-1)
			x64_my_insn_IR[ea2x64_my_insn[ea]]= x64_get_operand(ea, 0) + "="+ x64_get_operand(ea, 1);
		else
		{
			std::string tmp=x64_get_operand(ea, 1).replace(left_bracket_index, 1, "");
			int right_bracket_index = tmp.find(']');
			tmp = tmp.replace(right_bracket_index, 1, "");
			x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + tmp;
		}
	}
	/*else if (Mnem.find("test") != -1 && right_op_is_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = "if "+x64_get_operand(ea, 0) +"=="+ extract_iterator_var(ea, 1);
	}*/
	/*else if (Mnem.find("test") != -1 && left_op_is_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + extract_iterator_var(ea, 0)+ "==" + x64_get_operand(ea, 1);
	}*/
	else if (Mnem.find("test") != -1)
	{
		if (!right_op_contain_iterator(ea) && left_op_contain_iterator(ea))
		{
			if (x64_my_insn[ea2x64_my_insn[ea]].operand1 != "")
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + x64_my_insn[ea2x64_my_insn[ea]].operand1;
			else
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + x64_get_operand(ea,1);
		}
		else if (!left_op_contain_iterator(ea) && right_op_contain_iterator(ea))
		{
			if(x64_my_insn[ea2x64_my_insn[ea]].operand0!="")
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_my_insn[ea2x64_my_insn[ea]].operand0 + "==" + x64_get_operand(ea, 1);
			else
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea,0) + "==" + x64_get_operand(ea, 1);
		}
		else if (left_op_contain_iterator(ea) && right_op_contain_iterator(ea))
		{
			if (x64_get_operand(ea, 0) == x64_get_operand(ea, 1))
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "== 0";
			else x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + x64_get_operand(ea, 1);
		}
	}
	/*else if (Mnem.find("cmp") != -1 && right_op_is_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + extract_iterator_var(ea, 1);
	}
	else if (Mnem.find("cmp") != -1 && left_op_is_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + extract_iterator_var(ea, 0) + "==" + x64_get_operand(ea, 1);
	}*/
	else if (Mnem.find("cmp") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)))
	{
		if (!right_op_contain_iterator(ea) && left_op_contain_iterator(ea))
			if(x64_my_insn[ea2x64_my_insn[ea]].operand1!="")
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + x64_my_insn[ea2x64_my_insn[ea]].operand1;
			else
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + x64_get_operand(ea,1);
		else if (!left_op_contain_iterator(ea) && right_op_contain_iterator(ea))
			if(x64_my_insn[ea2x64_my_insn[ea]].operand0!="")
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_my_insn[ea2x64_my_insn[ea]].operand0 + "==" + x64_get_operand(ea, 1);
			else
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea,0) + "==" + x64_get_operand(ea, 1);
		else if (left_op_contain_iterator(ea) && right_op_contain_iterator(ea))
		{
			if (x64_get_operand(ea, 0) == x64_get_operand(ea, 1))
				x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "== 0";
			else x64_my_insn_IR[ea2x64_my_insn[ea]] = "if " + x64_get_operand(ea, 0) + "==" + x64_get_operand(ea, 1);
		}
	}
	else if (Mnem.find("xor") != -1 && right_op_contain_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 1) + "=0";
	}
	/*else if (Mnem.find("add") != -1 && right_op_is_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] =x64_get_operand(ea,0)+"="+x64_get_operand(ea, 0)+"+"+extract_iterator_var(ea, 1);
	}*/
	else if (Mnem.find("add") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "+"+x64_get_operand(ea, 1);
	}
	/*else if (Mnem.find("sub") != -1 && right_op_is_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "-" + extract_iterator_var(ea, 1);
	}*/
	else if (Mnem.find("sub") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "-"+x64_get_operand(ea, 1);
	}
	/*else if (Mnem.find("imul") != -1 && right_op_is_iterator(ea) && op2_type==0)
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "*" + extract_iterator_var(ea, 1);
	}*/
	else if (Mnem.find("imul") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)) && op2_type==0)
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "*" + x64_get_operand(ea, 1);
	}
	/*else if (Mnem.find("imul") != -1 && right_op_is_iterator(ea) && op2_type == 5)
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + extract_iterator_var(ea, 1) + "*" + x64_get_operand(ea, 2);
	}*/
	else if (Mnem.find("imul") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)) && op2_type == 5)
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 1) + "*" + x64_get_operand(ea, 2);
	}
	/*else if (Mnem.find("div") != -1 && x64_my_insn[ea2x64_my_insn[ea]].operand0.find("/ITERATOR")!=-1)
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = "eax=eax/" + extract_iterator_var(ea, 0);
	}*/
	else if (Mnem.find("div") != -1 && left_op_contain_iterator(ea))
	{
		x64_my_insn_IR[ea2x64_my_insn[ea]] = "eax=eax/" + x64_get_operand(ea, 0);
	}
	/*else if ((Mnem.find("rol") != -1 || Mnem.find("shl") != -1 || Mnem.find("sll") != -1 || Mnem.find("sal") != -1) && x64_my_insn[ea2x64_my_insn[ea]].operand0.find("<<ITERATOR") != -1)
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) +"="+ extract_iterator_var(ea, 0)+"<<"+x64_get_operand(ea, 1);
	}*/
	else if ((Mnem.find("rol") != -1 || Mnem.find("shl") != -1 || Mnem.find("sll") != -1 || Mnem.find("sal") != -1) && (left_op_contain_iterator(ea)))
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea,0) + "=" + x64_get_operand(ea, 0) + "<<" + x64_get_operand(ea, 1);
	}
	/*else if ((Mnem.find("ror") != -1 || Mnem.find("shr") != -1 || Mnem.find("srl") != -1 || Mnem.find("sar") != -1) && x64_my_insn[ea2x64_my_insn[ea]].operand0.find(">>ITERATOR") != -1)
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = extract_iterator_var(ea, 0) + "=" + extract_iterator_var(ea, 0) + ">>" + x64_get_operand(ea, 1);
	}*/
	else if ((Mnem.find("ror") != -1 || Mnem.find("shr") != -1 || Mnem.find("srl") != -1 || Mnem.find("sar") != -1) && left_op_contain_iterator(ea))
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + ">>" + x64_get_operand(ea, 1);
	}
	
	/*else if (Mnem.find("and") != -1 && right_op_is_iterator(ea))
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "&" + extract_iterator_var(ea, 1);
	}*/
	else if (Mnem.find("and") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)))
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "&" + x64_get_operand(ea, 1);
	}
	/*else if (Mnem.find("or") != -1 && right_op_is_iterator(ea))
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "|" + extract_iterator_var(ea, 1);
	}*/
	else if (Mnem.find("or") != -1 && (left_op_contain_iterator(ea) || right_op_contain_iterator(ea)))
	{
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "|" + x64_get_operand(ea, 1);
	}
	else if(Mnem.find("inc")!=-1)
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "+1";
	else if(Mnem.find("dec") != -1)
	x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_get_operand(ea, 0) + "=" + x64_get_operand(ea, 0) + "-1";
}

void x64_iterator_handler_v1(ea_t ea, std::string Mnem, int op0_type, int op1_type, int op2_type)
{
	//if(x64_my_insn[ea2x64_my_insn[ea]].parameters0.find("redundant")== x64_my_insn[ea2x64_my_insn[ea]].parameters0.end())
		x64_my_insn_IR[ea2x64_my_insn[ea]] = x64_my_insn[ea2x64_my_insn[ea]].operand0;
}

/*bool is_iterator_source_insn(ea_t ea)
{
	for (int i = 0;i < iter_source.size();i++)
	{
		if (iter_source[i] == ea)
		{
			return true;
		}
	}
	return false;
}*/

std::string extract_iterator_var(ea_t ea, int operand_num)
{
	int iterator_index, split=-1;
	if (operand_num == 0)
	{
		iterator_index = x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITERATOR");
		for (int i = iterator_index;i < x64_my_insn[ea2x64_my_insn[ea]].operand0.length();i++)
		{
			if (x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '+' || x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '-' || x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '*' || x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '/'\
				|| x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '>' || x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '<' || x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '|' || x64_my_insn[ea2x64_my_insn[ea]].operand0[i] == '&')
			{
				split = i;
				break;
			}
		}
		if (split == -1)
			split = x64_my_insn[ea2x64_my_insn[ea]].operand0.length();
		return x64_my_insn[ea2x64_my_insn[ea]].operand0.substr(iterator_index, split - iterator_index - 1);
	}
	else if (operand_num == 1)
	{
		iterator_index = x64_my_insn[ea2x64_my_insn[ea]].operand1.find("ITERATOR");
		for (int i = iterator_index;i < x64_my_insn[ea2x64_my_insn[ea]].operand1.length();i++)
		{
			if (x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '+' || x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '-' || x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '*' || x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '/'\
				|| x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '>' || x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '<' || x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '|' || x64_my_insn[ea2x64_my_insn[ea]].operand1[i] == '&')
			{
				split = i;
				break;
			}
		}
		if (split == -1)
			split = x64_my_insn[ea2x64_my_insn[ea]].operand1.length();
		return x64_my_insn[ea2x64_my_insn[ea]].operand1.substr(iterator_index, split - iterator_index - 1);
	}

}

bool right_op_is_iterator(ea_t ea)
{
	int iterator_index = x64_my_insn[ea2x64_my_insn[ea]].operand1.find("ITERATOR");
	if (iterator_index ==0)
	{
		std::string ITERATOR="ITERATOR";
		for (int i = iterator_index + ITERATOR.length() + 1;i < x64_my_insn[ea2x64_my_insn[ea]].operand1.length();i++)
		{
			if (isdigit(x64_my_insn[ea2x64_my_insn[ea]].operand1[i]))
				continue;
			else return false;
		}
		return true;
	}
	return false;
}

bool left_op_is_iterator(ea_t ea)
{
	int iterator_index = x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITERATOR");
	if (iterator_index == 0)
	{
		std::string ITERATOR = "ITERATOR";
		for (int i = iterator_index + ITERATOR.length() + 1;i < x64_my_insn[ea2x64_my_insn[ea]].operand0.length();i++)
		{
			if (isdigit(x64_my_insn[ea2x64_my_insn[ea]].operand0[i]))
				continue;
			else return false;
		}
		return true;
	}
	return false;
}

bool left_op_contain_iterator(ea_t ea)
{
	if (x64_my_insn[ea2x64_my_insn[ea]].operand0.find("ITERATOR") != -1)
		return true;
	return false;
}

bool right_op_contain_iterator(ea_t ea)
{
	if (x64_my_insn[ea2x64_my_insn[ea]].operand1.find("ITERATOR") != -1)
		return true;
	return false;
}