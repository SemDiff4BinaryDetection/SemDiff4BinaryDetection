from msynth import Simplifier
from miasm.expression.expression import Expr, ExprId, ExprInt, ExprMem
from formula_simplifier_lib import *
from similarity.text import find_next_operator,get_correspond_right_quotation,is_calling_subfunction,get_corresponding_left,extract_function_parameters, get_calling_subfunction_left_bracket,get_function_name
from pdb import set_trace as bp

BIT=32
ORACLE_PATH='oracle.pickle'
simplifier=Simplifier(ORACLE_PATH)
#priority: 1. * / << >>  & | ^ %
#          2. + -  
#          Note: -(...) or !(...) is deemed as an operand
#          So each formula must be in form: operand operator operand operator operand operator...
def simplify_formula(formula):
 #print("simplify_formula formula: ",formula)
 if formula.replace(' ','')=='':
  return ''
 global simplifier
 operator_operand_list=parse_opd_opt(formula)
 #print("simplify_formula formula: ",formula)
 #print("simplify_formula operator_operand_list:",operator_operand_list,"simplify_formula formula: ",formula)
 result=calculate(operator_operand_list)
 #print("simplify_formula formula: ",formula,"simplify_formula result=",result,"type=",type(result))
 result1=simplifier.simplify(result)
 #print("result1:",result1)
 #print("formula: ",formula)
 #print("simplify_formula simplified_result1=",result1,"result=",result,"simplify_formula formula: ",formula)
 return result1
 
#split string into following form:
# operand, operator, operand, operator......
# those operand and operator sequences are stored into operator_operand_list
# and return this list
def parse_opd_opt (formula):
 #print("parse_opd_opt",formula)
 operator_operand_list=[]
 index=0
 last_operand_start=0
 while index<len(formula):
  #print("parse_opd_opt index=",index,"/",len(formula))
  if formula[index]=='(':
   index1=index
   index=get_right_bracket_index(formula,index,'(')
   '''print("parse_opd_opt found ",formula[index1:index+1])
   if formula.find("UNKNOWN")!=-1:
    bp()'''
  elif formula[index]=='[':
   index=get_right_bracket_index(formula,index,'[')
   #print("[ hit, index=",index)
  elif formula[index]=='!':
   index+=1
   index=get_right_bracket_index(formula,index,'(')
  elif formula[index]=='-' and index==0:
   index+=1
   index=get_right_bracket_index(formula,index,'(')
  elif formula[index]=="I":
   if formula[index:index+4]=="ITER":
    index+=4
    index=get_right_bracket_index(formula,index,'(')
    #print(index)
  elif formula[index]=="U":
   if formula[index:index+7]=="UNKNOWN":
    index1=index
    index+=7
    #print(formula)
    index=get_right_bracket_index(formula,index,'(')
    #print("index=",index,"len(formula)=",len(formula))
    '''print("parse_opd_opt found ",formula[index1:index+1])
    bp()'''
  elif formula[index]=="b":
   if(formula[index:index+3]=="bsr" or formula[index:index+3]=="bsf"):
    index+=3
    index=get_right_bracket_index(formula,index,'(')
  elif formula[index]=='"':#If we encounter the string starting with " and end with "
    index=get_correspond_right_quotation(formula,index+1)+1
    #print("quotation hit, index=",index)
  elif formula[index]=='$':#Sometimes the label can start with a '$'
    index=find_next_operator(formula,index+1)
    if index==len(formula):
     index-=1
  elif is_calling_subfunction(formula,index):#If we encounter the RETURN_xxx() or [...]()   
    index1=get_calling_subfunction_left_bracket(formula,index) 
    index1=get_right_bracket_index(formula,index,'(')
    if index1==-1:
     index=find_next_operator(formula,index)      
  #elif formula[index]=='R':
  #  if formula[index:index+4]=="log2":
  #     index=get_right_bracket_index(formula,index+4,'(')
  if index>=len(formula)-1:
   operator_operand_list.append(formula[last_operand_start:])
   break
  if is_operator(formula[index]):
   operator_operand_list.append(formula[last_operand_start:index])
   #print("parse_opd_opt operand append ",formula[last_operand_start:index])
   operator=get_operator(formula,index)
   operator_operand_list.append(operator)
   #print("parse_opd_opt operator append ",operator)
   index+=len(operator)
   last_operand_start=index
  else:
   index+=1
  #print("last_operand_start="+formula[last_operand_start])
 operator_operand_list=normalize(operator_operand_list)
 #print("normalized!")
 #print("parse_opd_opt operator_operand_list",operator_operand_list)
 #operator_operand_list = list(filter(None, operator_operand_list))#Delete null strings such as null in ['','cmp','']
 for index in range(0,len(operator_operand_list),2):#Next, we further simplify each operand
  #print("parse_opd_opt index=",index,"len(operator_operand_list)=",len(operator_operand_list),"operator_operand_list[index]=",operator_operand_list[index],"operator_operand_list=",operator_operand_list)
  #bp()
  if operator_operand_list[index][0]=='(':
    operator_operand_list[index]=simplify_formula(operator_operand_list[index][1:-1])
  elif operator_operand_list[index][0]=='[':
    operator_operand_list[index]=ExprMem(simplify_formula(operator_operand_list[index][1:-1]),BIT)
  elif operator_operand_list[index][0]=='!':
   operator_operand_list[index]=~simplify_formula(operator_operand_list[index][2:-1])
  elif operator_operand_list[index].startswith("-("):
   operator_operand_list[index]=-simplify_formula(operator_operand_list[index][2:-1])
  elif operator_operand_list[index][0:4]=="ITER":
   #print("ITER!")
   if not really_has_this_char(operator_operand_list[index],'='):
    operator_operand_list[index]=ExprId("ITER("+str(simplify_formula(operator_operand_list[index][5:-1]))+")",BIT)
   elif really_has_this_char(operator_operand_list[index],'='):
    left_op=split_IR2two_parts(operator_operand_list[index][5:-1],'=')[0]
    right_op=split_IR2two_parts(operator_operand_list[index][5:-1],'=')[1]
    print("left_op=",left_op)
    print("right_op=",right_op)
    left_op=simplify_formula(left_op)
    right_op=simplify_formula(right_op)
    print(left_op)
    print(right_op)
    operator_operand_list[index]=ExprId("ITER("+"["+str(left_op)+"]="+str(right_op)+")",BIT)
  elif operator_operand_list[index][0:7]=="UNKNOWN":
    string=""
    operands=split_IR2two_parts(operator_operand_list[index][8:-1],',')
    #print("operands",operands)
    for item in operands:
     #print("item=",item)
     string+=str(simplify_formula(item))+","
    string="UNKNOWN("+string[:-1]+")"
    operator_operand_list[index]=ExprId(string,BIT)
  elif operator_operand_list[index][0:3]=="bsr":  
    operator_operand_list[index]=ExprId("bsr("+str(simplify_formula(operator_operand_list[index][4:-1]))+")",BIT)
  elif operator_operand_list[index][0:3]=="bsf":  
    operator_operand_list[index]=ExprId("bsf("+str(simplify_formula(operator_operand_list[index][4:-1]))+")",BIT)
  #elif operator_operand_list[index][0:4]=="log2":  
  #  operator_operand_list[index]=ExprId("log2("+str(simplify_formula(operator_operand_list[index][5:-1]))+")",BIT)
  elif is_calling_subfunction(operator_operand_list[index],0):
    print("parse_opd_opt is_calling_subfunction ",operator_operand_list[index])
    simplified_calling=recursive_simplify_calling(operator_operand_list[index],BIT)
    if simplified_calling!=[]:
     operator_operand_list[index]=simplified_calling
 return operator_operand_list

#recursively simplify the calling subfunction IR. For example, RETURN(RETURN(1+2+3,4+5),0,1) will be recursively simplified.
def recursive_simplify_calling(IR,BIT):
  right_bracket=IR.rfind(')')
  left_bracket=get_corresponding_left(IR,right_bracket)
  IR_left=IR[:left_bracket]
  func_name=get_function_name(IR_left)
  IR_right=IR[left_bracket+1:right_bracket]
  print("recursive_simplify_calling IR_right=",IR_right)
  parameters=extract_function_parameters(IR_right)
  simplified_parameters=[]
  for parameter in parameters:
    simplified_parameter=simplify_formula(parameter)
    simplified_parameters.append(simplified_parameter)
  return simplified_parameters
 
'''def get_function_name(func_name):
 if func_name.startswith("RETURN_"):
  return func_name
 elif func_name.find('[')!=-1:
  disp_struct=out_most_disp()
  disp_struct.disp=split_elements(func_name)
  disp_struct.shape=get_memory_store_shape(func_name)
  return disp_struct '''
    
#If string really contains this char rather than contain this char within a quotation or a bracket, return true.
def really_has_this_char(string,char):
 bracket_level=0
 #qutation_level=0
 i=0
 while i <len(string):
  #print("really_has_this_char i=",i,"char=",char,"bracket_level=",bracket_level,"string=",string)
  if string[i]=='"':
   i=string.find('"',i+1,len(string))+1
   continue
  elif string[i]=='(':
   bracket_level+=1
  elif string[i]==')':
   bracket_level-=1
  elif string[i]==char and bracket_level==0:
   return True
  i+=1 
 return False  
 
 
#If string really contains this string rather than contain this string within a quotation or a bracket, return true. 
def really_has_this_string(IR,substring):
 start_quotation=0
 end_quotation=0
 while start_quotation <len(IR):
  #print("really_has_this_char i=",i,"char=",char,"bracket_level=",bracket_level,"string=",string)
  if IR[start_quotation]=='"':
   end_quotation=IR.find('"',start_quotation+1,len(IR))+1
   IR=IR[:start_quotation]+IR[end_quotation:]
  start_quotation+=1 
 if substring in IR:
  return True
 return False

 
#Given a string in a form of UNKNOWN(,), split them into two parts. Note that any operand can contain sub ','. We need to ignore them. Also, given a string in a form of []="xxxx=xxxx,xxxxx", we need split it according to the first =.
def split_IR2two_parts(IR,split_char):
 result=[]
 real_comma_index=-1;
 bracket_level=0
 #qutation_level=0
 index=0
 while index <len(IR):
  #print("split_IR2two_parts index=",index)
  if IR[index]=='(':
   bracket_level+=1
  elif IR[index]==')':
   bracket_level-=1
  elif IR[index]=='"':
   index=IR.find('"',index+1,len(IR))+1
   continue
  elif IR[index]==split_char and bracket_level==0:
   real_comma_index=index
   break  
  index+=1
  
 if real_comma_index!=-1:#if we found the real comma which really seperates two operands insteand of being within some ()
  result.append(IR[:real_comma_index])
  result.append(IR[real_comma_index+1:])
 return result  
  
 
#priority: 1. * / << >>  & | ^ %
#          2. + -  
#          Note: -(...) or !(...) is deemed as an operand
#          So each formula must be in form: operand operator operand operator operand operator...
def calculate(operator_operand_list):
 #print("calculate operator_operand_list=",operator_operand_list)
 global simplifier
 for index in range(0,len(operator_operand_list),2):#Transform strings into Expr objects here
  if is_int(operator_operand_list[index]):
   operator_operand_list[index]=create_ExprInt(operator_operand_list[index],BIT)
  elif is_var(operator_operand_list[index]):
   operator_operand_list[index]=create_ExprID(operator_operand_list[index],BIT)
  elif is_qutation_string(operator_operand_list[index]):
   operator_operand_list[index]=create_ExprID(operator_operand_list[index],BIT)
  '''elif is_arm_ldr_label(operator_operand_list[index]):
   operator_operand_list[index]=create_ExprID(operator_operand_list[index],BIT)'''
   
  
   
 while len(operator_operand_list)>1:
  index=select_operator_decende_priority(operator_operand_list)
  #print(operator_operand_list[index-1],operator_operand_list[index+1])
  result=triple_calculate(operator_operand_list[index-1],operator_operand_list[index],operator_operand_list[index+1])
  operator_operand_list.pop(index-1)
  operator_operand_list.pop(index-1)
  operator_operand_list[index-1]=result
 #print("calculate",operator_operand_list[0])
 return operator_operand_list[0]
   
def select_operator_decende_priority(operator_operand_list):
 for index in range(1,len(operator_operand_list),2):
   if operator_operand_list[index] in ['*', '/', "<<", ">>",  '&', '|', '^', '%']:
    return index
 for index in range(1,len(operator_operand_list),2):
   if operator_operand_list[index] in ['+', '-']:
    return index
    
def triple_calculate(operand0,operator,operand1):
  #print("triple_calculate operand0:",operand0)
  #print("triple_calculate type(operand0):",type(operand0))
  #print("triple_calculate operator:",operator)
  #print("triple_calculate operand1:",operand1)
  #print("triple_calculate type(operand1):",type(operand1))
  if operator=='+':
   expression=operand0+operand1
  elif operator=='-':
   expression=operand0-operand1
  elif operator=='*':
   expression=operand0*operand1 
  elif operator=='/':
   #If two operands are int, we calculate. Otherwise, since msynth does not support simplify ExprId/ExprId or ExprOp/ExprOp, we directly convert it (../..) into a new ExprId
   if type(operand0)==ExprInt and type(operand1)==ExprInt:
    if operand1!=create_ExprInt("0",BIT):#not zero division
     expression=operand0//operand1  
    elif operand1==create_ExprInt("0",BIT):#zero division
     expression=create_ExprInt("0",BIT)
   else:
    expression=create_ExprID(str(operand0)+'/'+str(operand1),BIT)
  elif operator=="<<":
   expression=operand0<<operand1
  elif operator==">>":
   expression=operand0>>operand1
  elif operator=='&':
   expression=operand0&operand1
  elif operator=='|':
   expression=operand0|operand1
  elif operator=='^':
   expression=operand0^operand1
  elif operator=='%':
   expression=operand0%operand1
  return expression 
'''def get_BIT():
 global BIT
 if is_ARM():
  BIT=32
 elif is_x64():
  BIT=64
  '''

  
def test_main():
 while True:
  formula=input("Please enter the expression:")
  result=simplify_formula(formula)
  print(result)
 
#test_main()

  
#/c/Program Files/IDA Pro 7.5 SP3/IDA SDK and Tools/idasdk75/plugins/zianliu_binary_similarity/deep first/x64/Debug/IR_output.txt
#/c/Program Files/IDA Pro 7.5 SP3/IDA SDK and Tools/idasdk75/plugins/zianliu_binary_similarity/deep first/x64/Debug/test_arm1/IR_output1.txt