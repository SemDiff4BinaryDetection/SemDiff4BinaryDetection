import re
from miasm.expression.expression import Expr, ExprId, ExprInt, ExprMem


def normalize(operator_operand_list):
 for index in range(0,len(operator_operand_list),2):
  #print(str(index)+"/"+str(len(operator_operand_list)))
  operator_operand_list[index]=operator_operand_list[index].strip()
  if operator_operand_list[index].find("var_")==0:
   operator_operand_list[index]="(-("+operator_operand_list[index][4:]+"))"
  elif operator_operand_list[index].find("arg_")==0:
   operator_operand_list[index]=operator_operand_list[index][4:]
 return operator_operand_list
 
def is_int(string):
 if type(string)==str:
  if string.isnumeric():
   return True
  elif re.match(r'^[0-9A-Fa-f]+[h]*$',string)!=None:
   return True
  elif re.match(r'^0x[0-9A-Fa-f]+$',string)!=None:
   return True
 return False
  
def is_var(string):
 if type(string)==str:
  if string.find("VAR")==0:
   return True
  elif string.find("RETURN_")==0:
   return True
  elif string.find("ITVAR")==0:
   return True
  elif re.match(r'^[a-zA-Z0-9_]+$',string)!=None:#form like "abcd123"
   return True
  elif re.match(r'^[$]*[a-zA-Z0-9_]+.[a-zA-Z0-9_]+$',string)!=None:#form like "abcd123.abcd123"
   return True
 return False
 
def is_qutation_string(string):
 if type(string)==str:
  if string[0]=='"' and string[-1]=='"':
   return True
 return False
 
'''def is_arm_ldr_label(string):
 if type(string)==str:
  if string[0:2]=="=(":
   return True
 return False  '''
 
 
def create_ExprInt(string,BIT):
 v=ExprInt(to_int(string),BIT)
 return v
 
def create_ExprID(string,BIT):
 v=ExprId(string,BIT)
 return v
 
def to_int(string):
 if string[-1]=='h':
  return int(string[:-1],16)
 elif string.isnumeric():
  return int(string)
 else:
  return int(string,16)
  
def is_operator(char):
 if char=='+' or char=='-' or char=='*' or char=='/' or char=='<' or char=='>' or char=='&' or char=='|' \
 or char=='^'  or char=='%':
  return True
 return False
 
def get_operator(formula,index):
 if formula[index]=='+':
  return '+'
 elif formula[index]=='-':
  return '-'
 elif formula[index]=='*':
  return '*'
 elif formula[index]=='/':
  return '/'
 elif formula[index]=='<':
  return "<<"
 elif formula[index]=='>':
  return ">>"
 elif formula[index]=='&':
  return '&'
 elif formula[index]=='|':
  return '|'
 elif formula[index]=='^':
  return '^'
 elif formula[index]=='%':
  return '*'
 
#Start_index is the first character after the first '"'. We need to find the corresponding ending quotation.
def get_correspond_right_quotation(formula,start_index):
 for index in range(start_index,len(formula)):
  if formula[index]=='"':
   return index
 return len(formula)-1 
 
def get_right_bracket_index(formula,index,mode):
 level=1
 if mode=='(':
  left_notation='('
  right_notation=')'
 elif mode=='[':
  left_notation='['
  right_notation=']'
 #print("")
 i=index+1
 while i <len(formula):
  #print(formula[i])
  if formula[i]==left_notation:
   level+=1
  elif formula[i]==right_notation:
   level-=1
  elif formula[i]=='"':
   i=get_correspond_right_quotation(formula,i+1)
  if level==0:
   return i
  i+=1 
 return -1  
   
  

 