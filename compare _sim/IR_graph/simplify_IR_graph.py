import networkx as nx
from formula_simplifier import simplify_formula,split_IR2two_parts,really_has_this_char,really_has_this_string,get_function_name
from formula_simplifier_lib import is_operator
from similarity.text import extract_function_parameters, get_corresponding_right_bracket, is_int, to_int,get_correspond_right_quotation,get_correspond_left_quotation
import re
from similarity.text import IR_memory_store,IR_cmp,IR_expression,IR_calling,out_most_disp,IR_out_most_cmp,cmp_stru,get_first_non_alpha,split_elements,put_bracket_disp_in_each_elelment,add_to_each_elelment,get_corresponding_left
from pdb import set_trace as bp
import re

#Some structures to store instructions in a more organized way.


#4 types of IR:
#              1.memory location store
#              2.if else statement
#              3.loop instructions
#                -- with "=" connected to two expressions
#                -- without "=", just an expression 
#              4.calling function
def simplify_IR_graph(G):
 item=0
 #for node in G.nodes():
  #print(node)
 for node in G.nodes():
  if node!=0:
   print("simplify_IR_graph node:",node)
   #print("IR: ",G.nodes[node]['IR'])
   for index in range(0,len(G.nodes[node]['IR'])):
    type_of_IR=get_IR_type(G.nodes[node]['IR'][index])
    G.nodes[node]['IR'][index]=process_IR_type(G.nodes[node]['IR'][index],type_of_IR)
   G.nodes[node]['IR']=list(dict.fromkeys(G.nodes[node]['IR']))
   G.nodes[node]['mode']=type_of_IR
   print(item,"/",len(G.nodes()))
   item+=1
 return G   
 
#4 types of IR to process:
#              1....=...
#              2.if...==...
#              3....
#              4.function(..,..,..)
#              5.return ...
def get_IR_type(IR):
 IR=IR.strip()
 if really_has_this_char(IR,'=') and not really_has_this_string(IR,"=="):
  return 1
 elif is_call_insn(IR):
  return 4
 elif IR.find(" and ")!=-1 or IR.find(" test ")!=-1 or IR.find(" cmp ")!=-1 or IR.find(" or ")!=-1\
 or IR.find(" xor ")!=-1 or IR.find(" add ")!=-1 or IR.find(" adc ")!=-1 or IR.find(" sub ")!=-1\
 or IR.find(" sbb ")!=-1:#In case adc is in return_12adc23
  return 2
 elif IR.find("return")!=-1:
  return 5
 else:
  return 3 
  
#If has really '=' symbol, return true. otherwise return false.
'''def has_equation_sysmbol(string):
 if string.find("]=")!=-1:
  return True
 elif string.find("])=")!=-1:
  return True
 return False'''
 
#4 types of IR to process:
#              1....=...
#              2.if...==...
#              3....
#              4.function(..,..,..)
def process_IR_type(IR,mode):
 IR=last_clean_IR(IR)
 print("process: ",IR, "mode ", mode)
 if mode==1:#Memory storing mode
  '''if IR.strip().startswith("ITER("):#if IR is ITER(...=...), then it us a special situation, need process exceptionally
   start_index=IR.find("ITER(")
   start_index+=5
   end_index=IR.rfind(")")
   IR=IR[start_index:end_index]
   IR_left=IR.split("=")[0]
   IR_left=simplify_formula(IR_left)
   IR_right=IR.split("=")[1]
   IR_right=simplify_formula(IR_right)
   return "ITER("+str(IR_left)+"="+str(IR_right)+")"'''
  #else:#if IR is only ...=...
  IR_left=split_IR2two_parts(IR,'=')[0]#IR.split("=")[0]
  #print("IR_left:",IR_left)
  IR_left=str(simplify_formula(IR_left))
  IR_right=split_IR2two_parts(IR,'=')[1]#IR.split("=")[1]
  #print("mode 1 right, IR_right",IR_right)
  IR_right=str(simplify_formula(IR_right))
  struct=IR_memory_store()
  struct.left=out_most_disp()
  struct.left.disp=split_elements(IR_left)
  struct.left.shape=get_memory_store_shape(IR_left)
  elements=split_elements(IR_right)
  #print("mode 1 right, elements:",elements)
  for index in range(0, len(elements)):
   if type(elements[index])==list:
    disp=elements[index]
    elements[index]=out_most_disp()
    elements[index].disp=disp
    elements[index].shape=get_memory_store_shape(str(disp))
  struct.right=elements  
  print("process_IR_type simplified IR:",str(IR_left),"=",str(IR_right))
  return struct
 elif mode==2:#comparing instruction mode
  ''' IR_left=IR.split("==")[0].split("if")[1]
  IR_right=IR.split("==")[1]
  IR_left=simplify_formula(IR_left)
  IR_right=simplify_formula(IR_right)
  return "if "+str(IR_left)+"=="+str(IR_right)'''
  out_most_cmp=IR_out_most_cmp()#The resulting structure for this cmp instruction should be a IR_out_most_cmp structure.
  cmp_stru1=get_cmp_stru(IR)#Translate this cmp structrue as a cmp_stru
  
  #Assign values from cmp_stru to IR_out_most_cmp structure.
  out_most_cmp.left=cmp_stru1.left
  out_most_cmp.Mnem=cmp_stru1.Mnem
  out_most_cmp.right=cmp_stru1.right
  #Get all the comparing instructions in this cmp_stru structure recursively.
  out_most_cmp.compare_lists=get_cmp_lists(cmp_stru1)
  #print("cmp_stru1.left=",cmp_stru1.left)
  #print("cmp_stru1.Mnem=",cmp_stru1.Mnem)
  #print("cmp_stru1.right=",cmp_stru1.right)
  #print("compare_lists")
  for each_cmp in get_cmp_lists(cmp_stru1):
   print(each_cmp.left,each_cmp.Mnem,each_cmp.right)
  #bp()
  return out_most_cmp
 elif mode==3:#Expression mode
  IR=str(simplify_formula(IR))
  struct=IR_expression()
  elements=split_elements(IR)
  for index in range(0,len(elements)):
   if type(elements[index])==list:
    disp=elements[index]
    elements[index]=out_most_disp()
    elements[index].disp=disp
    elements[index].shape=get_memory_store_shape(str(disp))
  struct.elements=elements
  print("process_IR_type simplified IR:",str(IR))
  return struct
 elif mode==4:#Calling subroutine mode
  struct=IR_calling()
  struct.parameters=[]
  #print("before simplify ",IR)
  if re.match(r"^\s*$",IR[IR.find('(')+1:IR.rfind(')')])!=None:
   #print("contains no parameters!")
   struct.func_name=get_function_name(IR[:IR.find('(')])
   return struct
   #return IR
  right_bracket=IR.rfind(')')
  left_bracket=get_corresponding_left(IR,right_bracket)
  IR_left=IR[:left_bracket]
  struct.func_name=get_function_name(IR_left)
  IR_right=IR[left_bracket+1:right_bracket]
  parameters=extract_function_parameters(IR_right)
  #print(parameters)
  for index in range(0,len(parameters)):
   #print(parameters[index])
   if parameters[index].find('"')!=-1:
    continue
   parameters[index]=str(simplify_formula(parameters[index]))  
   #print(parameters[index])
  #print(parameters)
  #IR=IR_left+"("
  for index in range(0,len(parameters)):
   parameters[index]=split_elements(parameters[index])
   #Now we need to transfer the out most list type within the string into out_most_disp type.
   for index1 in range(0,len(parameters[index])):
    if type(parameters[index][index1])==list:
      disp=parameters[index][index1]
      parameters[index][index1]=out_most_disp()
      parameters[index][index1].disp=disp
      parameters[index][index1].shape=get_memory_store_shape(str(disp))  
   struct.parameters.append(parameters[index])
  #IR=IR[:-1]+')'
  print("process_IR_type simplified IR",IR)
  return struct
  #return IR
 elif mode==5:
  index=IR.find("return ")
  IR=IR[index+7:]  
  return "return "+str(simplify_formula(IR))
  

#4 types of IR to process:
#              1....=...
#              2.if...==...
#              3....
#              4.function(..,..,..)
#We process each IR into a list of string for later use in minhash comparison
def process_IR_type_hash_split(IR,mode):
 IR=first_clean_IR(IR)
 IR=last_clean_IR(IR)
 print("process: ",IR, "mode ", mode)
 if mode==1:#Memory storing mode
  IR_left=split_IR2two_parts(IR,'=')[0]#IR.split("=")[0]
  #print("IR_left:",IR_left)
  IR_left=str(simplify_formula(IR_left))
  #print("IR_left:",IR_left)
  IR_right=split_IR2two_parts(IR,'=')[1]#IR.split("=")[1]
  #print("IR_right:",IR_right)
  IR_right=str(simplify_formula(IR_right))
  #print("IR_right:",IR_right)
  left_list=split_elements(IR_left)
  #print("left_list=",left_list)
  right_list=split_elements(IR_right)
  #print("right_list=",right_list)
  #print("mode 1 right, elements:",elements)
  #print("process_IR_type_hash_split left_string=",left_list)
  left_list=put_bracket_disp_in_each_elelment(left_list)
  right_list=put_bracket_disp_in_each_elelment(right_list)
  left_list=add_to_each_elelment('r',left_list,"=")
  right_list=add_to_each_elelment('l',right_list,"=")
  print("process_IR_type simplified IR:",left_list+right_list)
  return left_list+right_list
 elif mode==2:#comparing instruction mode
  cmp_lists=get_cmp_lists1(IR)
  result_list=[]
  #print("process_IR_type_hash_split result_list=",result_list)
  for each_cmp in cmp_lists:
   if len(each_cmp)==3:
    left_string,Mnem,right_string=each_cmp[0],each_cmp[1],each_cmp[2]
   else:#If Mnem can not recongnize
    continue
   left_string=split_elements(str(simplify_formula(left_string)))
   right_string=split_elements(str(simplify_formula(right_string)))
   #print("process_IR_type_hash_split left_string=",left_string)
   left_string=put_bracket_disp_in_each_elelment(left_string)
   right_string=put_bracket_disp_in_each_elelment(right_string)
   left_string=add_to_each_elelment('l',left_string,Mnem)
   right_string=add_to_each_elelment('l',right_string,Mnem)
   result_list+=left_string+right_string
  #bp()
  print("process_IR_type simplified IR:",result_list)
  return result_list
 elif mode==3:#Expression mode
  IR=str(simplify_formula(IR))
  elements=split_elements(IR)
  elements=put_bracket_disp_in_each_elelment(elements)
  print("process_IR_type simplified IR:",elements)
  return elements
 elif mode==4:#Calling subroutine mode
  #print("before simplify ",IR)
  if re.match(r"^\s*$",IR[IR.find('(')+1:IR.rfind(')')])!=None:
   #print("contains no parameters!")
   func_name=get_function_name(IR[:IR.find('(')])
   return [func_name]
   #return IR
  right_bracket=IR.rfind(')')
  left_bracket=get_corresponding_left(IR,right_bracket)
  IR_left=IR[:left_bracket]
  func_name=get_function_name(IR_left)
  IR_right=IR[left_bracket+1:right_bracket]
  print("process_IR_type_hash_split IR_right",IR_right)
  parameters=extract_function_parameters(IR_right)
  #print("process_IR_type_hash_split parameters=",parameters)
  for index in range(0,len(parameters)):
   #print(parameters[index])
   if parameters[index].find('"')!=-1:
    continue
   parameters[index]=str(simplify_formula(parameters[index]))  
   #print(parameters[index])
  #print(parameters)
  #IR=IR_left+"("
  for index in range(0,len(parameters)):
   parameters[index]=split_elements(parameters[index])
   parameters[index]=put_bracket_disp_in_each_elelment(parameters[index])
   parameters[index]=add_to_each_elelment('l',parameters[index],func_name+"(")
  return_list=[]
  for parameter in parameters:
   return_list+=parameter
  print("process_IR_type simplified IR",return_list)
  return return_list
  #return IR
 elif mode==5:
  index=IR.find("return ")
  IR=IR[index+7:]  
  return_list=split_elements(str(simplify_formula(IR)))
  return_list=add_to_each_elelment('l',right_list,"return")
  return return_list
  
  
#Given a cmp IR, return all the comparing instructions within it. e.g., ((4 ADD VAR0) OR (5 TEST 0))-->[(4 ADD VAR0),(5 TEST 0)]
def get_cmp_lists1(IR):
 print("get_cmp_lists1 IR=",IR)
 left_string,Mnem,right_string=split_cmp_IR(IR)
 if left_string==None and Mnem==None and right_string==None:#If Mnem can not recongnize
  return []
 if is_cmp_IR(left_string): #If left hand side is a recursive cmp instruction, dig into it.
  left=get_cmp_lists1(left_string)
 else:#If left is string.
  left=[left_string]
  
 if is_cmp_IR(right_string): #If left hand side is a recursive cmp instruction, dig into it.
  right=get_cmp_lists1(right_string)
 else:#If left is string.
  right=[right_string]
  
 print("get_cmp_lists1 left_string=",left_string,"right_string=",right_string) 
 if not is_cmp_IR(left_string) and not is_cmp_IR(right_string): #if left and right both not nested, e.g., 3 CMP 5
  result_list=[]
  result_list.append(left_string)
  result_list.append(Mnem)
  result_list.append(right_string)
  print("get_cmp_lists1 both not IR cmp")
  return [result_list]
 
 elif is_cmp_IR(left_string) and is_cmp_IR(right_string): #if left and right both nested, e.g., (3 ADD 5) OR (5 SUB 5)
  result_list=[]
  for item in left:
   result_list.append(item)
  for item in right:
   result_list.append(item)
  print("get_cmp_lists1 both IP cmp")
  return result_list
 
 elif is_cmp_IR(left_string) and not is_cmp_IR(right_string):#One side is nested, another is not nested
  result_list=[]
  for item in left:
   result_list.append(item)
  print("get_cmp_lists1 left is IR cmp")
  return result_list
 elif not is_cmp_IR(left_string) and is_cmp_IR(right_string):#One side is nested, another is not nested
  result_list=[]
  for item in right:
   result_list.append(item)
  print("get_cmp_lists1 right is IR cmp")
  return result_list
  
def is_call_insn(IR):
 #print("IR",IR)
 right_bracket=IR.rfind(')')
 left_bracket=get_corresponding_left(IR,right_bracket)
 #print("left_bracket ",left_bracket)
 if right_bracket==-1 or left_bracket==-1:#Do not even have out most left/right brackets
  return False
 #elif IR[left_bracket:right_bracket].find(',')!=-1:
 # return True
 else:#Have the out most left and right brackets.
  string=IR[:left_bracket]
  #print("is_cal_insn:",string)
  if string=="":
   return False
  if string.find("RETURN_")==0:
   return True
  elif is_function_name(string):
   return True
  elif is_expression(string):
   #print("is_expression!")
   return True
  elif is_quotation(string):
   return True
 return False
 
def is_function_name(string):
 for char in string:#If the string contains operator, then it is not an expression
  if is_operator(char) or char=='[' or char==']' or char=='(' or char==')':
   return False  
 return True  
 
#We decide this is an expression if the character before the left bracket is like a string. If it is any operator, this means that this is like " +()", which is not a calling pattern.
def is_expression(string):
 #print("string:{"+string.replace(" ",'')+"}")
 last_valid_char=string.replace(" ",'')[-1]
 first_valid_char=string.replace(" ",'')[0]
 if string.replace(" ",'')=="ITER" or string.replace(" ",'')=="UNKNOWN":
  return False
 if last_valid_char==']' and first_valid_char=='[':#string in the form of []
  return True
 elif last_valid_char==')':
  if first_valid_char=='(':#string in the form of ()
    return True
  elif string.replace(" ",'')[:8]=="UNKNOWN(":
    return True
 return False
 
#Decide whether a string starts and ends with "
def is_quotation(string): 
 string=string.replace(" ",'')
 #print("is_quotation string=",string)
 if string[0]=='"' and string[-1]=='"':
  if string.count('"')==2:
   return True
 return False  
   
 
#Some IR might still have unprocessed value such as var_, arg for some reason. We clean up them here.
def last_clean_IR(IR):
 #print("last_clean_IR IR",IR)
 if IR.find("var_")!=-1:
  IR=IR.replace("var_","-")
 if IR.find("arg_")!=-1:
  IR=IR.replace("arg_",'')
 if IR.find("---")!=-1:
  IR=IR.replace("---",'-')
 if IR.find("+-")!=-1:
  IR=IR.replace("+-",'-')
 if IR.find("--")!=-1:
  IR=IR.replace("--",'+')
 if IR.find(".8")!=-1:
  IR=IR.replace(".8","")
 if IR.find(".16")!=-1:
  IR=IR.replace(".16","")
 if IR.find(".32")!=-1:
  IR=IR.replace(".32","")
 if IR.find(".64")!=-1:
  IR=IR.replace(".64","")
 if IR.find(".128")!=-1:
  IR=IR.replace(".128","")
 return IR

#Abstract the memory shape of [[base+3]+4] into [[]]
def get_memory_store_shape(memory_address):
 shape=""
 for char in memory_address:
  if char=='[' or char==']':
   shape+=char
 return shape  
 
  
#Given an IR string, translate it into a cmp_stru structure. If its right or left part contains recursive comparison, we recursively translate them.
def get_cmp_stru(IR):
 result=cmp_stru()
 left_string,result.Mnem,right_string=split_cmp_IR(IR)
 if left_string==None and result.Mnem==None and right_string==None:#If Mnem can not recongnize
  result.left=None
  result.Mnem=""
  result.right=None
  return result
 if is_cmp_IR(left_string): #If left hand side is a recursive cmp instruction, dig into it.
  result.left=get_cmp_stru(left_string)
 else:#If left is string.
  print("left_string",left_string,"type:",type(left_string))
  if left_string.strip()=="":#If the left part is null, e.g., (and-1)
   result.left=None
  elif is_int(left_string.strip()):#If right string is an integer
    result.left=to_int(left_string.strip()) 
  else:#If the left part is not null, e.g., (and-1)
   #result.left=split_elements(str(simplify_formula(left_string)))
   simplified_left_IR=str(simplify_formula(left_string))
   result.left=out_most_disp()
   result.left.disp=split_elements(simplified_left_IR)
   result.left.shape=get_memory_store_shape(simplified_left_IR)
   
  
 if is_cmp_IR(right_string): #If right hand side is a recursive cmp instruction, dig into it.
  result.right=get_cmp_stru(right_string)
 else:#If right is a string. Now there are two cases: 1. right is just an expression. 2. right is like cmpne var4,5. For the second case we need to split ','.
  #print("get_cmp_stru IR:",IR)
  print("right_string=",right_string,"type=",type(right_string))
  if really_has_this_char(right_string,','):#If right part is like cmpne var4,5.
   first_item=right_string.split(',')[0]
   if first_item.strip()!="":#first item in the ...,... string is not null
    simplified_first_item=split_elements(str(simplify_formula(first_item)))
   else:#first item in the ...,... string is null
    simplified_first_item=[]
   second_item=right_string.split(',')[1]
   simplified_second_item=split_elements(str(simplify_formula(second_item)))
   #Now concatenate first and second items into result.right
   result.right=[simplified_first_item,',',simplified_second_item]
  else:#If right part is just an expression, no ',' i.e., not like cmpne var4,5.
   if right_string.strip()=="":#If right_string is null
    result.right=None
   elif is_int(right_string.strip()):#If right string is an integer
    result.right=to_int(right_string.strip())
    #print("get_cmp_stru result.right=",result.right)
    #bp()
   else:#If right_string not null
    #result.right=split_elements(str(simplify_formula(right_string)))
    simplified_right_IR=str(simplify_formula(right_string))
    result.right=out_most_disp()
    result.right.disp=split_elements(simplified_right_IR)
    result.right.shape=get_memory_store_shape(simplified_right_IR)
 return result 
 
#Given an IR string, split its right part, Mnem, and left part.
def split_cmp_IR(IR):
 IR=IR.strip()
 Mnem,Mnem_index=get_cmp_Mnem(IR.lower())
 if Mnem==None and Mnem_index==None:#If Mnem can not recongnize
  return None,None,None
 left_string=IR[:Mnem_index]
 left_bracket=left_string.find('(')
 left_string=left_string[left_bracket+1:]
 
 right_string=IR[Mnem_index+len(Mnem):]
 right_bracket=right_string.rfind(')')
 right_string=right_string[:right_bracket]
 print("split_cmp_IR","IR=",IR, "left_string=",left_string,"Mnem=",Mnem,"right_string=", right_string)
 
 if really_has_this_char(left_string,'='):
  left_string=split_IR2two_parts(left_string,'=')[1]
 if really_has_this_char(right_string,'='):
  right_string=split_IR2two_parts(right_string,'=')[1]
 return left_string,Mnem,right_string
 
#Find the IR's comparing Mnem and its indexes. The given IR is all turned to lower case.
def get_cmp_Mnem(IR):
 matches=['cmp','test','add','adc','sub','sbb','and','xor','or','cmov','mov','set'] 
 #We firstly delete all the () including '(' and ')'. After this, if we find one match, that is the Mnem
 outmost_left_bracket=IR.find('(')
 outmost_right_bracket=IR.rfind(')')
 print("get_cmp_Mnem",IR)
 IR='('+delete_IR_brackets(IR[outmost_left_bracket+1:outmost_right_bracket])+')'
 print("get_cmp_Mnem",IR)
 for word in matches:
  if IR.find(word)!=-1:
   if(IR[IR.find(word)-1]!=' ' or IR[IR.find(word)+len(word)]!=' '):#If the found adc is within RETURN_92adc
    break
   complete_Mnem=get_complete_Mnem(IR.find(word),word,IR)#For some case, we might hit a 'cmp' while the actual Mnem is like cmpne etc.
   print("get_cmp_Mnem IR:",IR,"complete_Mnem:",complete_Mnem,"IR.find(word)",IR.find(word))
   return complete_Mnem,IR.find(word)
 return None,None#If Mnem can not recongnize
   
def is_cmp_IR(IR):
 matches=[' cmp ',' test ',' add ',' adc ',' sub ',' sbb ',' and ',' xor ',' or ',' mov ',' set '] 
 return any(cmp in IR.lower() for cmp in matches)
  
#Given a cmp_stru structure, return all the comparing instructions within it.
def get_cmp_lists(cmp_stru1):
 result_list=[]
 if type(cmp_stru1.left)==cmp_stru:#If left part is cmp_stru structure, concatenate all its contents.
  left_result_list=get_cmp_lists(cmp_stru1.left)
  for item in left_result_list:
   result_list.append(item)
 if type(cmp_stru1.right)==cmp_stru:#If left part is cmp_stru structure, concatenate all its contents.
  right_result_list=get_cmp_lists(cmp_stru1.right)
  for item in right_result_list:
   result_list.append(item)
 if (type(cmp_stru1.left)==out_most_disp or type(cmp_stru1.left)==int) and (type(cmp_stru1.right)==out_most_disp or type(cmp_stru1.right)==int):#If this cmp_stru is the bottom level, i.e., right and left sides are all out_most_disp type.
  result_list.append(cmp_stru1)
 return result_list
 
  
#Replace all the part within () including '(' and ')' with whitespace of the same length
def delete_IR_brackets(IR):
 #print("delete_IR_brackets IR=",IR)
 index=0
 while index<len(IR):
  if IR[index]=='(':
   #print("delete_IR_brackets index=",index)
   right_bracket=get_corresponding_right_bracket(IR,index)
   IR=IR[:index]+' '*(right_bracket-index+1)+IR[right_bracket+1:]#Delete the ()
   index+=1
  elif IR[index]=='"':
   index=get_correspond_right_quotation(IR,index+1)+1
  else:
   index+=1  
 return IR  
 
#For some case, we might hit a 'cmp' while the actual Mnem is like cmpne etc. We need to extract this actual Mnem. 
def get_complete_Mnem(word_start_index,word,IR):
 arm_suffix=['eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le']
 if IR[word_start_index+len(word):word_start_index+len(word)+2] in arm_suffix:#Has arm suffix
  return word+IR[word_start_index+len(word):word_start_index+len(word)+2] 
 else:
  x86_word=IR_contains_x86_suffix_after_word(word_start_index,word,IR)
  if x86_word!=None:#Has x86 suffix
   return x86_word
  return word
  
def IR_contains_x86_suffix_after_word(word_start_index,word,IR):
 x86_suffix=['o','no','s','ns','e','z','ne','nz','b','nae','c','nb','ae','nc','be','na','a',\
 'nbe','l','nge','ge','nl','le','ng','g','nle','p','pe','np','po','cxz','ecxz']
 index1=get_first_non_alpha(IR,word_start_index+len(word))#get the end index of this Mnem +1
 for suffix in x86_suffix:
  #print("IR_contains_x86_suffix_after_word IR[word_start_index+len(word):index1]:",IR[word_start_index+len(word):index1],"suffix",suffix)
  if IR[word_start_index+len(word):index1]==suffix:
   return word+suffix
 return None  
 
#For better hash comparison. we firstly unify all RETURN_... ti RETURN_, then reserve VAR0-VAR4, and unify all VARn to VAR
def first_clean_IR(IR):
 result_IR1=re.sub('RETURN[_0-9A-F]*',"RETURN_",IR)
 result_IR2=re.sub('VAR[5-9]','VAR',result_IR1)
 result_IR2=re.sub('VAR\d\d+','VAR',result_IR2)
 return result_IR2