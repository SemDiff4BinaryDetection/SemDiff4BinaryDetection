import re
from difflib import SequenceMatcher
#from .learn_variable_meaning import *
ACCEPT_TEXTUAL_THRESHOLD=0
from pdb import set_trace as bp

class IR_memory_store:
 def _init_(self):
  self.left=out_most_disp() #Memory address
  self.right=[] #Value
  
 
class IR_cmp:
 def _init_(self):
  self.left=[]
  self.Mnem=""
  self.right=[]

class IR_expression:
 def _init_(self):
  self.elements=[] #Each word in the expression 

class IR_calling:
 def _init_(self):
  self.func_name=None
  self.parameters=[]

class IR_out_most_cmp:#This is the out most compare structire.
 def _init_(self):
  self.left=None#This can be a cmp structure or a list (for string)
  self.Mnem="" #A string representing the operator. i.e., cmp, add, sub, and etc.
  self.right=None#This can be a cmp structure or a list (for string)
  self.compare_lists=[]#This is a list of all the comparing instruction inside this structure.
  
class cmp_stru:
 def _init_(self):
  self.left=None#This can be a cmp structure, a out_most_disp, or an int
  self.Mnem="" #A string representing the operator. i.e., cmp, add, sub, and etc.
  self.right=None#This can be a cmp structure, a out_most_disp, or an int
 

class out_most_disp: #For storing out most disp.
 def _init_(self):
  self.disp=[]
  self.shape="" #[[base+3]+4] into [[]]

def get_function_name(IR):
 right_bracket=IR.rfind(')')
 left_bracket=get_corresponding_left_bracket(IR,right_bracket)
 return IR[:left_bracket]    
 
 
def get_parameters(IR):
 right_bracket=IR.rfind(')')
 left_bracket=get_corresponding_left_bracket(IR,right_bracket)
 IR=IR[left_bracket+1:right_bracket]
 parameters=IR.split(',')
 return parameters

    
#Check whether this is a calling subfunction
def is_calling_subfunction(formula,index):#If we encounter the RETURN_xxx() or [...]()
 if formula[index]=='R':
  if formula[index:index+7]=='RETURN_':
   immediate_next_operator_index=find_next_operator(formula,index+7)
   if immediate_next_operator_index==len(formula):
     immediate_next_operator_index=len(formula)-1
   #print("is_calling_subfunction immediate_next_operator_index=",immediate_next_operator_index)
   if formula[immediate_next_operator_index]=='(':
    return True
 elif formula[index]=='[':
  right_bracket= get_right_bracket_index(formula,index,'[')
  if right_bracket==len(formula)-1:#not found ]( pattern
   return False
  elif formula[right_bracket+1]=='(':#found ]( pattern
   return True
 return False 
 
def get_corresponding_left(IR,right_bracket):
 level=1
 index=right_bracket-1
 while index >-1:
  if IR[index]==')':
   level+=1
  elif IR[index]=='(':
   level-=1
  elif IR[index]=='"': 
   index=get_correspond_left_quotation(IR,index-1)
  if level==0:
   return index
  #print("level",level," index ",index," len ",len(IR))
  index-=1
 return len(IR)
 
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
 
 
#Given a string, group characters into words
#Parameter1: the string
def split_elements(string):
 string=string.replace("@32",'')
 index=0
 result_list=[]
 #if string.find('[')!=-1:
  #print("before: ",string)
  #string=simplify_address(string)
  #print("after: ",string)
 #print("split_elements string",string)
 while index<len(string):
  if string[index]=='[':#If encounter [, we should extract the whole [] as a word
   #left_bracket=string.find('[',index,len(string)-1)
   right_disp=get_corresponding_right_disp(string,index+1)
   translated_disp=translate_disp(string[index:right_disp+1])#Translate [[base+2]+3] into [[base,2],[3]]
   result_list+=translated_disp
   index=right_disp+1
  else:#None [] cases
   element_len=get_element_len(string,index)
   #print("index=",index,"element_len=",element_len,"string:",string[index:index+element_len])
   if string[index:index+element_len] not in [' ','[',']','+']:
    result_list.append(string[index:index+element_len])
   index+=element_len
 while index<len(result_list):#If any element is an integer, we transform it to int type.
  #if is_int(result_list[index]):
  # result_list[index]=to_int(result_list[index])
  #elif type(result_list[index])==str:#We replace all the RETURN_... to RETURN for convinience
  # if result_list[index].find("RETURN_")!=-1:
  #  result_list[index]="RETURN"
  if is_calling_subfunction(result_list[index],0):
   return_list=recursive_split_calling_subfunction(result_list[index])
   if return_list!=[]:
    for parameter in return_list:
     result_list.insert(index,parameter)
     index+=1
  else:
   index+=1
   
 return result_list 
 
#We split the calling subfunction into a list of string. For example, RETURN_...(1,2,3)--->[RETURN(1),RETURN(2),RETURN(3)]
#Note that if the IR is nested, e.g., RETURN(RETURN(1,2,3),4,5,6)-->[RETURN(RETURN(1)),RETURN(RETURN(2)),RETURN(RETURN(3)),RETURN(4),RETURN(5),RETURN(6)]
def recursive_split_calling_subfunction(IR):
  right_bracket=IR.rfind(')')
  left_bracket=get_corresponding_left(IR,right_bracket)
  IR_left=IR[:left_bracket]
  func_name=get_function_name(IR_left)
  IR_right=IR[left_bracket+1:right_bracket]
  print("recursive_split_calling_subfunction IR_right=",IR_right)
  parameters=extract_function_parameters(IR_right)
  result_list=[]
  for parameter in parameters:
    split_list=split_elements(parameter)
    split_list=put_bracket_disp_in_each_elelment(split_list)
    split_list=add_to_each_elelment('r',split_list,func_name+"(")
    result_list+=split_list
  return result_list  
    
    
#Given a string and a starting position, return the length of
#the word starting from this position
#Parameter1: string
#Parameter2: starting position
#Return value: length of the word
def get_element_len(string,index):
 #print("get_element_len string",string,"index",index,"string[index]=",string[index],"string:",string)
 if string[index] in ['+','-','/','*','~','%','^','&','(',')','[',']','|',',','!']:
  return 1
 elif string[index] ==' ':
  return 1
 elif string[index]=='<' and string[index+1]=='<' or string[index]=='>' and string[index+1]=='>':
  return 2
 elif string[index]=='<' and not string[index+1]=='<' or string[index]=='>' and not string[index+1]=='>':
  return 1
 elif string[index]=='@':
  return 3
 elif string[index]=='0' and index<=len(string)-2:
  if string[index+1]=='x':
   index1=end_index_of(string,index+2)
   return index1-index
  else:
   index1=find_next_operator(string,index+1)
   return index1-index
 elif is_calling_subfunction(string,index):
   #if string[index:index+7]=="RETURN_":
   #index1=end_index_of(string,index+7)
   index1=get_calling_subfunction_left_bracket(string,index) 
   index1=get_right_bracket_index(string,index1,'(')
   if index1==-1:
    index1=find_next_operator(string,index)-1
   return index1-index+1
   #else:
   #index1=find_index_after_this_word(string,index+1)
   #return index1-index
 elif string[index:index+3]=="add" or string[index:index+3]=="adc" or string[index:index+3]=="and":
   return 3
 elif string[index:index+3]=="sub" or string[index:index+3]=="sdc" or string[index:index+3]=="xor" or \
 string[index:index+3]=="mov":
   return 3
 elif string[index:index+3]=="cmp":
   return 3
 elif string[index:index+4]=="test":
   return 4
 elif string[index:index+2]=="or":
   return 2
 elif string[index:index+4]=="cmov":
   index1=get_first_non_alpha(string,index+4)
   return index1-index
 elif string[index:index+3]=="set":
   index1=get_first_non_alpha(string,index+3)
   return index1-index
 elif string[index]=='=':
  if string[index+1]=='=':
   return 2
  else:
   return 1
 elif string[index]=='V':
  if string[index:index+3]=="VAR":
   index1=end_index_of(string,index+3)
   #print("index=",index," index1=",index1)
   #print(string[index:index1])
   return index1-index
  else:
   index1=find_index_after_this_word(string,index+1)
   return index1-index   
 elif string[index]=='i':
  if index+1>len(string)-1:
   index1=find_index_after_this_word(string,index+1)
   return index1-index
  elif string[index+1]=='f':
   return 2
  else:
   index1=find_index_after_this_word(string,index+1)
   return index1-index
 elif string[index]=='"':
  index1=find_next_qutation(string,index+1)
  return index1-index
 #elif string[index].isnumeric():
 # index1=end_index_of(string,index+1)
 # return index1-index
 elif string[index]=="I":
  if string[index:index+4]=="ITER":
   #index1=get_corresponding_right_bracket(string,index+4)
   #return index1-index+1
   return 4
  else:
   index1=find_index_after_this_word(string,index+1)
   return index1-index   
 elif string[index]=="U":
  if string[index:index+7]=="UNKNOWN":
   return 7
  else:
   index1=find_index_after_this_word(string,index+1)  
   return index1-index
 elif string[index]=='$' or string[index]=='_':
   index1=find_next_operator(string,index+1)
   return index1-index   
 elif string[index]=='b':
  if string[index:index+3]=='bsr' or string[index:index+3]=='bsf': 
   return 3
  else:
   index1=find_index_after_this_word(string,index+1)  
   return index1-index
 #elif string[index]=='l':
 # if string[index+4]=='log2': 
 #  return 4  
 # else:
 #  index1=find_index_after_this_word(string,index+1)  
 #  return index1-index
 elif string[index].isalpha():#General english vocabulary
  index1=find_index_after_this_word(string,index+1)
  return index1-index
 elif string[index].isnumeric():#General number
  #print("string[index]=",string[index])
  index1=find_next_operator(string,index+1)
  return index1-index
 else:
  print("get_element_len failed!")
  print("get_element_len string=",string)
  print("get_element_len index=",index)
  print("get_element_len string[index]",string[index]) 
  print("Nonetype!!!")
  
#Get the first ( of this calling subfunction
def get_calling_subfunction_left_bracket(formula,index):
 if formula[index]=='R':
  return formula.find('(',index,-1)
 elif formula[index]=='[':
  return get_right_bracket_index(formula,index,'[')+1
 
def find_next_qutation(string,index):
 for index1 in range(index,len(string)):
  if string[index1]=='"':
   return index1+1

def is_operator(char):
 if char in ['+','-','*','/','~','%','^','&','(',')','[',']','|',',','=','"','(',')']:
  return True

def find_next_operator(string,index):
 #print("find_next_operator len(string)=",len(string),"index=",index)
 for index1 in range(index,len(string)):
  if string[index1] in ['+','-','*','/','~','%','^','&','(',')','[',']','|',',','=','"','(',')']:
   return index1
  elif string[index1:index1+2]=="<<" or string[index1:index1+2]==">>":
   return index1
 return len(string)
 
#Given an english-word-like variable starting index, find forwardly to return the first character index after this word.
def find_index_after_this_word(string,index):
 for index1 in range(index,len(string)):
  if not (string[index1].isalpha() or string[index1]=='.' or string[index1]=='_' or string[index1].isnumeric()):#Sometimes the variable can be like abcd_1234.abcd_1234
   return index1
 return len(string)
 
#Return the starting index of next word, given a hex or a decimal input.
#Parameter1: string
#Parameter2: starting position (the first character after "VAR", "RETURN_","0x")
def end_index_of(string,startindex):
 #print("start indeex=",startindex," len=",len(string))
 if startindex==len(string)-1:
  return startindex+1
 elif startindex==len(string):
  return startindex
 for index in range(startindex,len(string)):
   if re.match(r'[0-9a-fA-F.]',string[index])==None:
    #print(string[index])
    return index 
   if index==len(string)-1:
    return len(string)
    
def get_corresponding_left_bracket(string,right_bracket):
 level=1
 for index in range(right_bracket-1,-1,-1):
  if string[index]=='(':
   level-=1
  elif string[index]==')':
   level+=1
  if level==0:
   return index
   
def get_first_non_alpha(string,start_index):
 for index in range(start_index,len(string)):
  if string[index].isalpha()==False:
   return index
 return len(string)  
   
def get_corresponding_right_bracket(string,left_bracket):
 level=1
 index=left_bracket+1
 while index <len(string):
  if string[index]=='(':
   level+=1
  elif string[index]==')':
   level-=1
  elif string[index]=='"':
   index=get_correspond_right_quotation(string,index+1)
  if level==0:
   return index
  index+=1 

#Start_index is the first character after the first '"'. We need to find the corresponding ending quotation.
def get_correspond_right_quotation(formula,start_index):
 for index in range(start_index,len(formula)):
  if formula[index]=='"':
   return index
 return len(formula)-1 
 
#Start_index is the first character after the first '"'. We need to find the corresponding ending quotation.
def get_correspond_left_quotation(formula,start_index):
 for index in range(start_index,-1,-1):
  if formula[index]=='"':
   return index
 return 0 
   
def get_cmp_left(IR):
 return IR.split("==")[0].split("if")[1]
 
def get_cmp_right(IR):
 return IR.split("==")[1]
 
def get_eq_left(IR):
 return IR.split("=")[0]
 
def get_eq_right(IR):
 return IR.split("=")[1]
 
#The comparison logic is firstly compare two IR strings' textual similarity,
#If they have low similarity, it coulbd be because they contain [].
#If so, we compare the meaning of this []. This means if the same [] is also used
#other similar instructions, we deem it similar. For example:
#if [VAR2+1567]==3;-----------------------------if [VAR1+1342]==3;
#RETURN_1234(VAR2+1234,3,5,6);------------------RETURN_134(VAR1+1123,3,5,6);
#The first parameter should be deemed similar
#When comparing two strings, there can be 3 situations:
#1. expression vs expression (may contain [])
#2. memory address without outmost []
#3. memory address with outmost []
#
#
#If the string is in form [], then it is directly situation 3. However, if it is not in
#form [......], it might be situation 1 or 2. We assume situation 1, then 2.
'''def text_similarity(string1,string2):
 #print("text_similarity",string1,string2)
 global ACCEPT_TEXTUAL_THRESHOLD
 #Situation 3, memory address with outmost []
 if string1.strip().startswith('@') and string1.strip().endswith(']') and string2.strip().startswith('@') and string2.strip().endswith(']'):
  #print("text_similarity situation3")
  return disp_similarity(simplify_address(string1),simplify_address(string2))
 elif not string1.strip().endswith(']') and not string2.strip().endswith(']'):
  #Situation 1, expression vs expression (may contain [])
  similarity=expression_similarity(string1,string2)
  if similarity<=ACCEPT_TEXTUAL_THRESHOLD and string1.find('[')!=-1 and string2.find('[')!=-1:
  #Situation 2, memory address without outmost []
   #print("text_similarity situation2, string1, string2:")
   #print(string1," ",string2)
   similarity1=disp_similarity(simplify_address(string1),simplify_address(string2))
   return max(similarity,similarity1)
  else:
   return similarity
 else:
  return -2'''
  
#Two IRs are represented by two lists. Each list contains multiple string and disp struct.
#How to compare: Firstly extract the string sequence and compare their similarity. Next
#compare their disp structure similarity. Final similarity should be the minimum similarity.
def text_similarity_v1(list1,list2):
 #print("text_similarity_v1 list1:",list1,"list2",list2)
 #Extract string and disp structures out of list 1
 string_list1=[]
 disp_list1=[]
 num_list1=[]
 for item in list1:
  #print("item:",item,"type=",type(item))
  if type(item)==str:
   string_list1.append(item)
  elif type(item)==out_most_disp:
   disp_list1.append(item)
  elif type(item)==int:
   num_list1.append(item)
 #Extract string and disp structures out of list 2
 string_list2=[]
 disp_list2=[]
 num_list2=[]
 for item in list2:
  #print("item:",item,"type=",type(item))
  if type(item)==str:
   string_list2.append(item)
  elif type(item)==out_most_disp:
   disp_list2.append(item)
  elif type(item)==int:
   num_list2.append(item)
 #print("text_similarity_v1 disp_list1:",disp_list1,"disp_list2:",disp_list2)
 #print("text_similarity_v1 num_list1:",num_list1,"num_list2:",num_list2)
 #print("text_similarity_v1 string_list1:",string_list1,"string_list2:",string_list2)
 string_sim=SequenceMatcher(None,string_list1,string_list2).ratio()
 #print("string list1:",string_list1,"string_list2",string_list2,"sim=",string_sim)
 num_sim=int_num_list_sim(num_list1,num_list2)
 if len(disp_list1)!=len(disp_list2):
  min_disp_sim=0
 elif len(disp_list1)==0:
  min_disp_sim=1
 else:
  min_disp_sim=1
  for disp1,disp2 in zip(disp_list1,disp_list2):
   disp_similarity=disp_sim(disp1,disp2)
   if disp_similarity<min_disp_sim:
    min_disp_sim=disp_similarity
   
 total_sim=min(string_sim,min_disp_sim)
 total_sim=min(total_sim,num_sim)
 return total_sim
   
#Given two lists of numbers, decide their similarity. Note that the num lists here are extracted from string, not disp. Thus we decide two numbers are same if they are equal or abs is 1. 
def int_num_list_sim(num_list1,num_list2):
 if len(num_list1)==0 and len(num_list2)==0:#sizes are all zero
  return 1
 elif len(num_list1)==0 or len(num_list2)==0:#one size is zero while another isn't
  return 0
 elif len(num_list1)!=len(num_list2):#both sizes are non-zero and length not same
  return 0
 else:#both sizes are non-zero and length are same
  min_sim=1
  for int1,int2 in zip(num_list1,num_list2):
   if int1==int2 or abs(int1-int2)==1:
    sim=1
   else:
    sim=0
   if sim<min_sim:
    min_sim=sim
  return min_sim  
 
def expression_similarity(string1,string2):
 elements1=split_elements(string1)
 elements2=split_elements(string2)
 #print(string1,":",elements1,string2,":",elements2)
 if len(elements1)>1 or len(elements2)>1:#When two strings contain enough elements for comparison
  #scaler=(max(len(elements1),len(elements2)))*1.0/(max(len(elements1),len(elements2))+2)
  result=SequenceMatcher(None,elements1,elements2).ratio()#*scaler
  #elements1,iters1=extract_iter(elements1)
  #elements2,iters2=extract_iter(elements2)
  #scaler=(max(len(elements1),len(elements2)))*1.0/(max(len(elements1),len(elements2))+2)
  #normal_item_result=SequenceMatcher(None,elements1,elements2).ratio()*scaler
  #if len(iters1)>0 or len(iters2)>0:
  # iter_item_result=iter_lists_sim(iters1,iters2)
  # result=0.5*normal_item_result+0.5*iter_item_result
  #else:
  #  result=normal_item_result
 else:
  if is_int(string1) and is_int(string2):
   result= 2.0/(abs(to_int(string1)-to_int(string2))+2)
  else:
   #scaler=(max(len(string1),len(string2)))*1.0/(max(len(string1),len(string2))+2)
   result=SequenceMatcher(None,elements1,elements2).ratio()#*scaler
 return result
 
#Simplify [base+......]+[base2+......] into [base+OFFSET]+[base2+OFFSET]
def simplify_address(string):
 #print("simplify_address",string)
 index=string.find('[')
 while index < len(string):
  if string[index]=='[':
   index2=get_corresponding_right_disp(string,index+1)
   #print("simplify_address ",string," ",index2)
   string1=replace_with_offset(string[index:index2+1])
   string=string[:index]+string1+string[index2+1:]
   index+=len(string1)
  else:
   index+=1
 return string  
   
def get_corresponding_right_disp(string,startindex):
 level=1
 index=startindex
 while index < len(string):
  if string[index]=='[':
   level+=1
  elif string[index]==']':
   level-=1
  elif string[index]=='"':
   index=get_correspond_right_quotation(string,index+1)
  if level==0:
   return index
  index+=1 

def replace_with_offset(string):
 index=string.rfind('[')#Get the right most [
 index1= get_element_len(string,index+1)+index+1
 #Address base just passed
 #print("index1=",index1,string[index1],"replace_with_offset",string)
 while index1 < string.rfind(']'):
  #print(index1,string.rfind(']'))
  if string[index1]=='+' or string[index1]=='-':#index1 is the first + or -
   index2=string.find(']',index1,string.rfind(']')+1)#If we have found some + after the right most [, find its ]
   #print("index2=",index2)
   #string=string[:index1]+"+OFFSET"+string[index2:]#Replace with OFFSET
   replace=iterate_replace_offset(string[index1:index2])
   #print("string=",string)
   #print("left:",string[:index1])
   #print("replace:",replace)
   #print("index1=",index1,"len=",len(replace))
   #print("right",string[index2:])
   string=string[:index1]+replace+string[index2:]
   index1+=len(replace)
   #print("string=",string)
   #bp()
  else:
   index1+=1
 return string  
 
#The given string is a substring of [base+...], that is +.... We need to replace all the offsets, reserving the 
#operators, while do not replace them all as one "offset".
def iterate_replace_offset(string):
 index=0
 #print("iterate_replace_offset",string)
 #print("iterate_replace_offset",string)
 while index < len(string):
  if string[index]=='0' and index<len(string)-1:
   if string[index+1]=='x':#If encounter 0x...
    index2=end_index_of(string,index+2)#index2=next element first index
    string=string[:index]+"OFFSET"+string[index2:]
    index+=6
    #print("1:",index,"/",len(string))
   else:
    index2=find_next_operator(string,index+1)#Split the substring from current 
    substring=string[index:index2]
    if is_int(substring):#encounter numeric element
     string=string[:index]+"OFFSET"+string[index2:]
     index+=6
     #print("2:",index,"/",len(string))
  elif string[index]=='0' and index==len(string)-1:
   index+=1
  elif not is_operator(string[index]):#If encounter non operator character
   index2=find_next_operator(string,index+1)#Split the substring from current 
   substring=string[index:index2]
   if is_int(substring):#encounter numeric element
    string=string[:index]+"OFFSET"+string[index2:]
    index+=6
    #print("3:",index,"/",len(string))
   else:#encounter other elements, this is the case where we shall reserve.
    index2=find_next_operator(string,index+1)
    index=index2
  elif is_operator(string[index]):#If encounter operator character
   index+=1
   #print("4:",index,"/",len(string))
  elif string[index]==' ':
   index+=1 
   #print("5:",index,"/",len(string))
  #print(string) 
  #bp()
 #print("iterate_replace_offset return",string) 
 return string  

def extract_base(string):
 #print("extract_base: ",string)
 index=string.rfind('[')
 index1=get_element_len(string,index+1)+index+1
 #print("index+1,index1,result string: ",string[index+1]," ",string[index1]," ",string[index+1:index1])
 return string[index+1:index1]
 
'''def disp_similarity(string1,string2):
 string1=replace_with_offset(string1)
 string2=replace_with_offset(string2)
 
 base1=extract_base(string1)
 base2=extract_base(string2)
 base_score=check_vocab_sim(base1,base2)
 result=(base_score+SequenceMatcher(None,string1.replace(" ","").replace(base1,""),\
 string2.replace(" ","").replace(base1,"")).ratio())
 #print("disp_similarity, "," base_score=",base_score," result=",result)
 return result
 '''
def disp_similarity(string1,string2):
 #print("disp_similarity",string1,"   ",string2)
 #print("disp_similarity origin string1=",string1)
 string1=replace_with_offset(string1)
 string2=replace_with_offset(string2)
 #print("disp_similarity string1=",string1)
 elements1=split_elements(string1.replace(" ",""))
 elements2=split_elements(string2.replace(" ",""))
 
 elements1,iters1=extract_iter(elements1)
 elements2,iters2=extract_iter(elements2)
 #scaler=(max(len(elements1),len(elements2)))*1.0/(max(len(elements1),len(elements2))+2)
 normal_item_result=SequenceMatcher(None,elements1,elements2).ratio()#*scaler
 if len(iters1)>0 or len(iters2)>0:
  iter_item_result=iter_lists_sim(iters1,iters2)
  result=0.5*normal_item_result+0.5*iter_item_result
 else:
  result=normal_item_result
 return result

def get_var_list(string):
 var_list=[]
 for index in range(0,len(string)):
  if string[index]=="V":
   if string[index:index+3]=="VAR" and string[index-2:index]!="IT":
    index1=end_index_of(string,index+3)
    if string[index:index1] not in var_list: 
      var_list.append(string[index:index1])
 return var_list
 
#Given a string like ..., ..., ... (that has been extracted from [VAR](..., ..., ...)),
# we need to extract all its parameters. We focus on the comma that only has no 
#unbalanced left bracket on its left hand.
def extract_function_parameters(string):
 print("extract_function_parameters",string)
 parameters=[]
 bracket_level=0#used to record how deep bracket is in now
 qutation_level=0#used to record whether now we are in a qutation
 start_index=0
 for index in range(0,len(string)):
  if string[index]=='(':
   bracket_level+=1
  elif string[index]==')':
   bracket_level-=1
  elif string[index]=='"' and qutation_level==0:
   qutation_level+=1
  elif string[index]=='"' and qutation_level==1:
   qutation_level-=1
  if string[index]==',' and bracket_level==0 and qutation_level==0:
   parameters.append(string[start_index:index])
   start_index=index+1
  elif index==(len(string)-1) and bracket_level==0 and qutation_level==0:
   print("parameter=",string[start_index:index+1])
   parameters.append(string[start_index:index+1])
  
 return parameters
 
def clean_suffix(IR1,IR2):
 IR1=IR1.replace(".8","")
 IR1=IR1.replace(".16","")
 IR1=IR1.replace(".32","")
 IR1=IR1.replace(".64","")
 IR1=IR1.replace(".128","")
 IR2=IR2.replace(".8","")
 IR2=IR2.replace(".16","")
 IR2=IR2.replace(".32","")
 IR2=IR2.replace(".64","")
 IR2=IR2.replace(".128","")
 return IR1,IR2
 
def is_int(string):
 if type(string)==str:
  if string.isnumeric():
   return True
  elif re.match(r'^[-]*[0-9A-Fa-f]+[h]*$',string)!=None:
   return True
  elif re.match(r'^0x[0-9A-Fa-f]+$',string)!=None:
   return True
 return False
 
def to_int(string):
 if string[-1]=='h':
  return int(string[:-1],16)
 elif string.isnumeric():
  return int(string)
 else:
  return int(string,16)
  
def extract_iter(elements):
 #print("extract_iter",elements)
 iter_list=[]
 new_elements=[]
 for index in range(0,len(elements)):
  #print("index=",index)
  if elements[index].startswith("ITER("):
   iter_list.append(elements[index])
  else:
   new_elements.append(elements[index])
 return new_elements,iter_list  
 
def iter_lists_sim(iters1,iters2):
 #Firstly patch the list with smaller length to align them up
 length=max(len(iters1),len(iters2))
 if len(iters1)<length:
  for index in range(len(iters1),length):
   iters1.append("")
 elif len(iters2)<length:
  for index in range(len(iters2),length):
   iters2.append("")
 #Next we sequencitlaly get similarity of each pair
 sim=0
 for iter1,iter2 in zip(iters1,iters2):
   element1=split_elements(iter1.replace("ITER",""))
   element2=split_elements(iter2.replace("ITER",""))
   scaler=(max(len(element1),len(element2)))*1.0/(max(len(element1),len(element2))+2)
   sim+=SequenceMatcher(None,element1,element2).ratio()*scaler
 sim=sim*1.0/length
 return sim
 
#Translate [[base+2]+3+[VAR0+4]] into [["base","+",2],"+",3,"+",["var0","+",4]]
def translate_disp(string):
 result_list=[]
 result_list=split_elements(string[1:-1])#strip the out most []
 #for index in range(0,len(result_list)):
 # if is_int(result_list[index]):
 #  result_list[index]=to_int(result_list[index]) 
 result_list.insert(0,'[')
 result_list.append(']')
 return result_list
 
#Compare each disp pair similarity.
def disp_sim(disp1,disp2):
 #print("disp_sim disp1:",disp1.disp,"disp2:",disp2.disp,"disp1 base:",get_disp_base(disp1.disp),"disp2 base:",get_disp_base(disp2.disp))
 #bp()
 if disp1.shape!=disp2.shape:#if shape not the same return 0. e.g., [[]] vs [[][]]
  return 0
 elif get_disp_base(disp1.disp)!=get_disp_base(disp2.disp):#if base not equal
  return 0
 else:#if base equal, further compare its content
  sim=cmp_disp_content(disp1.disp,disp2.disp)
  return sim
 
def get_disp_base(disp):
 if type(disp[0])==list:
  return get_disp_base(disp[0])
 else:
  return disp[0]
  
#Compare disp each level's content similarity iteratively.
#Input are two lists.
def cmp_disp_content(disp1,disp2):
 disp_sim_list=[]#For recording each item's similarity under this level
 disp_list1=[]#Store list items for disp1
 disp_list2=[]#Store list items for disp2
 str_list1=[]#Store string items for disp1
 str_list2=[]#Store string items for disp2
 num_list1=[]#Store num item for disp1
 num_list2=[]#Store num item for disp2
 '''for item1,item2 in zip(disp1,disp2):
  if type(item1)!=type(item2):
   return 0
  elif type(item1)==list and type(item2)==list:
   disp_sim_list.append(cmp_disp_content(item1,item2))
  elif type(item1)==str and type(item2)==str:
   str_list1.append(item1)
   str_list2.append(item2)
  elif type(item1)==int and type(item2)==int:
   num_list1.append(item1)
   num_list2.append(item2)'''
 disp_list1, str_list1, num_list1=categorize_disp_contents(disp1)
 disp_list2, str_list2, num_list2=categorize_disp_contents(disp2)
 if has_variable_string(str_list1) or has_variable_string(str_list2):#If any of the two string lists has variable like RETURN_... or s in [VAR4+s-...], we can not compare them at all. So just defaultly deem they are same.
  return 1
 str_sim=SequenceMatcher(None,str_list1,str_list2).ratio()
 num_sim=num_list_sim(num_list1,num_list2)
 #Align two disp_lists. Fill up the gap.
 max_len=max(len(disp_list1),len(disp_list2))
 if len(disp_list1)<max_len:
  for i in range(0,max_len-len(disp_list1)):
   disp_list1.append([])
 elif len(disp_list2)<max_len:
  for i in range(0,max_len-len(disp_list2)):
   disp_list2.append([])
 #Next, we compare the disp list similarity.   
 for item1,item2 in zip(disp_list1,disp_list2):
  disp_sim_list.append(cmp_disp_content(item1,item2))
 #print("str_list1",str_list1,"str_list2",str_list2,"str_sim",str_sim)
 #print("num_list1",num_list1,"num_list2",num_list2,"num_sim",num_sim)
 minimum1=min(str_sim,num_sim)
 minimum2=1
 for sim in disp_sim_list:
  if sim<1:
   minimum2=sim
 total_sim=min(minimum1,minimum2)
 #print(disp1,"vs",disp2)
 #print("disp_similarity: ",disp_sim_list) 
 #print("string_list ",str_list1,str_list2,"similarity: ",str_sim) 
 #print("num_list ",num_list1,num_list2,"similarity: ",num_sim)
 #bp()
 return total_sim
 
#Given a string list, if any element of it si like RETURN or s (i.e., alphabetic-like ), we return 1. Otherwise 0.
def has_variable_string(str_list):
 for item in str_list:
  if item.isalpha() and item!="ITER" and item!= "UNKNOWN":#If any element is only consists of alpha (RETURN, s and etc. But VAR0, VAR1 ,ITER, UNKONWN does not count.)
   return True
 return False  
   

#For each disp content, we need to categorize its content into 3 categories: string, number, and list.
#Each category correspond to one list. We return these three lists at the end of this function.
def categorize_disp_contents(disp):
 str_list=[]
 num_list=[]
 disp_list=[]
 for item in disp:
  if type(item)==list:
   disp_list.append(item)
  elif type(item)==str:
   str_list.append(item)
  elif type(item)==int:
   num_list.append(item)
 return disp_list, str_list, num_list
  
#Compare two number lists' similarity. All the numbers should be the offset of some memory address, which are within the disp.
def num_list_sim(num_list1,num_list2):
 if(len(num_list1)!=len(num_list2)):
  return 0
 elif num_list1==0:
  return 1
 sim_list=[]
 for int1,int2 in zip(num_list1,num_list2):
  if (int1*2>=int2 and int1<=int2) or (int2*2>=int1 and int2<=int1):#If one address offset is 1-2 times than the other one.
   sim_list.append(1)
  else:
   sim_list.append(0)
 min_sim=1
 for sim in sim_list:
  if sim<min_sim:
   min_sim=sim
 return min_sim  
   
def struct_to_string(node_stru):
 string=""
 if node_stru['mode']==1: #[]=...
  string=str(node_stru['IR'][0].left.disp)+"="
  for element in node_stru['IR'][0].right:
   #print(element)
   if type(element)==out_most_disp:
    string+=str(element.disp)+" "
   else:
    string+=str(element)+" "
 elif node_stru['mode']==2:#cmp
  cmp_list=node_stru['IR'][0].compare_lists
  for element in cmp_list:
   string+=str(element.left)+element.Mnem+str(element.right)+", "
 elif node_stru['mode']==3:#expression
  for element in node_stru['IR'][0].elements:
    if type(element)==out_most_disp:
     string+=str(element.disp)+" "
    else:
     string+=str(element)+" "
 elif node_stru['mode']==4:#calling
  if type(node_stru['IR'][0].func_name)==str:
   function_name=str(node_stru['IR'][0].func_name)#+"("+str(node_stru['IR'][0].parameters)+")"
  elif type(node_stru['IR'][0].func_name)==out_most_disp:
   function_name=str(node_stru['IR'][0].func_name.disp)#+"("+str(node_stru['IR'][0].parameters)+")"
  parameters="("
  for parameter in node_stru['IR'][0].parameters:
   for item in parameter:
    if type(item)==str:
     parameters+=" "+item
    elif type(item)==int:
     parameters+=" "+str(item)
    elif type(item)==out_most_disp:
     parameters+=" "+str(item.disp)    
   parameters+=","  
  psrameters=parameters[:-1]+")" 
  string=function_name+parameters
 return string 
 
def line_object_to_string(line_object):
 string=""
 if line_object.mode==1: #[]=...
  string=str(line_object.IR.left.disp)+"="
  for element in line_object.IR.right:
   #print(element)
   if type(element)==out_most_disp:
    string+=str(element.disp)+" "
   else:
    string+=str(element)+" "
 elif line_object.mode==2:#cmp
  cmp_list=line_object.IR.compare_lists
  for element in cmp_list:
   string+=str(element.left)+element.Mnem+str(element.right)+", "
 elif line_object.mode==3:#expression
  for element in line_object.IR.elements:
    if type(element)==out_most_disp:
     string+=str(element.disp)+" "
    else:
     string+=str(element)+" "
 elif line_object.mode==4:#calling
  if type(line_object.IR.func_name)==str:
   function_name=str(line_object.IR.func_name)
  elif type(line_object.IR.func_name)==out_most_disp:
   function_name=str(line_object.IR.func_name.disp)
  parameters="("
  for parameter in line_object.IR.parameters:
   for item in parameter:
    if type(item)==str:
     parameters+=" "+item
    elif type(item)==int:
     parameters+=" "+str(item)
    elif type(item)==out_most_disp:
     parameters+=" "+str(item.disp)    
   parameters+=","  
  psrameters=parameters[:-1]+")" 
  string=function_name+parameters
 return string 
 
#For a splited string list e.g., ['[','VAR3','5',']','(','VAR5','8',')'] --> ['[VAR3]','[5]','(VAR5)','(8)']
def put_bracket_disp_in_each_elelment(split_list):
 print("put_bracket_disp_in_each_elelment split_list=",split_list)
 new_list=[]
 level_string=""
 for i in split_list:
  if i=='[':
   level_string+='['
  elif i==']':
   level_string+=']'
  elif i=='(':
   level_string+='('
  elif i==')':
   level_string+=')'
  else:#encounter the normal item such as 'VAR4' or '6'
   print("put_bracket_disp_in_each_elelment level_string=",level_string,"i=",i)
   if type(i)==list:
    bp()
   new_item=level_string+i
   new_list.append(new_item)
 return new_list
   
#Given a list of string, add string for all of its elements. Position demonstrate whether add to each element's left or right.
def add_to_each_elelment(position,split_list,string):
 new_list=[]
 if position=='l':
  for i in split_list:
   new_list.append(string+i)
  return new_list 
 elif position=='r':
  for i in split_list:
   new_list.append(i+string)
  return new_list 