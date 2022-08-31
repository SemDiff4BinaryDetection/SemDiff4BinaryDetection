import csv
import os
import re
from simplify_IR_graph import get_IR_type,process_IR_type,process_IR_type_hash_split
from formula_simplifier import really_has_this_char,split_IR2two_parts
import pickle
from pdb import set_trace as bp
import os.path

class line_object:
 def _init_(self):
  self.mode=0
  self.IR=None


#This is for processing a single function of a binary code. Reserve the key IRs and write to IR_output1.txt. Simplify the key IRs and write to IR_output1_simplified.txt
def process_single_function():
 while True:
  file_path=input("please enter the file path:")
  zero_output_file = file_path+"\\0_output.txt"
  IR_file_path=file_path+"\\IR_output.txt"
  IR_output_list=init_IR_output_list(IR_file_path);
  
  with open(zero_output_file,encoding='utf-8') as f:
   file_content = f.read()
   IR_output_list=add_to_IR_output_list(IR_output_list,file_content);
  f.close()
  write_to_file(IR_output_list,file_path+"\\IR_output1.txt")
  write_simplified_zero_output_file(IR_output_list,file_path+"\\IR_output1_simplified.pickle")
  #content=pickle.load(open(file_path+"\\IR_output1_simplified.pickle",'rb'))

#This is for processing a binary code's all functions.
def process_this_binary():
 binary_path=input("please enter the binary's all functions' path:")
 functions=[]
 for root,dirs,_ in os.walk(binary_path):
    for d in dirs:
        functions.append(d)
        
 uncalculatable_functions=binary_path+"\\uncalculatable_function.txt"
 with open(uncalculatable_functions) as f:#read all the uncalculatable functions
     uncalculatables = f.read().split('\n')
     uncalculatables=list(filter(None, uncalculatables))
 f.close()
 
 func_count=0 
 for function in functions:
    function_name=get_function_origin_name(function)
    if function_name in uncalculatables:#If this function is uncalculatable, skip it.
     continue
    print("function:",function,func_count,"/",len(functions))
    file_path=binary_path+"\\"+function
    zero_output_file = file_path+"\\0_output.txt"
    IR_file_path=file_path+"\\IR_output.txt"
    IR_output_list=init_IR_output_list(IR_file_path);
    func_count+=1
    if this_function_has_been_processed(file_path):#If this function folder already contains desired output file, we skip it.
     continue
    
    with open(zero_output_file,encoding='utf-8') as f:
     file_content = f.read()
     IR_output_list=add_to_IR_output_list(IR_output_list,file_content);
    f.close()
    write_to_file(IR_output_list,file_path+"\\IR_output1.txt")
    write_simplified_zero_output_file(IR_output_list,file_path+"\\IR_output1_simplified.pickle")
    
    
def cmd_process_each_o_file_dir(single_o_file_dir):   
 #import sys 
 #single_o_file_dir=sys.argv[-1]
 
 binary_path=single_o_file_dir
 functions=[]
 for root,dirs,_ in os.walk(binary_path):
    for d in dirs:
        functions.append(d)
        
 uncalculatable_functions=binary_path+"\\uncalculatable_function.txt"
 with open(uncalculatable_functions) as f:#read all the uncalculatable functions
     uncalculatables = f.read().split('\n')
     uncalculatables=list(filter(None, uncalculatables))
 f.close()
 
 func_count=0 
 for function in functions:
    function_name=get_function_origin_name(function)
    if function_name in uncalculatables:#If this function is uncalculatable, skip it.
     continue
    print("function:",function,func_count,"/",len(functions))
    file_path=binary_path+"\\"+function
    zero_output_file = file_path+"\\0_output.txt"
    IR_file_path=file_path+"\\IR_output.txt"
    IR_output_list=init_IR_output_list(IR_file_path);
    func_count+=1
    if this_function_has_been_processed(file_path):#If this function folder already contains desired output file, we skip it.
     continue
    
    with open(zero_output_file,encoding='utf-8') as f:
     file_content = f.read()
     IR_output_list=add_to_IR_output_list(IR_output_list,file_content);
    f.close()
    write_to_file(IR_output_list,file_path+"\\IR_output1.txt")
    write_simplified_zero_output_file(IR_output_list,file_path+"\\IR_output1_simplified.pickle")
    
    
def cmd_process_this_binary():
 import subprocess
 o_dirs_dir=input("Please enter the o file dirs' dir:")
 o_dirs_error_dir=input("Please enter the o file dirs' error dir:")
 o_dirs_dir_paths=[]
 for subdir in os.listdir(o_dirs_dir):
    #for d in dirs:
     #if d.endswith('.o'):
      o_dirs_dir_paths.append(subdir)
      
 single_o_dir_count=0
 for single_o_dir in o_dirs_dir_paths:
  try:
   print("process:",str(single_o_dir_count)+"/"+str(len(o_dirs_dir_paths)))
   complete_path=o_dirs_dir+"\\"+single_o_dir
   cmd_process_each_o_file_dir(complete_path) 
   single_o_dir_count+=1
  except:
   subprocess.call('mv "'+complete_path+'" "'+o_dirs_error_dir+'"')  
    
#Delete the leading ARM_ or x64_ to get the original function name.    
def get_function_origin_name(function_name):
 if function_name[0:4]=="ARM_" or function_name[0:4]=="x64_":
  return function_name[4:]

#Transfer the content in the file into a list if IR.
def add_to_IR_output_list(IR_output_list,file_content):
  lines=file_content.split("\n")
  for line in lines:
   address=line.split(";;")[0]
   IR=line.split(";;")[-1]
   #print("IR is :")
   #print(IR)
   #print("address is:")
   #print(address)
   for index in range(0,len(IR_output_list)):
    #print("IR_output_list[index][0]")
    #print(IR_output_list[index][0])
    if IR_output_list[index][0]==address:
     #print("IR_output_list[index][1]")
     #print(IR_output_list[index][1])
     if not_contain(IR_output_list[index][1],IR):
      IR_output_list[index][1].append(IR)
      break
  #print("add_to_IR_output_list")
  #print(IR_output_list)
  return IR_output_list


def write_to_file(IR_output_list,IR_file_path):
   f=open(IR_file_path,"w",encoding='utf-8')
   for line in IR_output_list:
    #print(line[0]+"       "+line[1]+"\n")
    string=line[0]+";"
    for item in line[1]:
     string+=item+";"
    string+="\n"
    f.write(string)
   f.close()


def init_IR_output_list(IR_file_path): 
  IR_output_list=[]
  with open(IR_file_path) as IR_file:
   file_content = IR_file.read()
  IR_file.close()
  lines=file_content.split("\n")

  for line in lines:
   address=line.split("-->")[0]
   new_line=[address,[]]
   IR_output_list.append(new_line)
  return IR_output_list
  
def not_contain(big_list,element):
 for previous_element in big_list:
  previous_element=re.sub('VAR[.0-9]*','',previous_element)
  previous_element=re.sub('RETURN_[0-9]*','',previous_element)
  previous_element=re.sub('ITVAR[0-9]*','',previous_element)
  #print(previous_element)
  element=re.sub('VAR[.0-9]*','',element)
  element=re.sub('RETURN_[0-9]*','',element)
  element=re.sub('ITVAR[0-9]*','',element)
  #print(element)
  if element==previous_element:
   return False
 return True  
 
#We store each line of simplified IR into data structure. This structure is for each line:
#line{
#     mode
#     IR data structure
#}
#
#Thus we have a dict and the keys are each hex address and values are structure "line"
def write_simplified_zero_output_file(IR_output_list,IR_file_path):
   pickle_dict={}
   for line in IR_output_list:
    print(line[0],line[1],"\n")
    #string=line[0]+";"
    for item in line[1]:
     if item=="":#if null IR
      continue
     if item[-1]==';':#trim last ';'
      item=item[:-1]
     if really_has_this_char(item,';'):#If this IR contains more than one IR, seperated by ;
      item=split_IR2two_parts(item,';')[0]#Currently we ignore this case and only takes its first IR
     #Now we simplify each IR before writing them to file
     type_of_IR=get_IR_type(item)
     #if item.find('67')!=-1:
     # bp()
     #simplified_IR=process_IR_type(item,type_of_IR)
     simplified_IR=process_IR_type_hash_split(item,type_of_IR)
     #Now we create an 'IR' data structure for each line
     new_line_object=line_object()
     new_line_object.mode=type_of_IR
     new_line_object.IR=simplified_IR
     #print("write_simplified_zero_output_file simplified IR:",str(simplified_IR))
     #add line object to picke dictionary
     pickle_dict[line[0]]=new_line_object
     #string+=simplified_IR+";"
    #string+="\n"
    #f.write(string)
   with open(IR_file_path,"wb") as handle:
    pickle.dump(pickle_dict,handle,protocol=pickle.HIGHEST_PROTOCOL) 
   
def this_function_has_been_processed(file_path):
 file1=file_path+"\\IR_output1.txt"
 file2=file_path+"\\IR_output1_simplified.pickle"
 if os.path.exists(file1) and os.path.exists(file2):
  return True
 return False

#process_single_function()
process_this_binary()
#cmd_process_this_binary()