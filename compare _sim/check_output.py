import os
from shutil import copyfile
from pdb import set_trace as bp
import json

#User input a functions path and this function returns the statistics about this functions path.
def main():
 functions_path=input("Please enter the functions path:")
 functions=extract_all_functions(functions_path)
 all_function_statics=""
 function_count=0
 function_total_count=len(functions)
 not_None_sim_pairs=0#Used to record the number of functions that have the ground truth similar pair
 no_sim_count=0
 no_IR_count=0
 no_IR_count_functions=[]
 no_sim_functions=[]
 empty_functions=0
 empty_functions_list=[]
 significant_result=0#Used to record the number of significant result. For a result, if ground truth similar pair similarity - the second similar one >=0.2, we call it significant.
 result={}
 for function in functions: 
  if function.find("sqlite3_vsnprintf")!=-1:
   bp()
  print("progress:",str(function_count)+"/"+str(function_total_count),"function:",function)
  function1_path=functions_path+'\\'+function
  if not os.listdir(function1_path):
   empty_functions+=1
   empty_functions_list.append(function1_path.split('\\')[-1])
  if os.path.isfile(function1_path+"\\IR_output1.txt"):
   if os.path.getsize(function1_path+"\\IR_output1.txt")>=0:#if IR_output1.txt size bigger than 1 kb
    if os.path.isfile(function1_path+"\\sim.txt"): #If contain sim.txt
     return_string=statistics(function1_path+"\\sim.txt")+"\n"
     sim_values=return_string.split(":")[-1].split("mean")[0].split(' ')
     sim_values=list(filter(None, sim_values))
     #print(function,"main sim_values=",sim_values)
     first_sim_value=sim_values[0]
     second_sim_value=sim_values[1]
     not_None_sim_pairs+=1
     if first_sim_value!="None":
      all_function_statics+=function+return_string
      #not_None_sim_pairs+=1
      first_value=float(first_sim_value)
      second_value=float(second_sim_value)
      #if first_value==0 and second_value==0: #or first_value==1 and second_value==1 :
      # not_None_sim_pairs-=1
      # continue
      if first_value-second_value>=0: #or second_value*2<=first_value:
       significant_result+=1
      result[function]=function+" first_value="+str(first_value)+"second_value="+str(second_value)+" "+str(first_value>=second_value)
    else:
     no_sim_count+=1
     no_sim_functions.append(function1_path.split('\\')[-1])
     result[function]=function+" no sim False"
     print(function1_path+"\\sim.txt do not exist")    
   else:
    print(function1_path+"\\IR_output1.txt size not bigger than 3kb")   
  else:
   no_IR_count+=1
   no_IR_count_functions.append(function1_path.split('\\')[-1])
   result[function]=function+" not able to analyze False"
   #print(function1_path+"\\IR_output1.txt do not exist")  
  function_count+=1
  
 f=open("statistics_big_functions.txt",'w')
 f.write(all_function_statics)
 f.close()
 #accuracy=significant_result*1.0/not_None_sim_pairs
 accuracy=significant_result*1.0/function_total_count
 print("\n\n\n")
 for key in sorted(result):
  print(result[key])
 print("Accuracy=",accuracy,"not_None_sim_pairs=",not_None_sim_pairs,"no sim_count=",no_sim_count,"no_IR_count=",no_IR_count,"empty_functions=",empty_functions,"significant_result=",significant_result,"function_total_count=",function_total_count)
 print("\n\nempty_functions_list:")
 for i in empty_functions_list:
  print(i)
  
 print("\n\nno_IR_count_functions:")
 for i in no_IR_count_functions:
  print(i) 
  
 print("\n\nno simfunctions:")
 for i in no_sim_functions:
  print(i) 
 
    
#For a function_path, we extract all the function names within this function_path.
#For example, for a function ../../../../../x64_.....
#We only extract x64_.....
def extract_all_functions(functions_path):
 all_functions=[]
 for subdir,dirs,files in os.walk(functions_path):
  if subdir.find("/x64_")!=-1 or subdir.find("/ARM_")!=-1:
   function=subdir.split("/")[-1]
   all_functions.append(function)
 return all_functions 


#Do tatistics of this sim.txt
def statistics(sim_file_path):
 static_string=""
 f=open(sim_file_path,'r')
 content=f.read()
 f.close()
 lines=content.split('\n')
 value_array=[]
 lines=unify_lines(lines)#Make the first line has the same format as the rest of the lines. i.e., /... vs /... 
 if is_sim_pairs(lines[0]):#If the first line is a pair of similar functions
  #static_string+=lines[0] #Append the first line
  ground_truth_similar=lines[0].split(':')[0]
  for line in lines[1:]:#append the rest of the function pairs
   if line.split(':')[0]==ground_truth_similar:#If this line is comparing the same two functions as the first line, the ground truth similar pairs. i.e., .../... vs .../...
    continue
   try:
    value_array.append(float(line.split(':')[-1].strip()))
   except:
    value_array.append(0)
  value_array.sort()#Firstly we sort all the other items except the ground-truth one
  value_array.append(float(lines[0].split(':')[-1].strip()))  #Now we add the ground-truth one to the first
 else:#If the first line is not a pair of similar functions
  static_string+="similar pairs: None"
  for line in lines:
   try:
    value_array.append(float(line.split(':')[-1].strip()))
   except:
    value_array.append(0)
  value_array.sort()
 total=0
 for i in value_array:
  total+=i
 mean=total*1.0/len(value_array) 
 static_string+=" "+str(value_array[-1])+" "+str(value_array[-2])+" "+str(value_array[-3])+" mean="+str(mean)
 return static_string
 
#If line is like: x64_DES_ede3_cfb64_encrypt vs ARM_DES_ede3_cfb64_encrypt: 0.0
#This implies a similar pair
def is_sim_pairs(line):
 line=line.split(":")[0]
 #print(line)
 first_name=line.split(" vs ")[0].strip()
 first_name=get_real_name(first_name)
 second_name=line.split(" vs ")[1].strip()
 second_name=get_real_name(second_name)
 if first_name==second_name:
  return True
 else:
  return False
 
def get_real_name(name):
 if name.find('/')!=-1:
  name=name.split('/')[-1]
 if name.find("x64_")==0:
  return  name[4:]
 elif name.find("ARM_")==0:
  return  name[4:]
  
 
 
#If a function's IR_output1.txt is big enough (>=3kb), we copy all the contents in this function.
#Param 1: the functions path
#Param 2: the home folder of binary code. 
#The home structure:   home_______binary 1
#                              |     |___function1
#                              |     |___function2
#                              |     |___...
#                              |     |___function n
#                              |
#                              |
#                              |
#                              |__binary 2  
#                                    |___function1
#                                    |___function2
#                                    |___...
#                                    |___function n                      
def copy_big_files():
 functions_path=input("Please enter the functions path:")
 dest_binary_home="binary_home"
 functions=extract_all_functions(functions_path)
 function_count=0
 function_total_count=len(functions)
 binary_name=functions_path.split("\\")[-1]
 dest_binary_path=dest_binary_home+"\\"+binary_name
 os.mkdir(dest_binary_path)
 for function in functions:
  print("progress:",str(function_count)+"/"+str(function_total_count))
  function1_path=functions_path+'\\'+function
  if os.path.isfile(function1_path+"\\IR_output1.txt"):
   if os.path.getsize(function1_path+"\\IR_output1.txt")>=300:#if IR_output1.txt size bigger than 3 kb
    dest_function_path=dest_binary_path+"\\"+function
    os.mkdir(dest_function_path)
    try:
     copy_one_function_all_file(function1_path,dest_function_path)
    except:
     function_count+=1
     continue
  function_count+=1
  
#Given a list of functions from Asm2Vec, extract the functions with the same name.
def copy_same_files():
 against_rp_binary=input("Please enter the functions in RP you want to search against:")
 functions=[]
 functions_path=input("Please enter the functions path:")
 function_names=extract_all_functions(functions_path)
 dest_binary_home="binary_home"
 
 json_path=input("please enter the Asm2Vec JSON file path:")
 f=open(json_path.replace('"','').replace("'",""),'r')
 for line in f:
   functions.append(json.loads(line))
 
 '''json_path=input("please enter the Asm2Vec JSON files path:")
 for root,dirs,files in os.walk(json_path):
  for file in files:
   if file.endswith(".json"):
    complete_path=json_path+"\\"+file
    f=open(complete_path.replace('"','').replace("'",""),'r')
    for line in f:
     functions.append(json.loads(line))''' 
  
 binary_name=functions_path.split("\\")[-1] 
 dest_binary_path=dest_binary_home+"\\"+binary_name
 os.mkdir(dest_binary_path)
 
 function_count=0 
 function_total_count=len(functions)
 
 prefix=""
 if function_names[0].startswith('x64_'):
  prefix="x64_"
 elif  function_names[0].startswith('ARM_'):
  prefix="ARM_"
  
 has_similar_functions= read_has_similar_functions(functions_path)
 for function in functions:
  if result_no_same_binary_name(function['clones'],against_rp_binary):#To keep consistant with Asm2Vec results, we ignore the results that does not have the functions from the wanted binary
   print(function['function']['functionName'],"do no have functions from the wanted binary")
   continue
  print("progress:",str(function_count)+"/"+str(function_total_count))
  source_function=function['function']['functionName']
  dest_function_path=dest_binary_path+"\\"+prefix+source_function
  function1_path=functions_path+'\\'+prefix+source_function
  #if source_function=="awk_getline":
  # bp()
  name=prefix+source_function
  if not os.path.isdir(function1_path):#We ignore functions that exists in Asm2Vec result but not in our result. Becase Asm2Vec sometimes have non-exist functions, this is wired.
   print(function1_path,"exists in Asm2Vec result, not in my result")
   continue
  elif name not in has_similar_functions:#If the function does not has ground truth same functions 
   print(prefix+source_function,"no similar pairs")
   continue
  if not os.path.isdir(dest_function_path):
   os.mkdir(dest_function_path)
  try:
     copy_one_function_all_file(function1_path,dest_function_path)
  except:
     function_count+=1
     print(function1_path,"error while copy")
     continue
  function_count+=1
  

def read_has_similar_functions(functions_path):
 f=open(functions_path+"\\similar.txt",'r')
 content=f.read()
 f.close()
 lines=content.split('\n')
 lines = list(dict.fromkeys(lines))
 return lines
 
 
  
  
def unify_lines(lines):
 if is_sim_pairs(lines[0]):
  binary_name=lines[1].split(' vs ')[1].split(':')[0].split('/')[0].strip()
  insert_index=lines[0].find(' vs ')+4
  lines[0]=lines[0][:insert_index]+binary_name+'/'+lines[0][insert_index:]
 lines = list(dict.fromkeys(lines)) 
 return lines

  
#Copy all the file within this function
def copy_one_function_all_file(function_path,dest_function_path):
 
 src=function_path+"\\0_output.txt"
 dst=dest_function_path+"\\0_output.txt"
 copyfile(src, dst)
 
 src=function_path+"\\IR_output.txt"
 dst=dest_function_path+"\\IR_output.txt"
 copyfile(src, dst)
 
 src=function_path+"\\IR_output1.txt"
 dst=dest_function_path+"\\IR_output1.txt"
 copyfile(src, dst)
 
 src=function_path+"\\IR_output1_simplified.pickle"
 dst=dest_function_path+"\\IR_output1_simplified.pickle"
 copyfile(src, dst)
 
 src=function_path+"\\sim.txt"
 dst=dest_function_path+"\\sim.txt"
 copyfile(src, dst)
 
#If in the similarity results no this binary name, we just ignore this result
def result_no_same_binary_name(result,binary_name):
 binary_name_sets=[]
 for i in result:
  binary_name_sets.append(i["binaryName"])
 binary_name_sets = list(dict.fromkeys(binary_name_sets))
 if binary_name not in binary_name_sets:
  return True
 else:
  return False  

def merge_many_binaries():
 import subprocess
 binary_path=input("Please enter the binaries path:")
 binaries=[]
 for each_binary in os.listdir(binary_path):
  binaries.append(each_binary)
  
 total_uncalculatable_functions=[] 
 for each_binary in binaries:
  for each_function in os.listdir(binary_path+"\\"+each_binary):
   if not os.path.isdir(binary_path+"\\"+each_binary+"\\"+each_function):
    continue
   function_complete_path=binary_path+"\\"+each_binary+"\\"+each_function
   subprocess.call("mv '"+function_complete_path+"' '"+binary_path+"'")
   f=open(binary_path+"\\"+each_binary+"\\uncalculatable_function.txt",'r')
   uncalculatable_functions=f.read().split("\n")
   f.close()
   total_uncalculatable_functions+=uncalculatable_functions
  subprocess.call("rm -r '"+binary_path+"\\"+each_binary+"'")
 
 total_uncalculatable_functions=list(dict.fromkeys(total_uncalculatable_functions))
 total_uncalculatable_functions_string=""
 for i in total_uncalculatable_functions:
  total_uncalculatable_functions_string+=i+"\n"
 f=open(binary_path+"\\uncalculatable_function.txt",'w')
 f.write(total_uncalculatable_functions_string)
 f.close() 
  
#merge_many_binaries()
main() 
#copy_big_files()
#copy_same_files()