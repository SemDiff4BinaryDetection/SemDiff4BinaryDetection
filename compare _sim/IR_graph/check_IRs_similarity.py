#We read from the output file i.e., IR_output.txt, IR_output1.txt, and conditional.txt to 
#create two IR graphs and compare their similarity using area_similarity method.
import pickle
from similarity.text import IR_memory_store,IR_cmp,IR_expression,IR_calling,out_most_disp,IR_out_most_cmp,cmp_stru,line_object_to_string
from simplify_IR_graph import get_IR_type,process_IR_type
import matplotlib.pyplot as plt
from create_sim_and_disim_pairs import get_args,get_args_for_pickle
from create_IR_graph import arm_G,x64_G,create_ir_graph,create_ir_graph_from_pickle,create_ir_graph_from_pickle_single, arm_already_scaned_addresses, x64_already_scaned_addresses
from similarity.IR_graph_similarity import compare4all_nodes,compare_specific_pair,compare4all_nodes_sequence_assisted,compare4_all_nodes_topological_sort_hash,topological_sort_hash_graph_single
from similarity.IR_graph_similarity_hash import compare4all_nodes_hash
from simplify_IR_graph import simplify_IR_graph
from similarity.sequence_nodes_compare import nodes_sequence_compare,one_sequence_pair_compare
import os
import networkx as nx
from random import randint
from pdb import set_trace as bp
import sys
from datasketch import MinHash
sys.setrecursionlimit(5500)

class line_object:
 def _init_(self):
  self.mode=0
  self.IR=None


def check_this_pair(pair_path):
 global arm_G
 global x64_G
 create_ir_graph_args=get_args(pair_path)
 create_ir_graph(create_ir_graph_args[0],create_ir_graph_args[1],create_ir_graph_args[2],\
 create_ir_graph_args[3],create_ir_graph_args[4],create_ir_graph_args[5])
 simplify_IR_graph(arm_G)
 simplify_IR_graph(x64_G)
 #return compare4all_nodes(arm_G,x64_G)#all node compare based on each node's text info
 #while True:#one node pair compare based on each node's text info
 # compare_specific_pair(arm_G,x64_G)
 sequence_length=8
 #return nodes_sequence_compare(arm_G,x64_G,sequence_length)#all node compare based on sequence of nodes
 #while True:#one sequence pair compare based on sequence of nodes
 # one_sequence_pair_compare(arm_G,x64_G,sequence_length)
 return compare4all_nodes_sequence_assisted(arm_G,x64_G,sequence_length)#all node compare based on bare node and its neighbour (sequences)
 
def main():
 result={}
 pairs_path=input("Please enter the 'pair' folder:")
 for subdir,dirs,files in os.walk(pairs_path):
  if not subdir.endswith("\\pairs"):
   each_pair=pairs_path+"\\"+subdir.split('/')[-1]
   sim=check_this_pair(each_pair)
   result[subdir.split('/')[-1]]=sim
 for key,value in result.items():
  print(key,":",value)
   
   
def main1():
 each_pair=input("Please enter a pair's folder:")
 sim=check_this_pair(each_pair)
 print("sim=",sim)

#Param 1: First function's path
#Param 2: Second function's path
def function_pair_sim(function1_path,function2_path):
 print("processing:",function1_path.split('\\')[-1],"         ",function2_path.split('\\')[-1])
 create_ir_graph_args1=get_args_for_pickle(function1_path)
 create_ir_graph_args2=get_args_for_pickle(function2_path)
 #if pickle_file_not_same_scale(create_ir_graph_args1[1],create_ir_graph_args2[1]):
 # sim=0
 #else:
 result=create_ir_graph_from_pickle(create_ir_graph_args1[0],create_ir_graph_args1[1],\
 create_ir_graph_args2[0],create_ir_graph_args2[1])
 if result=="RecursionError":
  print("function_pair_sim RecursionError")
  return -1
 #plt.figure("x64")
 #nx.draw(x64_G,with_labels=True)
 #plt.figure("arm")
 #nx.draw(arm_G,with_labels=True)
 #plt.show()
 sequence_length=8
 #sim=compare4all_nodes_sequence_assisted(arm_G,x64_G,sequence_length)#all node compare based on bare node and 
 #sim=compare4all_nodes_hash(arm_G,x64_G,sequence_length)
 #sim=nx.graph_edit_distance(arm_G,x64_G,node_match=single_node_hash_sim)
 
 sim=compare4_all_nodes_topological_sort_hash(arm_G,x64_G)
 print(function1_path.split('\\')[-1]," vs ",function2_path.split('\\')[-1],"sim:",sim)
 return sim
 
def single_node_hash_sim(node1,node2):
 # print("node1=",node1,"node2=",node2)
 #if node1['mode']!=node2['mode']:
 # return False
 #else:
  if node1=={} or node2=={}:
   return False
  m1 = MinHash(num_perm=128)
  for d in node1['IR'][0]:
    m1.update(d.encode('utf8'))
    
  m2 = MinHash(num_perm=128)
  for d in node2['IR'][0]:
    m2.update(d.encode('utf8'))
    
  if m1.jaccard(m2)>=0.4:
   return True
  else: return False
    
  
def all_functions_similarity():
 functions_path1=input("Please enter the 1st functions folder:")
 functions_path2=input("Please enter the 2nd functions folder:")
 uncalculatable_functions=get_uncalculatable_functions(functions_path1,functions_path2)
 functions=extract_all_functions(functions_path1)
 function_count=0
 function_total_count=len(functions)
 for function in functions:
  print("progress:",str(function_count)+"/"+str(function_total_count))
  #if already_has_sim_file(functions_path1+'\\'+function):#Turn on this switch to skip already generated sim functions
  # function_count+=1
  # continue
  if not is_uncaculatable_fuction(functions_path1+'\\'+function,uncalculatable_functions):#Must not on the uncalculatable list.
   #Firstly we compare this function with its corresponding function's similarity
   functions_sim_table={}#Record all the functions pair and their similarity
   function1_path=functions_path1+'\\'+function
   function2_path=functions_path2+"\\"+get_mirror_function_name(function,functions_path2)
   if exist_this_function(get_mirror_function_name(function,functions_path2),functions_path2):#If counterpart function exists
    if not is_uncaculatable_fuction(function2_path,uncalculatable_functions):#Must has pickle file and IR_output1.txt
     sim=function_pair_sim(function1_path,function2_path)
     if sim==None:
      bp()
     functions_sim_table[function+" vs "+get_mirror_function_name(function,functions_path2)]=sim
   else:#If counterpart function does not exists
    function_count+=1
    continue 
  else:
   function_count+=1
   continue 
  #Secondly we randomly select other 100 functions and compare function's similarity with them.
  function2_paths=generate_unreapeated_functions(functions_path2,uncalculatable_functions)
  for i in range(0,len(function2_paths)):#For each one in the random function paths, we calculate similarity
   sim=function_pair_sim(function1_path,function2_paths[i])
   if sim==None:
    bp()
   function2_name=function2_paths[i].split('\\')[-1]
   functions_sim_table[function+" vs "+function2_name]=sim
  
  write_sim_table_to_function1(function1_path,functions_sim_table)
  function_count+=1
  
def all_functions_similarity_hash():
 functions_path1=input("Please enter the 1st functions folder:")
 functions_path2=input("Please enter the 2nd functions folder:")
 uncalculatable_functions=get_uncalculatable_functions(functions_path1,functions_path2)
 functions=extract_all_functions(functions_path1)
 write_similar_pairs(functions,extract_all_functions(functions_path2),functions_path1)
 function_count=0
 function_total_count=len(functions)
 functions_hash1=hash_each_function(functions_path1,functions,uncalculatable_functions)
 functions2=extract_all_functions(functions_path2)
 functions_hash2=hash_each_function(functions_path2,functions2,uncalculatable_functions)
 for hash1 in functions_hash1:
  functions_sim_table={}
  print("progress:",str(function_count)+"/"+str(function_total_count))
  hash2=get_counterpart_function(hash1[0],functions_hash2)
  if hash2!=None:#Has similar counter part function
   sim=hash1[1].jaccard(hash2[1])
   functions_sim_table[hash1[0]+" vs "+hash2[0]]=sim
  elif hash2==None:#No similar counter part function
   function_count+=1
   continue
  for hash2 in functions_hash2:
   sim=hash1[1].jaccard(hash2[1])
   functions_sim_table[hash1[0]+" vs "+hash2[0]]=sim
  write_sim_table_to_function1(functions_path1+'\\'+hash1[0],functions_sim_table) 
  function_count+=1
 '''for function in functions:
  print("progress:",str(function_count)+"/"+str(function_total_count))
  #if already_has_sim_file(functions_path1+'\\'+function):#Turn on this switch to skip already generated sim functions
  # function_count+=1
  # continue
  if not is_uncaculatable_fuction(functions_path1+'\\'+function,uncalculatable_functions):#Must not on the uncalculatable list.
   #Firstly we compare this function with its corresponding function's similarity
   functions_sim_table={}#Record all the functions pair and their similarity
   function1_path=functions_path1+'\\'+function
   function2_path=functions_path2+"\\"+get_mirror_function_name(function,functions_path2)
   if exist_this_function(get_mirror_function_name(function,functions_path2),functions_path2):#If counterpart function exists
    if not is_uncaculatable_fuction(function2_path,uncalculatable_functions):#Must has pickle file and IR_output1.txt
     sim=function_pair_sim(function1_path,function2_path)
     if sim==None:
      bp()
     functions_sim_table[function+" vs "+get_mirror_function_name(function,functions_path2)]=sim
   else:#If counterpart function does not exists
    function_count+=1
    continue 
  else:
   function_count+=1
   continue 
  #Secondly we randomly select other 100 functions and compare function's similarity with them.
  function2_paths=generate_unreapeated_functions(functions_path2,uncalculatable_functions)
  for i in range(0,len(function2_paths)):#For each one in the random function paths, we calculate similarity
   sim=function_pair_sim(function1_path,function2_paths[i])
   if sim==None:
    bp()
   function2_name=function2_paths[i].split('\\')[-1]
   functions_sim_table[function+" vs "+function2_name]=sim
  
  write_sim_table_to_function1(function1_path,functions_sim_table)
  function_count+=1'''
 
#This one is specially designed for binaries like coreutils that contains multiple binaries. When comparing, we are taking one binary to compare all the bianries' all functions.
def many_binaries_all_functions_similarity_hash():
 functions_path1=input("Please enter the 1st binary folder:")
 functions_path2=input("Please enter the 2nd binaries folder:")
 uncalculatable_functions=[]
 for each_binary in os.listdir(functions_path2):
  uncalculatable_functions+=get_uncalculatable_functions(functions_path1,functions_path2+"\\"+each_binary)
 functions=extract_all_functions(functions_path1)
 function_count=0
 function_total_count=len(functions)
 functions_hash1=hash_each_function(functions_path1,functions,uncalculatable_functions)
 
 functions_hash2=[]
 for each_binary in os.listdir(functions_path2):
  functions2=extract_all_functions(functions_path2+"\\"+each_binary)
  functions_hash2+=hash_each_function(functions_path2,functions2,uncalculatable_functions)
 for hash1 in functions_hash1:
  functions_sim_table={}
  print("progress:",str(function_count)+"/"+str(function_total_count))
  hash2=get_counterpart_function(hash1[0],functions_hash2)
  if hash2!=None:#Has similar counter part function
   sim=hash1[1].jaccard(hash2[1])
   functions_sim_table[hash1[0]+" vs "+hash2[0]]=sim
  elif hash2==None:#No similar counter part function
   function_count+=1
   continue
  for hash2 in functions_hash2:
   sim=hash1[1].jaccard(hash2[1])
   functions_sim_table[hash1[0]+" vs "+hash2[0]]=sim
  write_sim_table_to_function1(functions_path1+'\\'+hash1[0],functions_sim_table) 
  function_count+=1
  
#Given a function name and a list of hash list with format [[func1,hash1],[func2,hash2]...], find the hash of counterpart function.
def get_counterpart_function(func_name,functions_hash):
 for i in functions_hash:
  if i[0]==func_name:
   return i
 return None  

#Given a list of function paths, hash each of them. The result is a list, each element contains 2 members, 1st is function name, 2nd is hash value
def hash_each_function(functions_path,functions,uncalculatable_functions):
 result_list=[]
 num=0
 for function in functions:
  print("hash_each_function process:",str(num)+"/",str(len(functions)),"function=",function)
  new_record=[]
  if not is_uncaculatable_fuction(functions_path+"\\"+function,uncalculatable_functions):
   new_record.append(function)
   hash_value=get_function_hash(functions_path+"\\"+function)
   new_record.append(hash_value)
   result_list.append(new_record) 
  num+=1
 return result_list
   
#Param 1: First function's path
#Param 2: Second function's path
def get_function_hash(function_path):
 global arm_G
 arm_G.clear()
 global arm_already_scaned_addresses
 global x64_already_scaned_addresses
 arm_already_scaned_addresses.clear()
 x64_already_scaned_addresses.clear()
 create_ir_graph_args1=get_args_for_pickle(function_path)
 result=create_ir_graph_from_pickle_single(create_ir_graph_args1[0],create_ir_graph_args1[1])
 #if "x64_single_transfer" in function_path:
 # bp()
 if result=="RecursionError":
  print("function_pair_sim RecursionError")
  return -1
 hash1=topological_sort_hash_graph_single(arm_G)
 
 return hash1
 
#This is for debugging. Fix one function, we calculate all random 100 functions' similarity iwth it.
def one_function_all_similarity():
 functions_path1=input("Please enter the 1st functions folder:")
 functions_path2=input("Please enter the 2nd functions folder:")
 uncalculatable_functions=get_uncalculatable_functions(functions_path1,functions_path2)
 fixed_function=input("Please enter the fixed function path:")
 functions=[fixed_function.split("\\")[-1]]
 for function in functions:
  if not is_uncaculatable_fuction(functions_path1+'\\'+function,uncalculatable_functions):#Must has pickle file and IR_output1.txt
   #Firstly we compare this function with its corresponding function's similarity
   functions_sim_table={}#Record all the functions pair and their similarity
   function1_path=functions_path1+'\\'+function
   function2_path=functions_path2+"\\"+get_mirror_function_name(function,functions_path2)
   if exist_this_function(get_mirror_function_name(function,functions_path2),functions_path2):
    if not is_uncaculatable_fuction(function2_path,uncalculatable_functions):#Must has pickle file and IR_output1.txt
     sim=function_pair_sim(function1_path,function2_path)
     if sim==None:
      bp()
     functions_sim_table[function+" vs "+get_mirror_function_name(function,functions_path2)]=sim
     
  #Secondly we randomly select other 100 functions and compare function's similarity with them.
  #function2_paths=generate_100_unreapeated_functions(functions_path2,uncalculatable_functions)
  function2_paths=generate_unreapeated_functions(functions_path2,uncalculatable_functions)
  for i in range(0,len(function2_paths)):#For each one in the random function paths, we calculate similarity
   sim=function_pair_sim(function1_path,function2_paths[i])
   if sim==None:
    bp()
   function2_name=function2_paths[i].split('\\')[-1]
   functions_sim_table[function+" vs "+function2_name]=sim
  write_sim_table_to_function1(function1_path,functions_sim_table)
  
#This is for debugging. Fix one function, we calculate all random 100 functions' similarity iwth it.
def one_function_one_similarity():
 fixed_function1=input("Please enter the first fixed function path:")
 fixed_function2=input("Please enter the second fixed function path:")
 sim=function_pair_sim(fixed_function1,fixed_function2)


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
 
#For a x64_function, we rename it to ARM_function. For ARM function, vice versa.
def get_mirror_function_name(function_name,functions_path2):
 example_function2=extract_all_functions(functions_path2)[0]
 real_function_name=""
 #Firstly get the architecture ignorant function name
 if function_name.find("x64_")==0:
  real_function_name=function_name.split("x64_")[-1]
 elif function_name.find("ARM_")==0:
  real_function_name=function_name.split("ARM_")[-1]
 
 #Secondly get the result architecture function name 
 mirror_function_name=""
 if example_function2.find("x64_")==0:
  mirror_function_name="x64_"+real_function_name
 elif example_function2.find("ARM_")==0:
  mirror_function_name="ARM_"+real_function_name
 return mirror_function_name 
 
def exist_this_function(function_name,functions_path):
 if os.path.isdir(functions_path+"\\"+function_name):
  return True
 else:
  return False

#Within this functions_path, we generate 100 unrepeated functions
def generate_100_unreapeated_functions(functions_path,uncalculatable_functions):
 functions_array=[]
 for subdir,dirs,files in os.walk(functions_path):
  if subdir.find("/x64_")!=-1 or subdir.find("/ARM_")!=-1:
   functions_array.append(subdir)
 #functions_array now contains all functions' full path
 unreapeated_100_functions=[]#to store 100 randomly generated functions' full path
 #print("generate_100_unreapeated_functions len(functions_array):",len(functions_array),"")
 while len(unreapeated_100_functions)<100:
  random_num=randint(0,len(functions_array)-1)
  #print("generate_100_unreapeated_functions random_num:",random_num)
  random_function_full_path=functions_array[random_num]
  if random_function_full_path in unreapeated_100_functions:
   continue
  elif is_uncaculatable_fuction(random_function_full_path,uncalculatable_functions):#Must has pickle file and IR_output1.txt
   continue
  else:
   unreapeated_100_functions.append(random_function_full_path)
 return unreapeated_100_functions  
 
#Within this functions_path, we generate all other unrepeated functions
def generate_unreapeated_functions(functions_path,uncalculatable_functions):
 functions_array=[]
 for subdir,dirs,files in os.walk(functions_path):
  if subdir.find("/x64_")!=-1 or subdir.find("/ARM_")!=-1:
   functions_array.append(subdir)
 #functions_array now contains all functions' full path
 unreapeated_functions=[]#to store all other functions' full path
 #print("generate_100_unreapeated_functions len(functions_array):",len(functions_array),"")
 for i in range(0,len(functions_array)):
  if is_uncaculatable_fuction(functions_array[i],uncalculatable_functions):#Must has pickle file and IR_output1.txt
   continue
  else:
   unreapeated_functions.append(functions_array[i])
 return unreapeated_functions  

#Write the similarity dictionary to the function_path
def write_sim_table_to_function1(function_path,functions_sim_table):
 #print("write_sim_table_to_function1 functions_sim_table:",functions_sim_table)
 string=""
 f=open(function_path+"\\sim.txt",'w')
 for key,value in functions_sim_table.items():
  #print("key=",key,"type(key)=",type(key),"value=",value,"type(value)=",type(value))
  string+=key+": "+str(value)+"\n"
 f.write(string) 
 f.close()

#Decide whether this function is calculatable.
def is_uncaculatable_fuction(function_full_path,uncalculatable_functions):
 if function_full_path.find('\\x64_')!=-1:
  function_name=function_full_path.split('\\x64_')[-1]
 elif function_full_path.find('/x64_')!=-1:
  function_name=function_full_path.split('/x64_')[-1]
 elif function_full_path.find('\\ARM_')!=-1:
  function_name=function_full_path.split('\\ARM_')[-1]
 elif function_full_path.find('/ARM_')!=-1:
  function_name=function_full_path.split('/ARM_')[-1] 
 if function_name in uncalculatable_functions:
  return True
 else:
  return False
 
#Param1: functions 1 path
#Param2: functions 2 path
#read the uncalculatable_function.txt in two folders and form the uncalculatable_functions
def get_uncalculatable_functions(functions_path1,functions_path2):
 uncalculatable_functions=[]
 f=open(functions_path1+"\\uncalculatable_function.txt",'r')
 uncalculatable_functions=f.read().split("\n")
 f.close()
 
 f=open(functions_path2+"\\uncalculatable_function.txt",'r')
 uncalculatable_functions1=f.read().split("\n")
 f.close()
 
 for function in uncalculatable_functions1:
  if function not in uncalculatable_functions:
   uncalculatable_functions.append(function)
 return uncalculatable_functions
 
def try_to_open_pickle_file_if_it_is_not_openable():
 folder=input("Please enter the folder:")
 pickle_file=folder+"\\IR_output1_simplified.pickle"
 f=open(pickle_file,'rb')
 p=pickle.load(f)
 print(p)
 f.close()
 
#Decide whether this function has sim file. If has, that means this function has already been progressed.
#Param 1: one function's full path
def already_has_sim_file(functions_path):
 if os.path.isfile(functions_path+"\\sim.txt"):
  return True
 else:
  return False
  
#If one pickle file size is more than twice of another pickle file, we say these two pickle files not at same scale.
def pickle_file_not_same_scale(pickle_file1_path,pickle_file2_path):
 pickle_file_size1=os.path.getsize(pickle_file1_path)
 pickle_file_size2=os.path.getsize(pickle_file2_path)
 if pickle_file_size1>pickle_file_size2*2 or pickle_file_size1*2<pickle_file_size2:
  return True
 else:
  return False
  
#Write a file similar.txt to functions_path1, which records all the functions that has counterpart function in functions_path2
#First parameter: extracted functions from functions_path1
#Second parameter: extracted functions from functions_path2
#Third parameter: the first functions path (where similar.txt is written to)
def write_similar_pairs(functions1,functions2,functions_path1):
 has_sim_functions=[]
 for function in functions1:
  if function in functions2:
   has_sim_functions.append(function)
 f=open(functions_path1+"\\similar.txt",'w')
 string=""
 for i in has_sim_functions:
  string+=i+'\n'
 f.write(string) 
 f.close()

#all_functions_similarity()
all_functions_similarity_hash()
#one_function_all_similarity()
#one_function_one_similarity()
#main()
#try_to_open_pickle_file_if_it_is_not_openable()
 
 