import os
from shutil import copyfile
from generate_TADW_input import generate_TADW_input
from create_IR_graph import create_ir_graph,arm_G,x64_G
import networkx as nx

def create_pairs(folder):
 subfolder_list=[]
 for subdir,dirs,files in os.walk(folder):
  if not (subdir.endswith("\\functions") or subdir.endswith("/pairs")):
   subfolder_list.append(subdir.split("/")[-1])
 #subfolder_list=subfolder_list[1:]
 for item in subfolder_list:
  print(item)
 for each_folder in subfolder_list:
  for each_other_folder in subfolder_list:
   if each_folder!=each_other_folder:
    print("creating:",each_folder,each_other_folder)
    pair_folder_path=create_folder4pair(folder,each_folder,each_other_folder)
    copy_file4pair(pair_folder_path,folder+"\\"+each_folder,folder+"\\"+each_other_folder)
   
def create_folder4pair(root_folder,first_folder,second_folder):
 #print("first_folder=",first_folder)
 #print("second_folder",second_folder)
 pair_folder_path=root_folder+"\\pairs\\"+first_folder+"+"+second_folder
 os.mkdir(pair_folder_path)
 return pair_folder_path
   
def copy_file4pair(pair_folder_path,first_folder,second_folder):
 if first_folder.split("\\")[-1].find("ARM")!=-1:
  suffix="arm_"
 elif first_folder.split("\\")[-1].find("x64")!=-1:
  suffix="x64_"
 src=first_folder+"\\IR_conditional_map.txt"
 dst=pair_folder_path+"\\"+suffix+"IR_conditional_map.txt"
 copyfile(src, dst)
 
 src=first_folder+"\\IR_output.txt"
 dst=pair_folder_path+"\\"+suffix+"IR_output.txt"
 copyfile(src, dst)
 
 src=first_folder+"\\IR_output1.txt"
 dst=pair_folder_path+"\\"+suffix+"IR_output1.txt"
 copyfile(src, dst)
 
 if second_folder.split("\\")[-1].find("ARM")!=-1:
  suffix1="arm_"
 elif second_folder.split("\\")[-1].find("x64")!=-1:
  suffix1="x64_"
 if suffix==suffix1:#if two IR comes from same architecture.
  suffix1+="1"
 src=second_folder+"\\IR_conditional_map.txt"
 dst=pair_folder_path+"\\"+suffix1+"IR_conditional_map.txt"
 copyfile(src, dst)
 
 src=second_folder+"\\IR_output.txt"
 dst=pair_folder_path+"\\"+suffix1+"IR_output.txt"
 copyfile(src, dst)
 
 src=second_folder+"\\IR_output1.txt"
 dst=pair_folder_path+"\\"+suffix1+"IR_output1.txt"
 copyfile(src, dst)
 
 
def main():
 folder=input("Please enter the functions folder:")
 create_pairs(folder)#Firstly create similar and dissimilar pairs
 folder+="\\pairs"
 '''for subdir,dirs,files in os.walk(folder):#For each pair of functions
  if not subdir.endswith("\\pairs"):
   each_pair=folder+"\\"+subdir.split('/')[-1]
   create_ir_graph_args=get_args(each_pair)
   #print("pair folder::",each_pair)
   #print("arguments:",create_ir_graph_args)
   generate_TADW_input(create_ir_graph_args,each_pair)# Secondly generate TADW inputs'''
 
def get_args(pair_path):
  return_arg_list=[]
  all_files=[]
  for subdir,dirs,files in os.walk(pair_path):#For each file in this pair path
    for file in files:
     if file.find(".txt")!=-1:
      all_files.append(file)
  prefix=[]
  for file in all_files:
   if file.find("IR_")!=-1:
    pre=file.split("IR_")[0]
    if pre not in prefix:
     prefix.append(pre)
  
  return_arg_list.append(pair_path+"\\"+prefix[0]+"IR_output.txt")
  return_arg_list.append(pair_path+"\\"+prefix[0]+"IR_output1.txt")
  return_arg_list.append(pair_path+"\\"+prefix[0]+"IR_conditional_map.txt")
  return_arg_list.append(pair_path+"\\"+prefix[1]+"IR_output.txt")
  return_arg_list.append(pair_path+"\\"+prefix[1]+"IR_output1.txt")
  return_arg_list.append(pair_path+"\\"+prefix[1]+"IR_conditional_map.txt")
  return return_arg_list

#We directly get one address file and one pickle file from a function's folder
def get_args_for_pickle(function_path):
  return_arg_list=[]
  return_arg_list.append(function_path+"\\IR_output.txt")
  return_arg_list.append(function_path+"\\IR_output1_simplified.pickle")
  return return_arg_list    
 
#Input a pair's path, read two graphs and calculate their networks' similarity
def networx_edit_distance(each_pair):
 global arm_G
 global x64_G
 #each_pair=input("Please enter the pair's folder")
 create_ir_graph_args=get_args(each_pair)
 create_ir_graph(create_ir_graph_args[0],create_ir_graph_args[1],create_ir_graph_args[2],create_ir_graph_args[3],create_ir_graph_args[4],create_ir_graph_args[5])# Secondly generate TADW inputs
 print(each_pair.split("\\")[-1],"networx_edit_distance:",nx.graph_edit_distance(arm_G,x64_G,timeout=8))
 
def all_pairs_edit_distance():
 pairs_folder=input("please enter the pairs folder:")
 for subdir,dirs,files in os.walk(pairs_folder):
  if not subdir.endswith("\\pairs"):
   pair_path=pairs_folder+"\\"+subdir.split('/')[-1]
   networx_edit_distance(pair_path)
   
#main()
#all_pairs_edit_distance()