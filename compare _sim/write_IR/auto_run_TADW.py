import os
import warnings
import subprocess

def auto_run_TADW():
 sub_folders=[]
 folder=input("Please enter the folder:")\
 #Get all the pair path folders
 for subdir,dirs,files in os.walk(folder):
  if not (subdir.endswith("\\functions") or subdir.endswith("\pairs")):
   sub_folders.append(subdir.split('/')[-1])
 #For each pair path
 for each_pair_path in sub_folders:
  pair_path=folder+"\\"+each_pair_path
  TADW_input_files=extract_tadw_input_files(pair_path) #Extract 4 tadw input files
  input_graoups=group_tadw_input(TADW_input_files,pair_path) #group 4 tadw input files into two groups
  for group in input_graoups:
   print(group)
   #os.system('python C:\\Users\\nuc\\Downloads\\TADW-master\\TADW-master\\src\\main.py --edge-path '+group[0]+\
   #' --feature-path '+group[1]+' --output-path '+group[2]+'')
   subprocess.call(["python","C:\\Users\\nuc\\Downloads\\TADW-master\\TADW-master\\src\\main.py",\
   "--edge-path",group[0],"--feature-path",group[1],"--output-path",group[2]])
   
def get_prefix(file_name):
 if file_name.find("features.json")!=-1:
   prefix=file_name.split("features.json")[0]
 elif file_name.find("edge.csv")!=-1:
   prefix=file_name.split("edge.csv")[0]
 return prefix
 
#Extract the tadw files from current pair path
def extract_tadw_input_files(pair_path):
  #Get the TADW input file
  TADW_input_files=[]
  for subdir,dirs,files in os.walk(pair_path):
   for file in files:
    if file.find("edge.csv")!=-1 or file.find("features.json")!=-1:
     TADW_input_files.append(file)
  #Gourp twocorresponding input together
  #print("TADW_input_files:",TADW_input_files)
  if len(TADW_input_files)!=4:
   warnings.warn("TADW input file number not equal to 4! Chech the folder!")
  return TADW_input_files
   
#Given 4 tadw files, group them correspondingly into two pairs. Also add the tadw output file for each group.
def group_tadw_input(TADW_input_files,pair_path):
  input_graoups=[]
  for each_TADW_input in TADW_input_files:
    #Find the file containing edge and get the feature.json file with the same prefix.
   if each_TADW_input.find("edge.csv")!=-1:
    prefix=get_prefix(each_TADW_input)
    for each_other_TADW_input in TADW_input_files:
     prefix1=get_prefix(each_other_TADW_input)
     #Find the corresponding feature.json file with the same prefix.
     if prefix==prefix1 and each_other_TADW_input.find("features.json")!=-1:
      edge_path=pair_path+"\\"+each_TADW_input
      feature_path=pair_path+"\\"+each_other_TADW_input
      output_path=pair_path+"\\"+prefix+"tadw.csv"
      input_graoups.append([edge_path,feature_path,output_path])#Each group has three arguments. i.e., edge.csv, features.json, tadw.csv
  return input_graoups
  
auto_run_TADW()
    
  
  