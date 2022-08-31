from scipy import spatial
import csv
import os
total_sim_dict={}

#Given two addresses, compare their similarity from the tadw outputfile.
def two_addresses_similarity(arm_address_file,arm_embedding_file,x64_address_file,x64_embedding_file):
 #arm_address_file=input("Please enter the arm address file:")
 arm_address_map=read_address_map(arm_address_file)
 #print(arm_address_map['2198'])
 #x64_address_file=input("Please enter the x64 address file:")
 x64_address_map=read_address_map(x64_address_file)
 
 #arm_embedding_file=input("Please enter the arm embedding file:")
 arm_node_embeddings=read_node_embeddings(arm_embedding_file)
 #print(arm_node_embeddings[225])
 #x64_embedding_file=input("Please enter the x64 embedding file:")
 x64_node_embeddings=read_node_embeddings(x64_embedding_file)
 
 while True:
  arm_node=input("Please enter the arm node:")
  x64_node=input("Please emter the x64 node:")
  arm_embedding=arm_node_embeddings[int(arm_address_map[arm_node])]
  #print("arm_embedding",arm_embedding)
  x64_embedding=x64_node_embeddings[int(x64_address_map[x64_node])]
  #print("x64_embedding",x64_embedding)
  result = 1 - spatial.distance.cosine(arm_embedding, x64_embedding)
  print("similarity:",result)
  
#Read from the address map file. which maps each hex address into a range starting from 0 (so that tadw can execute)
def read_address_map(address_file):
 address_map={}
 with open(address_file,'r') as f:
  content=f.read()
 f.close()
 content=content.split('\n')
 for item in content:
  if item.find(':')!=-1:
   hex_address=item.split(':')[0]
   index=item.split(':')[1]
   address_map[hex_address]=index
 return address_map

#Delete first row (header) in the file, and for each line, the first element e.g., 1.0 is extracted as the index, rest elements grouped as vectors.
def read_node_embeddings(embedding_file):
 embeddings={}
 lines=[]
 with open(embedding_file,'r') as f:
  csvfile=csv.reader(f)
  for line in csvfile:
   lines.append(line)
 f.close()
 lines=lines[1:]
 for line in lines:
  node_index=int(float(line[0]))
  embedding=[]
  for index in range(1,len(line)):
   embedding.append(float(line[index]))
  embeddings[node_index]=embedding
 return embeddings
  
#Read from tadw output file to decide two graphs' nodes' embedding similarity.
def two_TADW_output_similarity(pair_path,tadw_output_file,map_file,tadw_output_file1,map_file1): 
 global total_sim_dict
 total_sim=0
 print("two_TADW_output_similarity pair_path:",pair_path)
 global_sim_list=[]
 arm_address_map=read_address_map(map_file)
 x64_address_map=read_address_map(map_file1)
 arm_node_embeddings=read_node_embeddings(tadw_output_file)
 x64_node_embeddings=read_node_embeddings(tadw_output_file1)
 for key in arm_address_map:
  key_embedding=arm_node_embeddings[int(arm_address_map[key])]
  max_sim=0
  max_key1=0
  for key1 in x64_address_map:
   key1_embedding=x64_node_embeddings[int(x64_address_map[key1])]
   similarity = 1 - spatial.distance.cosine(key_embedding, key1_embedding)
   global_sim_list.append(key1+"--"+key+":"+str(similarity))
   if similarity>max_sim:
    max_sim=similarity
    max_key1=key1
  #global_sim_list.append(key+"--"+max_key1+":"+str(max_sim))
  total_sim+=max_sim
 global_sim_list.append(str(total_sim*1.0/len(global_sim_list)))
 total_sim_dict[pair_path.split('\\')[-1]]=str(total_sim*1.0/len(global_sim_list))
 print_global_sim_to_file(global_sim_list,pair_path)
  
def print_global_sim_to_file(global_sim_list,pair_path):
 string=""
 f=open(pair_path+"\\similarity.txt",'w')
 for each_one in global_sim_list:
  string+=each_one+"\n"
 f.write(string)
 f.close() 

#Given a pair path, find all the tadw output files and group them into two groups correspondingly.
def extract_TADW_output_groups(pair_path):
 result_groups=[]
 tadw_output_files=[]
 for subdir,dirs,files in os.walk(pair_path):
  for file in files:
   if file.find("map.txt")!=-1 or file.find("tadw.csv")!=-1:
    tadw_output_files.append(file)
 #Now group them into two groups.
 for file in tadw_output_files:
  if file.find("map.txt")!=-1:#Firstly find the map file
   prefix=get_prefix(file)
   #next find its corresponding tadw file.
   for file1 in tadw_output_files:
    if file1.find("tadw.csv")!=-1:
     prefix1=get_prefix(file1)
     if prefix==prefix1:
      result_groups.append(file1)
      result_groups.append(file)
 return pair_path+"\\"+result_groups[0],pair_path+"\\"+result_groups[1],pair_path+"\\"+result_groups[2],pair_path+"\\"+result_groups[3]
    
#Extract arm_1 from arm_1map.txt and arm from arm_tadw.csv.
def get_prefix(file_name):
 if file_name.find("map.txt")!=-1:
   prefix=file_name.split("map.txt")[0]
 elif file_name.find("tadw.csv")!=-1:
   prefix=file_name.split("tadw.csv")[0]
 return prefix
 
#For all the pairs files under some folder, we decide each pairs' similarity.
def main():
 global total_sim_dict
 pairs_folder=input("Please enter the pairs folder:")
 for subdir,dirs,files in os.walk(pairs_folder):
  if not subdir.endswith("\\pairs"):
   pair_path=pairs_folder+"\\"+subdir.split('/')[-1]
   tadw_output_file,map_file,tadw_output_file1,map_file1=extract_TADW_output_groups(pair_path)
   two_TADW_output_similarity(pair_path,tadw_output_file,map_file,tadw_output_file1,map_file1)
 for key,value in total_sim_dict.items():
  print(key,value)
   

#Given a specific pair path, we compare this pair's similarity.
def main1():
 global total_sim_dict
 pairs_folder=input("Please enter the test case folder:")
 tadw_output_file,map_file,tadw_output_file1,map_file1=extract_TADW_output_groups(pairs_folder)
 two_TADW_output_similarity(pairs_folder,tadw_output_file,map_file,tadw_output_file1,map_file1)
 for key,value in total_sim_dict.items():
  print(key,value)
#two_addresses_similarity("IR_graph_TADW/arm_map.txt","IR_graph_TADW/arm_tadw.csv",\
#"IR_graph_TADW/x64_map.txt","IR_graph_TADW/x64_tadw.csv",)


main1()