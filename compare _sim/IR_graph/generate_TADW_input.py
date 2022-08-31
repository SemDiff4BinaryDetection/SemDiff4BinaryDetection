from similarity.text import split_elements
from simplify_IR_graph import get_IR_type,process_IR_type,simplify_IR_graph
from create_IR_graph import create_ir_graph,arm_G,x64_G
from datasketch import MinHash
import csv
import json
import networkx as nx
import os

#Process both IR address file and IR file to satisfy TADW input format.
def simplify_IRs(IR_address_file,IR_output_file,arch):
 with open(IR_address_file) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 address_lines=file_content.split("\n")
 #node_index_map=map_index(address_lines)
 #generate_TADW_input_edge(address_lines,node_index_map)
 #print(arm_address_lines)
 with open(IR_output_file) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 IR_lines=file_content.split("\n")
 iterate_add_nodes(address_lines[0],0,arch)
 #IR_lines=simplify_all_IRs(IR_lines)#Simplify all the lines in the IR file.
 #print("simplify_IRs",IR_lines)
 #IR_lines_feature=LSH_IR_lines(IR_lines)
 #generate_TADW_input_feature(IR_lines_feature,node_index_map)
 
def simplify_all_IRs(IR_lines):
 new_IR_lines=[]
 for line in IR_lines:
  if line.find(';')!=-1 and line.split(';')[1]!="":
   address=line.split(';')[0]
   line=line.split(';')[1]
   line=line.replace("+-",'-')
   type_of_IR=get_IR_type(line)
   #print("line",line,"mode=",type_of_IR)
   new_IR=process_IR_type(line,type_of_IR)
   new_IR=address+';'+new_IR
   new_IR_lines.append(new_IR)
 return new_IR_lines
 
 
def LSH_IR_lines(IR_line):
  #elements=split_elements(IR_line.replace(' ',''))
  m1=MinHash(4)
  for item in elements:
   m1.update(item.encode("utf8"))
  #print(m1.digest())
  result=str(m1.digest())
  result=listize(result)
  return result

#Generate features file.
#Parameter 1: graph.
#Parameter 2: the map to transfer each Key IR address to index (starting from 1)
#Parameter 3: architecture. arm-0, x64-1
def generate_TADW_input_feature(pair_path,G,index_map,dictionary,arch):
 IR_dict_feature={}
 translate_debug_info=""
 for each_node in G.nodes():
  if each_node!=0:
   print(each_node+":")
   IR_dict_feature[index_map[each_node]],new_tranlate_line=translate_to_dictionary_word(G.nodes[each_node]['IR'][0],dictionary)
   translate_debug_info+=str(each_node)+":"+new_tranlate_line+"\n"
 feature_path=pair_path+"\\"+arch+'features.json'
 with open(feature_path, 'w') as fp:
    json.dump(IR_dict_feature, fp)
 fp.close()
 
 translate_path=pair_path+"\\"+arch+'translate_debug.txt'
 #translate debug info into file
 with open(translate_path, 'w') as fp:
    fp.write(translate_debug_info)
 fp.close()
 
#Generate edge file.
#Parameter 1: graph.
#Parameter 2: the map to transfer each Key IR address to index (starting from 1)
#Parameter 3: architecture. arm-0, x64-1
def generate_TADW_input_edge(pair_path,G,index_map,arch):
 Key_IR_edges=[]
 print("generate_TADW_input_edge pair_path:",pair_path)
 for each_node in G.nodes():
  if each_node!=0:
   for each_one in G.successors(each_node):
    Key_IR_edges.append([each_node,each_one])

 edge_path=pair_path+"\\"+arch+"edge.csv" 
 #print("generate_TADW_input_edge pair_path:",pair_path)
 f=open(edge_path,'w')
 writer=csv.writer(f)
 writer.writerow(["node_1","node_2"])
 for each_line in Key_IR_edges:
  writer.writerow([index_map[each_line[0]],index_map[each_line[1]]])
 f.close()


def generate_TADW_input(create_ir_graph_args,pair_path):
 #if already_has_valid_output(pair_path)==True:
  #return
 global arm_G
 global x64_G
 create_ir_graph(create_ir_graph_args[0],create_ir_graph_args[1],create_ir_graph_args[2],\
 create_ir_graph_args[3],create_ir_graph_args[4],create_ir_graph_args[5])
 print("create_ir_graph completed")
 print("simplyfying arm_G")
 arm_G=simplify_IR_graph(arm_G)
 print("simplyfying x64_G")
 x64_G=simplify_IR_graph(x64_G)
 print("simplify_IR_graph completed")
 arm_index_map=map_index(arm_G)
 x64_index_map=map_index(x64_G)
 dictionary=generate_dict_from2graphs(arm_G,x64_G)
 #Two IR's files can be named as arm_output.txt and x64_output.txt.
 #And can be arm_output.txt and arm1_output.txt and etc. We need to 
 #extract arm or x64 as the prefix.
 prefix=create_ir_graph_args[0].split("\\")[-1].split("IR_")[0]
 prefix1=create_ir_graph_args[3].split("\\")[-1].split("IR_")[0]
 #print("generate_TADW_input prefix:",prefix)
 #print("create_ir_graph_args[0].split(IR_):",create_ir_graph_args[0].split("IR_"))
 generate_TADW_input_edge(pair_path,arm_G,arm_index_map,prefix)
 generate_TADW_input_feature(pair_path,arm_G,arm_index_map,dictionary,prefix)
 
 generate_TADW_input_edge(pair_path,x64_G,x64_index_map,prefix1)
 generate_TADW_input_feature(pair_path,x64_G,x64_index_map,dictionary,prefix1)
 
 generate_index_map_file(pair_path,arm_index_map,prefix)
 generate_index_map_file(pair_path,x64_index_map,prefix1)
 '''IR_address_file="arm_IR_output.txt"
 IR_output_file="arm_IR_output1.txt"
 simplify_IRs(IR_address_file,IR_output_file,0)
 IR_address_file="x64_IR_output.txt"
 IR_output_file="x64_IR_output1.txt"
 simplify_IRs(IR_address_file,IR_output_file,1)'''
 
def map_index(G):
 address_index_map={}
 index=0
 for each_node in G.nodes():
  if each_node!=0:
   address_index_map[each_node]=index
   index+=1
 return address_index_map

#transfer the string representation of minhash's digest into a list of features.
def listize(result):
 result=result.replace('[','')
 result=result.replace(']','')
 result=result.replace('\n','')
 return list(filter(None, result.split(' ')))
 
#Extract vocabulary from two graphs. Two graphs share the same vocabulary dictionary.
def generate_dict_from2graphs(G1,G2):
 vocabulary=[]
 for each_node in G1.nodes():
  if each_node!=0:
   words=split_elements(G1.nodes[each_node]['IR'][0])
   for word in words:
    word=clean_some_case(word)
    if word not in vocabulary:
     vocabulary.append(word)
 for each_node in G2.nodes():
  if each_node!=0:
   words=split_elements(G2.nodes[each_node]['IR'][0])
   for word in words:
    word=clean_some_case(word)
    if word not in vocabulary:
     vocabulary.append(word)
 dictionary={}
 
 for index in range(0,len(vocabulary)):
  dictionary[vocabulary[index]]=index
 return dictionary 

def translate_to_dictionary_word(IR,dictionary):
 print_str=IR
 translated=[]
 words=split_elements(IR)
 for word in words:
  word=clean_some_case(word)
  translated.append(dictionary[word])
  print_str+="  "+str(word)+":"+str(dictionary[word])
 return translated,print_str
 
 
def generate_index_map_file(pair_path,index_map,arch):
 map_file_path=pair_path+"\\"+arch+'map.txt'
 f=open(map_file_path,'w')
 for key,value in index_map.items():
  f.write(key+":"+str(value)+"\n")
 f.close()  
 
def clean_some_case(word):
 if word.startswith("VAR"):#clean x64 suffix
  if word.find('.')!=-1:
   word=word.replace(".8",'')
   word=word.replace(".16",'')
   word=word.replace(".32",'')
   word=word.replace(".64",'')
   word=word.replace(".128",'')
 elif word.startswith("RETURN_"):#clean return
  word="RETURN"
 return word
 
#If pair path has the input for TADW and size>0, return true. Else false.
def already_has_valid_output(pair_path):
 TADW_input_file=[]
 print("already_has_valid_output pair_path",pair_path)
 for subdir,dirs,files in os.walk(pair_path):
  for file in files:
   if file.find("edge.csv")!=-1 or file.find("features.json")!=-1:
    TADW_input_file.append(file)
 if(len(TADW_input_file))<4:#input files incomplete
  print("already_has_valid_output False++++++++++++++++++++++++++++++++++++++++++++++++++++++++++, file num=",len(TADW_input_file)) 
  return False 
 for file in TADW_input_file:
  if file.find(".txt")!=-1:
   f=open(pair_path+"\\"+file,'r')
   content=f.read()
   size=len(content.split('\n'))
  elif file.find(".csv")!=-1:
   f = open(pair_path+"\\"+file)
   reader = csv.reader(file)
   size=len(list(reader))
  if size<=1:
   print("already_has_valid_output False++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ file:",pair_path+"\\"+file,"size=",size) 
   return False
 print("already_has_valid_output True++++++++++++++++++++++++++++++++++++++++++++++++++++++++++") 
 return True
  