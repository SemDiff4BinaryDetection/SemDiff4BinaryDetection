import networkx as nx
from simplify_IR_graph import simplify_IR_graph
from similarity.text import split_elements
from similarity.learn_variable_meaning import learn_variable_meaning
from similarity.node_compare import node_vs_node
from similarity.area_compare import test_dictionarilize, test_dictionary_compare,create_context_sub_graph,create_context_sub_graph1
from similarity.IR_graph_similarity import find_anchor_sub_graph
from difflib import SequenceMatcher
import matplotlib.pyplot as plt
from pdb import set_trace as bp
import pickle
import sys
sys.setrecursionlimit(5500)

x64_conditional_jmp_map={}
arm_conditional_jmp_map={}

arm_G=nx.DiGraph()
arm_already_scaned_addresses=[]
#stores a list of:
#                  address1-->address2
arm_address_lines=[]
#stroes a list of:
#                 3ba : if VAR==0x3
arm_IR_lines=[]

x64_G=nx.DiGraph()
x64_already_scaned_addresses=[]
#stores a list of:
#                  address1-->address2
x64_address_lines=[]
#stroes a list of:
#                 3ba : if VAR==0x3
x64_IR_lines=[]

#Used in DFS traverse the graph. Record the nodes have already been accessed.
node_touched=[]


#Create two graphs, one for arm, one for x64 
#Param arm_IR_address_file_path/x64_IR_address_file_path: the file containing the address-->address 
#Param arm_IR_output_file_path/x64_IR_output_file_path: the file containing each line of IR
def create_ir_graph(arm_IR_address_file_path,arm_IR_output_file_path,input_arm_conditional_jmp_map,\
x64_IR_address_file_path,x64_IR_output_file_path,input_x64_conditional_jmp_map):
 #Firstly do some clean
 global arm_already_scaned_addresses
 global x64_already_scaned_addresses
 arm_already_scaned_addresses=[]
 x64_already_scaned_addresses=[]
 global arm_G
 global x64_G
 arm_G.clear()
 x64_G.clear()
 #Clean finished
 global arm_address_lines
 global arm_IR_lines
 global x64_address_lines
 global x64_IR_lines
 global x64_conditional_jmp_map
 global arm_conditional_jmp_map
 arm_conditional_jmp_map=input_arm_conditional_jmp_map
 x64_conditional_jmp_map=input_x64_conditional_jmp_map
 #arm_IR_address_file_path=input("please enter the ARM IR address file path:")
 #arm_IR_output_file_path=input("please enter the ARM IR output file path:")
 #x64_IR_address_file_path=input("please enter the ARM IR address file path:")
 #x64_IR_output_file_path=input("please enter the ARM IR output file path:")
 #arm_conditional_jmp_map=input("please enter the ARM conditional map path:")
 #x64_conditional_jmp_map=input("please enter the x64 conditional map path:")
 #arm_IR_address_file_path="arm_IR_output.txt"
 #arm_IR_output_file_path="arm_IR_output1.txt"
 #x64_IR_address_file_path="x64_IR_output.txt"
 #x64_IR_output_file_path="x64_IR_output1.txt"
 #x64_conditional_jmp_map=load_condition_flag("x64_IR_conditional_map.txt")
 #arm_conditional_jmp_map=load_condition_flag("arm_IR_conditional_map.txt")
 #First we create graph for arm
 print("create_ir_graph add nodes for arm_G")
 with open(arm_IR_address_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 arm_address_lines=file_content.split("\n")
 #print("arm_address_lines=",arm_address_lines)
 with open(arm_IR_output_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 arm_IR_lines=file_content.split("\n")
 #print("arm_IR_lines=",arm_IR_lines)
 iterate_add_nodes(arm_address_lines[0],0,0)
 
 #Next we create graph for x64
 print("create_ir_graph add nodes for x64")
 with open(x64_IR_address_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 x64_address_lines=file_content.split("\n")
 #print("address_lines",address_lines)
 with open(x64_IR_output_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 x64_IR_lines=file_content.split("\n")
 iterate_add_nodes(x64_address_lines[0],0,1)
 
##Create one graph.
#Param arm_IR_address_file_path/x64_IR_address_file_path: the file containing the address-->address 
def create_ir_graph_from_pickle_single(IR_address_file_path,IR_output_pickle_file_path):
 global arm_address_lines
 global arm_IR_lines
 #print("create_ir_graph_from_pickle_single IR_address_file_path=",IR_address_file_path,"IR_output_pickle_file_path=",IR_output_pickle_file_path)
 print("create_ir_graph_pickle_single add nodes for arm_G")
 with open(IR_address_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 arm_address_lines=file_content.split("\n")
 
 IR_file=open(IR_output_pickle_file_path,'rb')
 try:
  arm_IR_lines=pickle.load(IR_file)
 except:
  bp()
 IR_file.close()
 #print("create_ir_graph_from_pickle_single arm_address_lines=",arm_address_lines)
 #print("create_ir_graph_from_pickle_single arm_IR_lines=",arm_IR_lines)
 iterate_add_nodes_pickle(arm_address_lines[0],0,0)
 global arm_G
 print("create_ir_graph_from_pickle_single len(G.nodes())=",len(arm_G.nodes()),"len(arm_IR_lines)=",len(arm_IR_lines),"len(arm_address_lines)=",len(arm_address_lines))
 delete_loop_add_while(0)
 
 
 
#Create two graphs, one for arm, one for x64 
#Param arm_IR_address_file_path/x64_IR_address_file_path: the file containing the address-->address 
#Param arm_IR_output_file_path/x64_IR_output_file_path: the file containing each line of IR
def create_ir_graph_from_pickle(arm_IR_address_file_path,arm_IR_output_pickle_file_path,\
x64_IR_address_file_path,x64_IR_output_pickle_file_path):
 #Firstly do some clean
 global arm_already_scaned_addresses
 global x64_already_scaned_addresses
 arm_already_scaned_addresses=[]
 x64_already_scaned_addresses=[]
 global arm_G
 global x64_G
 arm_G.clear()
 x64_G.clear()
 #Clean finished
 global arm_address_lines
 global arm_IR_lines
 global x64_address_lines
 global x64_IR_lines
 global x64_conditional_jmp_map
 global arm_conditional_jmp_map
 
 print("create_ir_graph_pickle add nodes for arm_G")
 with open(arm_IR_address_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 arm_address_lines=file_content.split("\n")
 #print("arm_address_lines=",arm_address_lines)
 IR_file=open(arm_IR_output_pickle_file_path,'rb')
 arm_IR_lines=pickle.load(IR_file)
 IR_file.close()
 #print("arm_IR_lines=",arm_IR_lines)
 #try:
 iterate_add_nodes_pickle(arm_address_lines[0],0,0)
 delete_loop_add_while(0)
 #except RecursionError as re:
 # return "RecursionError"
 
 #Next we create graph for x64
 print("create_ir_graph_pickle add nodes for x64")
 with open(x64_IR_address_file_path) as IR_file:
   file_content = IR_file.read()
 IR_file.close()
 x64_address_lines=file_content.split("\n")
 #print("x64_address_lines",x64_address_lines)
 IR_file=open(x64_IR_output_pickle_file_path,'rb')
 x64_IR_lines=pickle.load(IR_file)
 IR_file.close()
 #try:
 iterate_add_nodes_pickle(x64_address_lines[0],0,1)
 delete_loop_add_while(1)
 #print("create_ir_graph_from_pickle done")
 #except RecursionError as re:
 # return "RecursionError" 
 
#DFS traverse the graph. If find an edge goes to this node's ancestor, that means find the loop. Delete this edge and look backward for "while" comparing node.
def delete_loop_add_while(arch):
 global node_touched
 if arch==0:
  G=arm_G
 elif arch==1:
  G=x64_G
 node_touched=[]
 node_touched.append(0)
 #print("DFS_traverse nodes=",list(G.nodes()))
 if 0 in list(G.nodes()):
  DFS_traverse(G,0,[])
 #bp()
 
#DFS traverse the graph. Parameter 1: graph, Parameter 2: current node, Parameter 3: history accessed nodes in this DFS path (i.e., ancestors of current node through this DFS path) The history_nodes does not include current node.
def DFS_traverse(G,node,history_nodes):
 global node_touched
 #print("DFS_traverse nodes=",list(G.nodes()))
 children_list=list(G.successors(node))
 #print("DFS_traverse children_list=",list(children_list))
 for child in children_list:
  if child==node:#an edge connecting self
   G.remove_edge(node,child)
   G.nodes[child]['IR'][0]=["while"]+G.nodes[child]['IR'][0]
   print("deleted loop edge from ",node,"to",child,"G.nodes[while_cmp_node]['IR'][0]=",G.nodes[child]['IR'][0])
  elif child not in history_nodes and child not in node_touched:#If endge to this child does not imply a loop and the child has not been accessed before
   node_touched.append(child)#Record the child node as the accessed node
   new_history_nodes=history_nodes+[node]#Record the child as the node in the DFS path.
   DFS_traverse(G,child,new_history_nodes)
  elif child in history_nodes:#If endge to this child imply a loop, this also imply this child has been touched
   G.remove_edge(node,child)
   while_cmp_node=look_back4while_cmp(G,history_nodes,child)
   G.nodes[while_cmp_node]['IR'][0]=["while"]+G.nodes[while_cmp_node]['IR'][0]
   print("deleted loop edge from ",node,"to",child,"G.nodes[while_cmp_node]['IR'][0]=",G.nodes[while_cmp_node]['IR'][0])
  elif child in node_touched:#If the endge to this child does not imply a loop but thie child has been touched
   continue
   
#Given a DFS path history_nodes, find the "while" cmp instruction after the node loop_poin. Because the structure should look like: loop_point-->"while" cmp node-->loop_point
def look_back4while_cmp(G,history_nodes,loop_point):
 loop_point_index=history_nodes.index(loop_point)
 for index in range(len(history_nodes)-1,loop_point_index,-1): #From last item to loop_point to reversely visit node
  if G.nodes[history_nodes[index]]['mode']==2:
   return history_nodes[index]#If we found there is such a node and it is a cmp instruction, then this should be the while cmp node.
 return  history_nodes[-1]#Other wise, this should be an infinite loop. There is no while cmp node, we just deem last node as the while node
 
#Iteratively add key IR into graphs. This is done in a recursion.
#Parameter1: IR string
#Parameter2: last key IR
#Parameter3: architecture. arm:0 x64:1
def iterate_add_nodes(address_line,latest_address,arch):
 global arm_already_scaned_addresses
 global x64_already_scaned_addresses
 if arch==0:
  G=arm_G
  already_scaned_addresses=arm_already_scaned_addresses
 elif arch==1:
  G=x64_G
  already_scaned_addresses=x64_already_scaned_addresses
 address=address_line.split("-->")[0]
 string_list=get_IR_string(address_line,arch)
 next_addresses=get_next_addresses(address_line)
 #print("iterate_add_nodes address_line",address_line,"next_addresses",next_addresses)
 if already_in_IR_graph(address_line,arch):
  next_IR=get_next_IR_address(address_line,arch)
  if next_IR!=None:
   label=find_flag(latest_address, next_IR, arch)
   #print("added label",label)
   G.add_edge(latest_address,next_IR,label=label)
   #if (latest_address=='1555' and next_IR=='1555') or (latest_address=='1588' and next_IR=='1588'):
   # bp()
  return
 already_scaned_addresses.append(address)
 #current node has IR
 if(len(string_list)!=0):
  for index in range(0,len(string_list)):
   string_list[index]=string_list[index].replace("+-",'-')
  G.add_node(address,IR=string_list,mode=None)
  #print("added node",address)
  label=find_flag(latest_address, address, arch)
  #print("added label",label)
  G.add_edge(latest_address,address,label=label)
  #if (latest_address=='1555' and address=='1555') or (latest_address=='1588' and address=='1588'):
  #  bp()
  for item in next_addresses:
   #print("next address:",item,"of the address_line:",address_line)
   if item!='':
    next_address_line=find_address_line(item,arch)
    #print("iterate_add_nodes next_address_line",next_address_line,"address",address,"latest_address",latest_address,"address_line",address_line)
    iterate_add_nodes(next_address_line,address,arch)
 #current node does not have IR
 else: 
   for item in next_addresses:
    #print("next address:",item,"of the address_line:",address_line)
    if item!='':
     next_address_line=find_address_line(item,arch)
     #print("iterate_add_nodes next_address_line",next_address_line,"latest_address",latest_address,"address_line",address_line)
     iterate_add_nodes(next_address_line,latest_address,arch)
  
#Iteratively add key IR into graphs. This is done in a recursion.
#Parameter1: IR string
#Parameter2: last key IR
#Parameter3: architecture. arm:0 x64:1
def iterate_add_nodes_pickle(address_line,latest_address,arch):
 global arm_already_scaned_addresses
 global x64_already_scaned_addresses
 if arch==0:
  G=arm_G
  already_scaned_addresses=arm_already_scaned_addresses
 elif arch==1:
  G=x64_G
  already_scaned_addresses=x64_already_scaned_addresses
 #print("iterate_add_nodes address_line",address_line,"latest_address",latest_address)
 #print("iterate_add_nodes_pickle address_line=",address_line)
 if(address_line==None):#For some case, the address file (...-->...) might contain non-existance addresses that belong to other functions, we just ignore them.
  return   
 address=address_line.split("-->")[0]
 IR_struct=get_IR_struct_pickle(address_line,arch)
 #print("iterate_add_nodes_pickle IR_struct=",IR_struct)
 next_addresses=get_next_addresses(address_line)
 #print("iterate_add_nodes_pickle next_addresses=",next_addresses,"address_line=",address_line)
 if already_in_IR_graph(address_line,arch):
  next_IR=get_next_IR_address_pickle(address_line,arch)
  #print("next_IR=",next_IR)
  if next_IR!=None:
   #label=find_flag(latest_address, next_IR, arch)
   #print("added label",label)
   G.add_edge(latest_address,next_IR)
   #print("iterate_add_nodes_pickle added edge",latest_address,next_IR)
   #G.add_edge(latest_address,next_IR,label=label)
   #if (latest_address=='1555' and next_IR=='1555') or (latest_address=='1588' and next_IR=='1588'):
   # bp()
  return
 already_scaned_addresses.append(address)
 #current node has IR
 if(IR_struct!=None):
  G.add_node(address,IR=[IR_struct.IR],mode=IR_struct.mode)
  #print("added node",address,"next_addresses=",next_addresses)
  #label=find_flag(latest_address, address, arch)
  #print("added label",label)
  G.add_edge(latest_address,address)
  #print("iterate_add_nodes_pickle added edge",latest_address,address)
  #G.add_edge(latest_address,address,label=label)
  #if (latest_address=='1555' and address=='1555') or (latest_address=='1588' and address=='1588'):
  #  bp()
  for item in next_addresses:
   #print("next address:",item,"of the address_line:",address_line)
   if item!='':
    next_address_line=find_address_line(item,arch)
    #print("iterate_add_nodes next_address_line",next_address_line,"address",address,"latest_address",latest_address,"address_line",address_line)
    try:
        iterate_add_nodes_pickle(next_address_line,address,arch)
    except RecursionError as re:
        print("iterate_add_nodes_pickle: RecursionError")
        return
 #current node does not have IR
 else: 
   for item in next_addresses:
    #print("next address:",item,"of the address_line:",address_line)
    if item!='':
     next_address_line=find_address_line(item,arch)
     #print("iterate_add_nodes next_address_line",next_address_line,"latest_address",latest_address,"address_line",address_line)
     try:
       iterate_add_nodes_pickle(next_address_line,latest_address,arch)
     except RecursionError as re:
       print("iterate_add_nodes_pickle: RecursionError")
       return
     
     
     
     
#Get IR string according to which graph, and which address
#For example, for:
#                  addr1-->addr2
#find IR string: 
#                  addr1; if VAR2==3
#Parameter1: address 
#Parameter2: architecture. arm:0 x64:1
def get_IR_string(address_line,arch):
 global arm_IR_lines
 global x64_IR_lines
 if arch==0:
  IR_lines=arm_IR_lines
 elif arch==1:
  IR_lines=x64_IR_lines
 #print("get_IR_string address_line",address_line)
 #print("get_IR_string IR_lines",IR_lines)
 address=address_line.split("-->")[0]
 for line in IR_lines:
  if address==line.split(";")[0]:
   result_list=list(filter(None,line.split(";")[1:]))
   return result_list
  

#Get IR structure according to which graph, and which address
#For example, for:
#                  addr1-->addr2
#find IR structure: 
#                  addr1; if VAR2==3
#Parameter1: address 
#Parameter2: architecture. arm:0 x64:1  
def get_IR_struct_pickle(address_line,arch):
 global arm_IR_lines
 global x64_IR_lines
 if arch==0:
  IR_lines=arm_IR_lines
 elif arch==1:
  IR_lines=x64_IR_lines
 #print("get_IR_string address_line",address_line)
 #print("get_IR_string IR_lines",IR_lines)
 address=address_line.split("-->")[0]
 if address in IR_lines:#If this address exists in the Key IR dictionary
  return IR_lines[address]
 else:
  return None

 
#Get next addresses. For example:
#                               address1-->address2, address3
#                               return address2, address3
#Parameter1: address1-->address2, address3
def get_next_addresses(address_line):
 #print("address_line="+address_line)
 next_addresses=address_line.split("-->")[1].split(",")
 return next_addresses
  
#Check if this address has already been scanned. 
#Parameter1: address line
#Parameter2: architecture. arm:0 x64:1
def already_in_IR_graph(address_line,arch):
 global arm_already_scaned_addresses
 global x64_already_scaned_addresses
 if arch==0:
  already_scaned_addresses=arm_already_scaned_addresses
 elif arch==1:
  already_scaned_addresses=x64_already_scaned_addresses
 address=address_line.split("-->")[0]
 if address in already_scaned_addresses:
  #print("already_in_IR_graph True")
  return True
 #print("already_in_IR_graph False") 
 return False
 
def main():
 global arm_G
 global x64_G

 create_ir_graph()
 
 arm_G=simplify_IR_graph(arm_G)
 x64_G=simplify_IR_graph(x64_G)
 #find_anchor_sub_graph(arm_G,x64_G)
 while True: 
  show_neighbour(arm_G,x64_G)
 #while True:
 # arm_node=input("Please enter an arm node:")
 # for each_node in arm_G.successors(arm_node):
 #  print(each_node)
 # if arm_node=='q':
 #  break
 
 #Create and simplify two IR graphs
 #plt.figure("ARM")
 #nx.draw(arm_G,with_labels=True)
 #plt.figure("x64")
 #nx.draw(x64_G,with_labels=True)
 #plt.show()
 
 #Learn variable meanings
 #combined_list=combine_two_IRs(arm_G,x64_G)
 #learn_variable_meaning(combined_list)
 #test_node_vs_node(arm_G,x64_G)
 #arm_dict,x64_dict=test_dictionarilize(arm_G,x64_G)
 '''print("arm_dict")
 for key in arm_dict.keys():
  print(key)
  for item in arm_dict[key]:
   print(item)
  print("")
 print("x64_dict")
 for key in x64_dict.keys():
  print(key)
  for item in x64_dict[key]:
   print(item)
  print("")'''
 #test_dictionary_compare(arm_dict,x64_dict)
 '''while True:
  arm_node=input("Please enter an arm node:")
  x64_node=input("Please enter a x64 node:")
  node_vs_node(arm_G.nodes[arm_node],x64_G.nodes[x64_node])'''
 '''arm_node=''
 while True:
  arm_node=input("Please enter an arm node:")
  print(arm_node.successors(arm_node))
  if arm_node=='q':
   break
  print(arm_G.nodes[arm_node])
  
  
 x64_node=''
 while True:
  x64_node=input("Please enter a x64 node:")
  if x64_node=='q':
   break
  print(x64_G.nodes[x64_node])'''

#Return IR string based on address.
#Parameter 1: address
#Parameter 2: architecture. arm:0 x64:1
def find_address_line(address,arch):
 global arm_address_lines
 global x64_address_lines
 if arch==0:
  address_lines=arm_address_lines
 elif arch==1:
  address_lines=x64_address_lines
 #print("find_address_line("+address+")")
 #print("lines:")
 #print(address_lines)
 for line in address_lines:
  #print(line.split("-->")[0])
  if address==line.split("-->")[0]:
   return line
   
#When some IR execute to this address line, and this address line is already scaned.
#We need to add an edge between the last IR and the nearest subsequent IR to this 
#address, not an edge between the last IR and this address line.
#Parameter 1: the already scanned address line i.e., a starting node in the loop
#Parameter 2: architecture. arm:0 x64:1
def get_next_IR_address(address_line,arch):
 
 #print("get_next_IR_address address_line",address_line) 
 address_to_address=address_line
 if is_IR_address(address_to_address.split("-->")[0],arch):
  #print("get_next_IR_address address_to_address.split(-->)[0]=",address_to_address.split("-->")[0])
  return address_to_address.split("-->")[0]
 #print("address_to_address.split(\"-->\")[1]",address_to_address.split("-->")[1].split(','))
 list1=address_to_address.split("-->")[1].split(',')
 while len(list(filter(None,list1)))==1:
  if is_IR_address(list1[0],arch):
   #print("get_next_IR_address list1[0]=",list1[0])
   return list1[0]
  else:
   address=address_to_address.split("-->")[1].split(',')[0]
   address_to_address=find_address2address(address,arch)
   #print("get_next_IR_address address_to_address",address_to_address)
   list1=address_to_address.split("-->")[1].split(',')
   #print("next address:",address,"address2address:",address_to_address)
   
#When some IR execute to this address line, and this address line is already scaned.
#We need to add an edge between the last IR and the nearest subsequent IR to this 
#address, not an edge between the last IR and this address line.
#Parameter 1: the already scanned address line i.e., a starting node in the loop
#Parameter 2: architecture. arm:0 x64:1
def get_next_IR_address_pickle(address_line,arch):
 
 #print("get_next_IR_address address_line",address_line) 
 address_to_address=address_line
 if is_IR_address_pickle(address_to_address.split("-->")[0],arch):
  #print("get_next_IR_address address_to_address.split(-->)[0]=",address_to_address.split("-->")[0])
  return address_to_address.split("-->")[0]
 #print("address_to_address.split(\"-->\")[1]",address_to_address.split("-->")[1].split(','))
 list1=address_to_address.split("-->")[1].split(',')
 loop_start_address=address_to_address#This parameter records the first address for the next while loop, in case that a-->b, b-->c, c-->a. Once we found a-->b been hit twice, that means an infinite loop and we should terminate.
 while len(list(filter(None,list1)))==1:
  if is_IR_address_pickle(list1[0],arch):
   #print("get_next_IR_address list1[0]=",list1[0])
   return list1[0]
  else:
   address=address_to_address.split("-->")[1].split(',')[0]
   address_to_address=find_address2address(address,arch)
   if address_to_address==loop_start_address:#Once we found a-->b been hit twice, that means an infinite loop
    return None
   #print("get_next_IR_address address_to_address:",address_to_address, "address:",address)
   list1=address_to_address.split("-->")[1].split(',')
   #print("next address:",address,"address2address:",address_to_address)

#Return "address1-->address2" for a given address1
def find_address2address(address,arch):
 #print("find_address2address with",address)
 global x64_address_lines
 global arm_address_lines
 if arch==0:
  address_lines=arm_address_lines
 elif arch==1:
  address_lines=x64_address_lines
 for address_to_address in address_lines:
  if address_to_address.split("-->")[0]==address:
   return address_to_address
  
#Test whether given address is key IR or not
def is_IR_address(address,arch):
 global x64_IR_lines
 global arm_IR_lines
 if arch==0:
  IR_lines=arm_IR_lines
 elif arch==1:
  IR_lines=x64_IR_lines
 for each_line in IR_lines:
  if each_line.split(';')[0]==address:
   if each_line.split(';')[1]!="":
    #print("is_IR_address is True for",address)
    return True
   else:
    #print("is_IR_address is False for",address)
    return False
    
#Test whether given address is key IR or not
def is_IR_address_pickle(address,arch):
 global x64_IR_lines
 global arm_IR_lines
 if arch==0:
  IR_lines=arm_IR_lines
 elif arch==1:
  IR_lines=x64_IR_lines
 if address in IR_lines:
  return True
 else:
  return False 

def print_nodes(G):
 for node in G.nodes():
  if node!=0:
   print(node,": ",G.nodes[node]['IR'])
   
  
def combine_two_IRs(G1,G2):
 combined_list=[]
 for node in G1.nodes():
  if node!=0:
   combined_list.append(split_elements(G1.nodes[node]["IR"].replace(" ","")))
 for node in G2.nodes():
  if node!=0:
   combined_list.append(split_elements(G2.nodes[node]["IR"].replace(" ","")))
 return combined_list
 
 
def show_neighbour(G1,G2):
 node1=input("please enter an arm node")
 node2=input("please enter an x64 node")
 create_context_sub_graph(G1,node1)
 create_context_sub_graph1(G2,node2)
 plt.show()
 
def load_condition_flag(file_path):
 result_map={}
 with open(file_path) as f:
  content=f.read()
 f.close() 
 lines=content.split('\n')
 for line in lines:
  if line!="":
   key=line.split(';')[0]
   value=line.split(';')[1]
   result_map[key]=value
 return result_map
 
def find_flag(from_node, to_node, arch):
 key=str(from_node)+"-->"+str(to_node)
 key=key.lower()
 #print("key=",key)
 if arch==0:#arm
  if key not in arm_conditional_jmp_map:
   return ""
  else:
   return arm_conditional_jmp_map[key]
 elif arch==1:#x64
  if key not in x64_conditional_jmp_map:
   return ""
  else:
   return x64_conditional_jmp_map[key]
 
#main()
'''s1="RETURN_BD4 ([((VAR1-0x9C0)-4)+0x9E8+var_9D0],(6-[VAR2+0x9DC])&7,0 )"
s2="RETURN_18F6 (((VAR2.64-RETURN_1441)+10F8h+var_1048),((-[VAR9.64+24]+0xFFFFFFFB)&7),ITVAR37.32 )"
from similarity.node_compare import node_vs_node
print(node_vs_node(s1,s2,4))'''
#from similarity.node_compare import IR_vs_IR
#IR_vs_IR("if @32[VAR2 + 0x1340]==0x0","if @32[VAR9.64 + 0x870]==0x0",2)