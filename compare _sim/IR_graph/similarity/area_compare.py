import networkx as nx
import operator
from difflib import SequenceMatcher as sm
from .text import split_elements, get_var_list,struct_to_string
from .node_compare import IR_vs_IR, node_vs_node
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout

AREA_RADIUS=8
NODE_SIM_THRESHOLD=0.5
subgraph=nx.DiGraph()
subgraph1=nx.DiGraph()

def print_area(G):
 global AREA_RADIUS
 node=input("please enter the address:")
 while node!="q":
  level=AREA_RADIUS
  print_predecessors_area(G,node,level)
  print_successors_area(G,node,level)
  node=input("please enter the address:")
 
def print_predecessors_area(G,node,level):
 if level==-1:
  return
 global AREA_RADIUS
 print(" "*(AREA_RADIUS-level),node)
 for each_node in G.predecessors(node):
  print_predecessors_area(each_node,level-1)

def print_successors_area(G,node,level):
 if level==-1:
  return
 global AREA_RADIUS
 print(" "*(AREA_RADIUS-level),node)
 for each_node in G.successors(node):
  print_successors_area(each_node,level-1)
  
def create_context_sub_graph(G,node,boundary=AREA_RADIUS):
  global subgraph
  subgraph=nx.DiGraph()
  level=boundary
  subgraph.add_node(node,IR=str(node)+":"+str(G.nodes[node]["IR"]),mode=G.nodes[node]["mode"])
  #context_proceding_graph(G,node,level,boundary)
  context_succesor_graph(G,node,level,boundary)
  labels=nx.get_node_attributes(subgraph,"IR")
  #nx.draw_spring(subgraph,with_labels=True,labels=labels)
  pos=nx.shell_layout(subgraph)
  nx.draw(subgraph,pos,with_labels=True,labels=labels)
 # nx.draw(subgraph,pos)
  nx.draw_networkx_edge_labels(subgraph,pos,edge_labels=nx.get_edge_attributes(subgraph,'label'))
  plt.figure("ARM")

#Append the nodes to a sub graph. 
#Param 1: IR graph. 
#Param 2: current node.
#Param 3: current level.
#Param 4: the largest level you can not exceed (i.e., the boundary).
def context_proceding_graph(G,node,level,boundary):
 global subgraph
 if level==-1:
  return 
 #print(" "*(boundary-level),node)
 for each_node in G.predecessors(node):
  if each_node!=0:
   subgraph.add_node(each_node,IR=str(each_node)+":"+str(G.nodes[each_node]["IR"]),mode=G.nodes[each_node]["mode"])
   subgraph.add_edge(each_node,node,label=G[each_node][node]["label"])
   context_proceding_graph(G,each_node,level-1,boundary)
  
#Append the nodes to a sub graph. 
#Param 1: IR graph. 
#Param 2: current node.
#Param 3: current level.
#Param 4: the largest level you can not exceed (i.e., the boundary).  
def context_succesor_graph(G,node,level,boundary):
 global subgraph
 if level==-1:
  return 
 #print(" "*(boundary-level),node)
 for each_node in G.successors(node):
  if each_node!=0:
   subgraph.add_node(each_node,IR=str(each_node)+":"+str(G.nodes[each_node]["IR"]),mode=G.nodes[each_node]["mode"])
   subgraph.add_edge(node,each_node,label=G[node][each_node]["label"])
   context_succesor_graph(G,each_node,level-1,boundary)
   
def create_context_sub_graph1(G,node,boundary=AREA_RADIUS):
  global subgraph1
  subgraph1=nx.DiGraph()
  level=boundary
  subgraph1.add_node(node,IR=str(node)+":"+str(G.nodes[node]["IR"]),mode=G.nodes[node]["mode"])
  #context_proceding_graph1(G,node,level,boundary)
  context_succesor_graph1(G,node,level,boundary)
  labels=nx.get_node_attributes(subgraph1,"IR")
  #pos=graphviz_layout(subgraph1)
  pos=nx.shell_layout(subgraph1)
  nx.draw(subgraph1,pos,with_labels=True,labels=labels)
  #nx.draw(subgraph1,pos)
  nx.draw_networkx_edge_labels(subgraph1,pos,edge_labels=nx.get_edge_attributes(subgraph1,'label'))
  plt.figure("x64")
  

 
def context_proceding_graph1(G,node,level,boundary):
 global subgraph1
 if level==-1:
  return 
 #print(" "*(boundary-level),node)
 for each_node in G.predecessors(node):
  if each_node!=0:
   subgraph1.add_node(each_node,IR=str(each_node)+":"+str(G.nodes[each_node]["IR"]),mode=G.nodes[each_node]["mode"])
   subgraph1.add_edge(each_node,node,label=G[each_node][node]["label"])
   context_proceding_graph1(G,each_node,level-1,boundary)
  
def context_succesor_graph1(G,node,level,boundary):
 global subgraph1
 if level==-1:
  return 
 #print(" "*(boundary-level),node)
 for each_node in G.successors(node):
  if each_node!=0:
   subgraph1.add_node(each_node,IR=str(each_node)+":"+str(G.nodes[each_node]["IR"]),mode=G.nodes[each_node]["mode"])
   subgraph1.add_edge(node,each_node,label=G[node][each_node]["label"])
   context_succesor_graph1(G,each_node,level-1,boundary)
 
def get_context_nodes(G,node,boundary):
  level=boundary
  result_list=traverse_predecessors_area(G,node,level,boundary)
  result_list1=traverse_successors_area(G,node,level,boundary)
  result_list=merge_lists(result_list,result_list1)
  result_list=list(dict.fromkeys(result_list))
  weight_dict=calculate_node_weight(result_list,G)
  result_list.remove(node)
  return result_list,weight_dict
 
def traverse_predecessors_area(G,node,level,boundary):
 if level==-1:
  return []
 result_list=[]
 #print(" "*(boundary-level),node)
 for each_node in G.predecessors(node):
  result_list1=traverse_predecessors_area(G,each_node,level-1,boundary)
  result_list=merge_lists(result_list,result_list1)
 result_list.append(node)
 return result_list

def traverse_successors_area(G,node,level,boundary):
 if level==-1:
  return []
 result_list=[]
 #print(" "*(boundary-level),node)
 for each_node in G.successors(node):
  result_list1=traverse_successors_area(G,each_node,level-1,boundary)
  result_list=merge_lists(result_list,result_list1)
 result_list.append(node)
 return result_list 
 
 
def merge_lists(result_list,result_list1):
 for item in result_list1:
  result_list.append(item)
 return result_list

def test_dictionarilize(arm_G,x64_G):
 arm_dictionary={}
 x64_dictionary={}
 #add dictionary for arm 
 #key--VAR
 #value--expressions relevant to VAR
 for node in arm_G.nodes():
  if node!=0:
   VAR_list=get_var_list(arm_G.nodes[node]["IR"])
   for item in VAR_list:
      if item not in arm_dictionary.keys():
       arm_dictionary[item]=[[arm_G.nodes[node]["IR"],arm_G.nodes[node]["mode"],str(node)]]
      else:
       arm_dictionary[item].append([arm_G.nodes[node]["IR"],arm_G.nodes[node]["mode"],str(node)])
 #add dictionary for x64 
 #key--VAR
 #value--expressions relevant to VAR
 for node in x64_G.nodes():
  if node!=0:
   VAR_list=get_var_list(x64_G.nodes[node]["IR"])
   for item in VAR_list:
      if item not in x64_dictionary.keys():
       x64_dictionary[item]=[[x64_G.nodes[node]["IR"],x64_G.nodes[node]["mode"],str(node)]]
      else:
       x64_dictionary[item].append([x64_G.nodes[node]["IR"],x64_G.nodes[node]["mode"],str(node)])  
     
    
 return arm_dictionary,x64_dictionary
 
def test_dictionary_compare(dict1,dict2):
 
 for key1 in dict1.keys():
  for key2 in dict2.keys():
   each_list_similarity=[]
   for IR1 in dict1[key1]:
    max_sim=0
    max_IR1=""
    max_IR2=""
    max_node1=0
    max_node2=0
    #print("str(node1)=",IR1[2])
    for IR2 in dict2[key2]:
     #print("IR2 node=",IR2[2],"IR1 mode=",IR1[1],"IR2 mode=",IR2[1])
     #print("IR2=",IR2)
     if IR1[1]==IR2[1]:#if mode are the same
      sim=IR_vs_IR(IR1[0],IR2[0],IR1[1])
      if IR1[2]=="BD4":
       #print("BD4")
       if IR2[2]=="18F6":
        print("BD4-18F6",sim)
      if sim>max_sim:
       max_sim=sim
       max_IR1=IR1[0]
       max_IR2=IR2[0]
       max_node1=IR1[2]
       max_node2=IR2[2]
    #if key1=="VAR2" and key2=="VAR9.64":
     #print(max_node1,max_node2,"sim:",max_sim)
    each_list_similarity.append(max_sim)
   #print(each_list_similarity) 
   avg_sim=0
   for item in each_list_similarity:
    avg_sim+=item
   avg_sim=avg_sim*1.0/len(each_list_similarity)
   print(key1,"---",key2,"=",avg_sim)
 #return avg_sim
 
def area_similarity(G1,G2,node1,node2):
 global AREA_RADIUS
 context_nodes1,weight_dict1=get_context_nodes(G1,node1,AREA_RADIUS)
 #print("context_1",context_nodes1)
 #print("weight1",weight_list1) 
 context_nodes2,weight_dict2=get_context_nodes(G2,node2,AREA_RADIUS)
 #print("context_2",context_nodes2)
 #print("weight2",weight_list2)
 nodes1_sim=[]
 for node_1 in context_nodes1:
  if node_1==0:
   continue
  weight1=weight_dict1[node_1]
  #print("finding similar node for:",node_1)
  max_sim=0
  max_node2=0
  max_weight2=0
  for node_2 in context_nodes2:
   if node_2==0:
    continue
   weight2=weight_dict2[node_2]
   if G2.nodes[node_2]["mode"]==G1.nodes[node_1]["mode"]:
    sim=node_vs_node(G1.nodes[node_1],G2.nodes[node_2])#*((weight1+weight2)/2) 
    #print(node_1,"vs",node_2,G1.nodes[node_1]["IR"][0],"vs",G2.nodes[node_2]["IR"][0],"with",sim,"mode",G1.nodes[node_1]["mode"])
    if sim>max_sim:
     max_sim=sim
     max_node2=node_2
     max_weight2=weight2
  if max_node2!=0:
    print(node_1,"maximum similar to",max_node2,struct_to_string(G1.nodes[node_1]),"vs",struct_to_string(G2.nodes[max_node2]),"with",max_sim,"mode=",G1.nodes[node_1]["mode"])   
    #print(G1.nodes[node_1]["IR"][0],"vs",G2.nodes[max_node2]["IR"][0],"with",max_sim) 
  else:
   print(node_1,"maximum similar to none")
  nodes1_sim.append([str(node_1)+"---"+str(max_node2),max_sim,weight1,max_weight2])
 #print("area similarity (context_nodes):") 
 #for item in nodes1_sim:
 # print(item)
 sum1=0
 for item in nodes1_sim:
  sum1+=item[1]
 return(sum1*1.0/len(nodes1_sim))
 
#Within the list, the more frequence the node is,
#the less weight should it have and vice versa.
def calculate_node_weight(result_list,G):
 global NODE_SIM_THRESHOLD
 weight_dict={}
 #print("result_list",result_list)
 for node1 in result_list:
  if node1==0:
   continue
  frequence=0
  for node2 in result_list:
   if node2==0:
    continue
   if node2==node1:
    continue
   if G.nodes[node2]["mode"]==G.nodes[node1]["mode"]:
    sim=node_vs_node(G.nodes[node2],G.nodes[node1])
    if sim>=NODE_SIM_THRESHOLD:
     frequence+=1
  #print("frequency of ",node1,G.nodes[node1]["IR"],frequence)
  weight_dict[node1]=3.0/(frequence+3)
 #print("")
 return weight_dict
  
    