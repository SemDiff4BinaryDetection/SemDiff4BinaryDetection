#ACCEPT_AREA_THRESHOLD
#ACCEPT_NODE_THRESHOLD
#ACCEPT_PARAM_NUM
#from .area_compare import area_similarity
from .node_compare import node_vs_node, IR_vs_IR,ACCEPT_IR_THRESHOD
from .text import struct_to_string
from .sequence_nodes_compare import generate_nodes_similarity_matrix,generate_sequence_starting_at_node,compare_two_sequences_lists_similarity
from pdb import set_trace as bp
from random import randint
import networkx as nx
from datasketch import MinHash

def compare_graph():
 node_pair=find_anchor_sub_graph()
 #for each_pair in node_pair:
  #find_common_sub_graph(each_pair,G1,G2)
  
  
#Check whether two graph contain similar number of nodes. If not at same scale, just decide them unsimilar
def not_same_scale(G1_node_num,G2_node_num):
 if G1_node_num>=G2_node_num*2 or G1_node_num*2<=G2_node_num:
  print("G1",G1_node_num,"nodes","G2",G2_node_num,"nodes! not same scale!")
  return True
 else:
  return False
  
def find_common_sub_graph(each_pair):
 sub_graph1=get_sub_graph(each_pair[0],G1)
 sub_graph2=get_sub_graph(each_pair[1],G2)
 node_pair=map_two_sub_graphs(sub_graph1,sub_graph2)
 for pair in node_pair:
  find_common_sub_graph(pair,G1,G2)
  
#4 types of IR to process:
#              1....=...
#              2.if...==...
#              3....
#              4.function(..,..,..)
#              5.return
def find_anchor_sub_graph(G1,G2): 
  memory_address1,compare1,expression1,calling1,return_1=classify_each_node(G1)
  memory_address2,compare2,expression2,calling2,return_2=classify_each_node(G2)
  memory_address_sim=[]
  compare_sim=[]
  expression_sim=[]
  calling_sim=[]
  return_sim=[]
 
  
  if len(calling1)>0 and len(calling2)>0:
   #print("calling1",calling1)
   #print("calling2",calling2)
   #for node1 in calling1:
   for node1 in calling1:
    max_sim=0
    max_node2=""
    for node2 in calling2:#area_similarity
     # print("set ",node1," and ",node2," as anchor points")
     node_sim=node_vs_node(G1.nodes[node1],G2.nodes[node2])
     area_sim=area_similarity(G1,G2,node1,node2)
     sim=0.6*node_sim+0.4*area_sim
     if sim>max_sim:
      max_sim=sim
      max_node2=node2
    string=node1+"---"+str(max_node2)+"="+str(max_sim)
    print(string)
    #calling_sim.append([string,max_sim]) 
  
  
  '''if len(compare1)>0 and len(compare2)>0:
   print("compare1",compare1)
   print("compare2",compare2)
   for node1 in compare1:
    max_sim=0
    for node2 in compare2:
     print("set ",node1," and ",node2," as anchor points")
     sim=area_similarity(G1,G2,node1,node2)
     if sim>max_sim:
      max_sim=sim
    compare_sim.append(max_sim) 
  print("compare",compare_sim)
   
  if len(memory_address1)>0 and len(memory_address2)>0:
   print("memory_address1",memory_address1)
   print("memory_address2",memory_address2)
   for node1 in memory_address1:
    max_sim=0
    for node2 in memory_address2:
     print("set ",node1," and ",node2," as anchor points")
     sim=area_similarity(G1,G2,node1,node2)
     if sim>max_sim:
      max_sim=sim
    memory_address_sim.append(max_sim)  
  print("memory address",memory_address_sim)  
  
  if len(expression1)>0 and len(expression2)>0:
   print("expression1",expression1)
   print("expression2",expression2)
   for node1 in expression1:
    max_sim=0
    for node2 in expression2:
     print("set ",node1," and ",node2," as anchor points")
     sim=area_similarity(G1,G2,node1,node2)
     if sim>max_sim:
      max_sim=sim
    expression_sim.append(max_sim) 
  print("expression",expression_sim)
  
  if len(return_1)>0 and len(return_2)>0:
   print("return_1",return_1)
   print("return_2",return_2)
   for node1 in return_1:
    max_sim=0
    for node2 in return_2:
     print("set ",node1," and ",node2," as anchor points")
     sim=area_similarity(G1,G2,node1,node2)
     if sim>max_sim:
      max_sim=sim
    return_sim.append(max_sim) 
  print("return",return_sim) '''
   
   
# We first find calling instruction as anchor point
# secondly find if-else instruction as anchor point
# thirdly find other instruction as anchor point
# finally find other instruction as anchor point
def classify_each_node(G):
  memory_address=[] 
  compare=[]
  expression=[]
  calling=[]
  return_=[]
  for node in G.nodes():
   if node==0:
    continue
   if G.nodes[node]['mode']==4:
    calling.append(node)
   elif G.nodes[node]['mode']==2:
    compare.append(node)
   elif G.nodes[node]['mode']==1:
    memory_address.append(node)
   elif G.nodes[node]['mode']==3:
    expression.append(node)
   elif G.nodes[node]['mode']==5:
    return_.append(node)
  return memory_address,compare,expression,calling,return_
 
#This function simply checks all the node in G1 to find their max similarity in G2. Then we average each node's similarity. We do not compare nodes' context or neighbour, only this node.
def compare4all_nodes(G1,G2):
 global ACCEPT_IR_THRESHOD
 total_sim=0
 len1=0
 for node1 in G1.nodes():#For each node in G1
  if node1!=0:
   IR1=G1.nodes[node1]["IR"][0]
   max_sim=0
   max_node2=""
   for node2 in G2.nodes():#For each node in G2
    if node2!=0:
     IR2=G2.nodes[node2]["IR"][0]
     if G1.nodes[node1]["mode"]==G2.nodes[node2]["mode"]:#If two nodes have same mode
      text_sim=IR_vs_IR(IR1,IR2,G1.nodes[node1]["mode"])
      #if G1.nodes[node1]["mode"]==2:
      # print("sim:",text_sim,node1,"vs",node2,struct_to_string(G1.nodes[node1]),"            ",struct_to_string(G2.nodes[node2]),"mode=",G1.nodes[node1]["mode"]) 
      if text_sim>max_sim:
       max_sim=text_sim
       max_node2=node2
   total_sim+= max_sim
   len1+=1
   if max_sim!=0:    
    print("sim:",max_sim,node1,"vs",max_node2,struct_to_string(G1.nodes[node1]),"            ",struct_to_string(G2.nodes[max_node2]),"mode=",G1.nodes[node1]["mode"])
   elif max_sim==0:
    print(node1,"has no similar nodes")
 return ("total similarity:",total_sim*1.0/len1)   
      #if(text_sim>=ACCEPT_IR_THRESHOD):#If two nodes' IR textual similarity above threshold
      # area_sim=area_similarity(G1,G2,node1,node2)
      # print(node1,"vs",node2,IR1,"vs",IR2,"=",area_sim)
       
#Given two nodes, compare their similarity. This is based on just the node's similarity. That is, for each node in G1, we check its max similarity node in G2. We do not compare nodes' context or neighbour, only this node.
def compare_specific_pair(G1,G2):
 node1=input("Please enter node1:")
 #node2=input("Please enter node2:")
 for node2 in G2.nodes():
  if node2==0:
   continue
  IR1=G1.nodes[node1]["IR"][0]
  IR2=G2.nodes[node2]["IR"][0]
  if G1.nodes[node1]["mode"]==G2.nodes[node2]["mode"]:#If two nodes have same mode
   text_sim=IR_vs_IR(IR1,IR2,G1.nodes[node1]["mode"])
   print("sim:",text_sim,node1,"vs",node2,struct_to_string(G1.nodes[node1]),"            ",struct_to_string(G2.nodes[node2]),"mode=",G1.nodes[node1]["mode"])   
'''def find_corresponding_node(node1,mode):
 global ACCEPT_NODE_THRESHOLD, ACCEPT_AREA_THRESHOLD
 for node2 in G2.nodes():
   node_vs_node_score=node_vs_node(node1,node2,mode)
   area_vs_area_score=0
   if node_vs_node_score>=ACCEPT_NODE_THRESHOLD:
    area_vs_area_score, node_pair=area_vs_area(node1,node2)
    if area_vs_area_score>=ACCEPT_AREA_THRESHOLD:
      return area_vs_area_score, node_pair'''
      
      
#This function checks all the node in G1 to find their max similarity in G2 with the assistance of sequence similarity. Then we average each node's similarity.
def compare4all_nodes_sequence_assisted(G1,G2,sequence_length):
 global ACCEPT_IR_THRESHOD
 total_sim=0
 len1=0
 similar_matrix=generate_nodes_similarity_matrix(G1,G2)#Amatrix decribing node-to-node similarity
 #print("compare4all_nodes_sequence_assisted sim_matrix:",similar_matrix)
 #if not_same_scale(len(G1.nodes()),len(G2.nodes())):
 # return 0
  
 if len(G1.nodes())>100:#If G1 has too many nodes, for efficiency, we extract beginning random subset of nodes for comparison.
 # G1_nodes_for_cmp=random_extract_node1(G1,100)
  G1_nodes_for_cmp=random_extract_node2(G1,100)
 else:
  G1_nodes_for_cmp=G1.nodes()
  
 #if len(G2.nodes())>100:#If G1 has too many nodes, for efficiency, we extract beginning random subset of nodes for comparison.
 # G2_nodes_for_cmp=random_extract_node1(G2,100)
 #else:
 # G2_nodes_for_cmp=G2.nodes()
 for node1 in G1_nodes_for_cmp:#For comparing nodes in G1
  #print("node1:",node1)
  if node1!=0:
   IR1=G1.nodes[node1]["IR"][0]#Get node1 content
   sequences1=generate_sequence_starting_at_node(G1,node1,sequence_length)#Get sequence of nodes starting from node1
   potential_node2s=[]#Storing potentially similar node 2s if their textual similarity >=0.5
   potential_node_similarity=[]#Storing bare-node similarity of node1 and node2
   print("node",node1,len(G1.nodes()),"nodes compare to ",len(G2.nodes()),"nodes!")
   for node2 in G2.nodes():#For each node in G2
    if node2!=0:
     IR2=G2.nodes[node2]["IR"][0]#Get node2 content
     if G1.nodes[node1]["mode"]==G2.nodes[node2]["mode"]:#If two nodes have same mode
      text_sim=IR_vs_IR(IR1,IR2,G1.nodes[node1]["mode"])
      if text_sim>ACCEPT_IR_THRESHOD:
       potential_node2s.append(node2)
       potential_node_similarity.append(text_sim)
   max_sim=0
   max_node2=None   
   print("node1",node1,"potential similar nodes:",len(potential_node2s))
   for potential_node2,bare_node_sim in zip(potential_node2s,potential_node_similarity):#For each potential node2, we calculate sequence similarity with node1
    sequences2=generate_sequence_starting_at_node(G2,potential_node2,sequence_length)#Get sequence of nodes starting from node2  
    #print("potential nodes:",potential_node2,"sequence1 len=",len(sequences1),"sequence2 len=",len(sequences2))
    #print("sequence1 len=",len(sequences1),"potential_node2",potential_node2,"sequence2 len=",len(sequences2))
    #if sequences2[0][0]=='420F0':
    # for i in sequences2:
    #  print(i)
    # for i in G2.successors(potential_node2):
    #  print(potential_node2,"successor:",i)
    # print()
    # bp()
    #print("compare4all_nodes_sequence_assisted sequences1:",sequences1,"sequences2:",sequences2)
    sequences_sim=compare_two_sequences_lists_similarity(sequences1,sequences2,similar_matrix)
    #print("compare4all_nodes_sequence_assisted sequences1:",sequences1,"sequences2",sequences2,"sim=",sequences_sim)
    if sequences_sim>=ACCEPT_IR_THRESHOD:#If sequences of node1 and node2 are similar, we deem node2 similar to node1.
     max_sim=bare_node_sim
     max_node2=potential_node2
     #print("compare4all_nodes_sequence_assisted sequences1:",sequences1,"sequences2",sequences2,"sim=",sequences_sim)
   total_sim+= max_sim#For node1, it compares to all potential node2's sequences (neighbour). If neighbour similarity>=0.5, we deem node1 and node2's bare node similarity as their similarity.
   len1+=1
   if max_sim!=0:    
    print("sim:",max_sim,node1,"vs",max_node2,struct_to_string(G1.nodes[node1]),"            ",struct_to_string(G2.nodes[max_node2]),"mode=",G1.nodes[node1]["mode"])
   elif max_sim==0:
    print(node1,"has no similar nodes")
 #return ("total similarity:",total_sim*1.0/len1)
 print("compare4all_nodes_sequence_assisted total_sim=",total_sim)
 if len1==0:
  return 0
 else: 
  return total_sim*1.0/len1
      #if(text_sim>=ACCEPT_IR_THRESHOD):#If two nodes' IR textual similarity above threshold
      # area_sim=area_similarity(G1,G2,node1,node2)
      # print(node1,"vs",node2,IR1,"vs",IR2,"=",area_sim)      
      
#When the graph contains too many nodes, for efficiency, we need to extract a subset of these nodes for further comparison. Given a node and a maximum depth, we extract nodes within the depth from the beginning of the graph.
#Param 1: Graph
#Param 2: maximum depth of extracted nodes
def random_extract_node(G,max_depth):
 random_nodes=[]#Extracted random nodes
 G_all_nodes=list(G.nodes())#G's all nodes
 #print(G_all_nodes)
 node_list=get_successor_nodes(G,0,max_depth)
 return node_list
 #print("random_extract_node node_list=",node_list)
 #bp()
 #while len(random_nodes)<node_num:
 # random_num=randint(0,len(G_all_nodes)-1)
 # random_nodes.append(G_all_nodes[random_num])
 # del G_all_nodes[random_num]
 #return random_nodes  
 
#Given a graph and the number of nodes, returns the topologically first node_num nodes. This functions uses the breadth first search to find the first node_num nodes.
def random_extract_node1(G,node_num):
 total_node_list=[]
 node_list=[0]#graph starting node
 while len(total_node_list)<100:
  new_node_list=[]
  for node in node_list:
   for each_node in G.successors(node):
    #print("random_extract_node1 each_node=",each_node)
    new_node_list.append(each_node)
  new_node_list=list(dict.fromkeys(new_node_list))#remove duplicate nodes
  node_list=new_node_list
  total_node_list=merge_list(total_node_list,node_list)
  #print("random_extract_node1 node_list=",node_list)
 return total_node_list
 
#Randomly select node_num nodes from graph G.
def random_extract_node2(G,node_num):
 all_nodes=[]
 for node in G.nodes():
  if node!=0:
   all_nodes.append(node)
 random_node_list=[]
 while len(random_node_list)<node_num:
  random_index=randint(0,len(all_nodes)-1)
  random_node_list.append(all_nodes[random_index])
  del all_nodes[random_index]
 return random_node_list
 
#Depth first search to find the nodes within boundary of #level
def get_successor_nodes(G,node,level):
 if level==0:#Reaches bottom
  return [node]
 else: #Not reach the bottom
  node_list=[]
  for each_node in G.successors(node):
   sub_node_list=get_successor_nodes(G,each_node,level-1)
   #print("get_successor_nodes ",each_node,"successor list:",sub_node_list,"level=",level)
   #bp()
   node_list=merge_list(node_list,sub_node_list)
   node_list.append(node)#add self to return list
  node_list=list(dict.fromkeys(node_list))#remove duplicate nodes  
  return node_list

#Given two lists [] and [], merge them into a single list.
def merge_list(list1,list2):
 for element in list2:
  list1.append(element)
 return list1 
 
#We have two graphs (no loop graph, thus DAG). First we topologically sort the nodes to translate the graph into a sequence (each DAG has a unique sequence). Then we translate each node into IR. Then calculate hash similarity between two.
def compare4_all_nodes_topological_sort_hash(G1,G2):
 #print("compare4_all_nodes_topological_sort_hash G1 cycles:",list(nx.simple_cycles(G1)))
 #print("compare4_all_nodes_topological_sort_hash G2 cycles:",list(nx.simple_cycles(G2)))
 topological_list1=list(nx.topological_sort(G1))#each element is a node (address)
 topological_list2=list(nx.topological_sort(G2))#each element is a node (address)
 
 topological_IR_list1=sequence2IR(topological_list1,G1)#each element is an IR (list of string)
 topological_IR_list2=sequence2IR(topological_list2,G2)#each element is an IR (list of string)
 bp()
 m1 = MinHash(num_perm=128)
 for d in topological_IR_list1:
    m1.update(d.encode('utf8'))
 
 m2 = MinHash(num_perm=128)
 for d in topological_IR_list2:
    m2.update(d.encode('utf8'))
 bp()
 return m1.jaccard(m2)   
 
#Given a sequence of nodes, translate each node into IR.
def sequence2IR(topological_list,G):
 result_list=[]
 for i in topological_list:
  if i==0:
   continue
  if i=="4129AC":
   bp()  
  print("sequence2IR i=",i,"G.nodes[i]=",list(G.nodes[i]))
  result_list+=G.nodes[i]['IR'][0]
 return result_list

#Given a graph, topologically sort its nodes and hash it.
def topological_sort_hash_graph_single(G):
 topological_list1=list(nx.topological_sort(G))#each element is a node (address)
 
 topological_IR_list1=sequence2IR(topological_list1,G)#each element is an IR (list of string)
 m1 = MinHash(num_perm=128)
 for d in topological_IR_list1:
    m1.update(d.encode('utf8'))
 return m1   