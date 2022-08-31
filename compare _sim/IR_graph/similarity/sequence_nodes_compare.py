import networkx as nx
from .node_compare import IR_vs_IR
from .text import struct_to_string
from pdb import set_trace as bp

#Given two IR graphs, initialize a matrix. Column names and row names should be all nodes of two IR graphs.
def initialize_nodes_similarity_matrix(G1,G2):
 columns=[]
 rows=[]
 for node1 in G1.nodes():#Generate columns
  if node1!=0:
   columns.append(node1)
   
 for node2 in G2.nodes():#Generate rows
  if node2!=0:
   rows.append(node2) 
 
 #Now create a 2-d dictionary
 sim_matrix={}
 for row in rows:
  row_dict={}
  for column in columns:
   row_dict[column]=0
  sim_matrix[row]=row_dict 
   
 return sim_matrix 
 
#Given two IR graphs, we generate a matrix describing each two nodes' similarity between two IR graphs.
def generate_nodes_similarity_matrix(G1,G2):
 df=initialize_nodes_similarity_matrix(G1,G2)#Initialize matrix
 #Next we add value into the matrix
 for node1 in G1.nodes():#For each node in G1
  if node1!=0:
   IR1=G1.nodes[node1]["IR"][0]
   max_sim=0
   max_node2=""
   for node2 in G2.nodes():#For each node in G2
    if node2!=0:
     IR2=G2.nodes[node2]["IR"][0]
     if G1.nodes[node1]["mode"]==G2.nodes[node2]["mode"]:#If two nodes have same mode
      #if node1=='402D8F' and node2=='137C8':
      # bp()
      text_sim=IR_vs_IR(IR1,IR2,G1.nodes[node1]["mode"])
      df[node2][node1]=text_sim
 return df
 
#Given an IR graph and the wanted sequence length, generate a set of all possible sequnces of this length.
#Each sequence is generated with a node of this IR graph as the starting node, and walk forward with length steps.
#We need to consider the joint node. Thus if within the length there are some joint nodes, we might generate many sequences.
def generate_seqences_of_length(G,length):
 #print("get_next_sequence G.edges:",G.edges())
 all_nodes_sequences=[]
 for node in G.nodes():#Get sequences for each node.
  if node!=0:
   each_node_sequences=get_next_sequence(G,node,length)
   #print("generate_seqences_of_length each_node_sequences:",each_node_sequences)
   for sequence in each_node_sequences:
    all_nodes_sequences.append(sequence)
 return all_nodes_sequences   


#Get the sequence of nodes within a boundary.
#Param 1: IR graph
#Param 2: current node
#Param 3: current level
def get_next_sequence(G,node,level):
 sequence_lists=[]
 if level==0:
  return [[node]]
 #print(" "*(boundary-level),node)
 if len(list(G.successors(node)))==0:#Reach the last key IR in the function but level still not reach bottom.
  return [[node]]
 for each_node in G.successors(node):
  if each_node!=0:
   temp_lists=get_next_sequence(G,each_node,level-1)
   #print("get_next_sequence temp_lists",temp_lists,"node=",node,"each_node=",each_node,"level=",level)
   for sequence in temp_lists:#Each return value of get_next_sequence should be a list of sequences.
    if sequence_contains_node(sequence,node):#We dont want loops in the sequence.
     sequence=reduce_loop_in_sequence(sequence, node)
     if sequence not in sequence_lists:
      sequence_lists.append(sequence)#Thus if detected for example (a,b) and we are adding b again to index 0. We do not add this b again.
    else: 
     sequence.insert(0,node)#For each sequence we insert the current node at beginning.
     if sequence not in sequence_lists:
      sequence_lists.append(sequence)#sequence_lists append this inserted sequence and return later.
 return sequence_lists   
   
def sequence_contains_node(sequence,node):
 for item in sequence:
  if item==node:
   return True
 return False
 
#For example, given a sequence a,b,c,d,e, and a node which is the root of this sequence, which is c. Now We need to add c before this sequence and transform a,b,c,d,e to c,a,b
def reduce_loop_in_sequence(sequence, node):
 match_index=0
 for index in range(0,len(sequence)):
  if sequence[index]==node:
   match_index=index
   break
 sequence=sequence[:match_index]  # For example trim a,b,c,d,e to a,b
 sequence.insert(0,node)          # For example add c to a,b
 return sequence
 
#Given two sequences lists, compare their similarity. The idea is that for one list, we see how many lists can be found in the other list. 
#Param 1: IR graph 1 sequence list
#Param 2: IR graph 2 sequence list
#Param 3: IR graph 1 and IR graph 2 similarity
def compare_two_sequences_lists_similarity(list1,list2,sim_matrix):
 #print("compare_two_sequences_lists_similarity list1:",list1,"list2",list2)
 sequence1_sim_list=[]#record the match of each sequence in list1
 for sequence1 in list1:#For eah sequence if list1, we check its max similarity in list 2
  max_sequence_sim=0
  max_sequence2=None
  max_matrix=None
  for sequence2 in list2:
   sequence_pair_sim,path_matrix=sequence_pair_similarity(sequence1,sequence2,sim_matrix)
   if sequence_pair_sim>max_sequence_sim:
    max_sequence_sim=sequence_pair_sim
    max_sequence2=sequence2
    max_matrix=path_matrix
  #if max_sequence_sim>=0.5: #and int(sequence1[0],16)>0x41dcc5:
  #   print("compare_two_sequences_lists_similarity sequence1: ",sequence1," most similar to:", max_sequence2," with",max_sequence_sim)
  #   print(max_sequence2)
  #   for i,element in zip(max_matrix,sequence1):
  #    print(element,i)
  #   bp()  
  sequence1_sim_list.append(max_sequence_sim) 
 total_sim=0#calculate total similarity 
 for sim in sequence1_sim_list:
  total_sim+=sim
 return total_sim*1.0/len(sequence1_sim_list) 
   
#Given two sequences of same length, and a node-to-node similarity matrix, we compute the overall similarity of two sequences using LCS algorithm.
def sequence_pair_similarity(sequence1,sequence2,sim_matrix):
    matrix = [ [0 for x in range(len(sequence2))] for x in range(len(sequence1)) ]
    max_i0_sim=0
    max_j0_sim=0
    for i in range(len(sequence1)):
        for j in range(len(sequence2)):
                '''if sim_matrix[sequence2[j]][sequence1[i]]>=0.5:#If i th item in sequence1 matches j th item in sequence2
                if i==0 or j==0:
                    matrix[i][j] = 1
                else:
                    matrix[i][j] = matrix[i-1][j-1] + 1
                    
                else:#If i th item in sequence1 does not matches j th item in sequence2'''
                if i==0: #Initialize first row values
                    if sim_matrix[sequence2[j]][sequence1[i]]>max_i0_sim:
                     matrix[i][j] = sim_matrix[sequence2[j]][sequence1[i]]
                     max_i0_sim=matrix[i][j]
                    else:
                     matrix[i][j] = max_i0_sim
                    if j==0:
                     max_j0_sim=max_i0_sim
                elif j==0: #Initialize first column values
                    if sim_matrix[sequence2[j]][sequence1[i]]>max_j0_sim:
                     matrix[i][j] = sim_matrix[sequence2[j]][sequence1[i]]
                     max_j0_sim=matrix[i][j]
                    else:
                     matrix[i][j]=max_j0_sim
                else:#For other cells, i.e., not in the first row nor first column, we select the most sim in 3 directions.
                    max1 = max(matrix[i-1][j], matrix[i][j-1])
                    max2=matrix[i-1][j-1]+sim_matrix[sequence2[j]][sequence1[i]]
                    matrix[i][j]=max(max1,max2)
    #print(matrix)
    return matrix[len(sequence1)-1][len(sequence2)-1]*1.0/len(sequence1),matrix 

  
 

#Given two IR graphs, return their similarity by using sequence based method
def nodes_sequence_compare(G1,G2,sequence_length):
 similarity_matrix=generate_nodes_similarity_matrix(G1,G2)#Produce similarity matrix
 G1_sequences=generate_seqences_of_length(G1,sequence_length)#Produce IR graph 1's sequences
 G2_sequences=generate_seqences_of_length(G2,sequence_length)#Produce IR graph 1's sequences
 #print("nodes_sequence_compare  G1_sequences:",G1_sequences,"G2_sequences",G2_sequences)
 similarity=compare_two_sequences_lists_similarity(G1_sequences,G2_sequences,similarity_matrix)
 return similarity
 

#Check more detailed information as to one pair of sequence and their similarity.
def one_sequence_pair_compare(G1,G2,sequence_length):
 similarity_matrix=generate_nodes_similarity_matrix(G1,G2)#Produce similarity matrix
 sequence1=input("Please enter the G1's sequence:")
 sequence1=sequence1[1:-1].split(',')
 for index in range(0,len(sequence1)):
  sequence1[index]=sequence1[index].strip()[1:-1]
 G2_sequences=generate_seqences_of_length(G2,sequence_length)#Produce IR graph 1's sequences
 sequence1_IR=""
 for node1 in sequence1:
  sequence1_IR+=" "+node1+": "+struct_to_string(G1.nodes[node1])
 max_sim=0
 max_sim_sequence2_IR=""
 max_sequence2=None
 max_matrix=None
 for sequence2 in G2_sequences:
  sim,path_matrix=sequence_pair_similarity(sequence1,sequence2,similarity_matrix)
  sequence2_IR=""
  for node2 in sequence2:
   sequence2_IR+=" "+node2+": "+struct_to_string(G2.nodes[node2])
  if sim>max_sim:
   max_sim=sim
   max_sim_sequence2_IR=sequence2_IR
   max_sequence2=sequence2
   max_matrix=path_matrix
 #print("sequence1:",sequence1_IR)
 #print("max_sequence2:",max_sim_sequence2_IR)
 #print("one_sequence_pair_compare sequence1:",sequence1,"similarity to sequence2:",max_sequence2,"=",max_sim,"common sequence:")
 #print(max_sequence2)
 for row,node in zip(max_matrix,sequence1):
  print(node,row)
 '''sequence2=input("Do you want to discover some pair in more detail? Please enter sequence2:")
 sequence2=sequence2[1:-1].split(',')
 for index in range(0,len(sequence2)):
  sequence2[index]=sequence2[index].strip()[1:-1]
 sim=sequence_pair_similarity(sequence1,sequence2,similarity_matrix)'''
 
#For one node in graph G, we generate all its sequences starting from this node.
#Param 1: graph
#Param 2: starting node
#Param 3: sequence length (i.e., the maximum depth level of successor of this node)
def generate_sequence_starting_at_node(G,start_node,length):
 sequences=get_next_sequence(G,start_node,length)
 if len(sequences)==0:
  bp()
 return sequences
 