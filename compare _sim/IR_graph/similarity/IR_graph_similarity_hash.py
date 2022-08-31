from .node_compare import IR_vs_IR,ACCEPT_IR_THRESHOD
from .sequence_nodes_compare import generate_sequence_starting_at_node
from operator import itemgetter
from datasketch import MinHash
from pdb import set_trace as bp
from random import randint

#This function checks all the node in G1 to find their max similarity in G2 with the assistance of hash. Then we average each node's similarity.
def compare4all_nodes_hash(G1,G2,sequence_length):
 global ACCEPT_IR_THRESHOD
 total_sim=0
 len1=0
 
  
 if len(G1.nodes())>100:#If G1 has too many nodes, for efficiency, we extract random subset of nodes for comparison.
 # G1_nodes_for_cmp=random_extract_node1(G1,100)
  G1_nodes_for_cmp=random_extract_node2(G1,100)
 else:
  G1_nodes_for_cmp=G1.nodes()
  
 minhash_set1,IR_dict1=generate_minhash_set(G1_nodes_for_cmp,G1,sequence_length)
 minhash_set2,IR_dict2=generate_minhash_set(G2.nodes(),G2,sequence_length)
 
 for node1 in G1_nodes_for_cmp:#For comparing nodes in G1
  #print("node1:",node1)
  if node1!=0:
   IR1=G1.nodes[node1]["IR"][0]#Get node1 content
   potential_node2s=[]#Storing potentially similar node2s if their textual similarity >=0.5
   potential_node_similarity=[]#Storing bare-node similarity of node1 and node2
   print("node",node1," compare to ",len(G2.nodes()),"nodes!")
   for node2 in G2.nodes():#For each node in G2
    if node2!=0:
     IR2=G2.nodes[node2]["IR"][0]#Get node2 content
     if G1.nodes[node1]["mode"]==G2.nodes[node2]["mode"]:#If two nodes have same mode
      #text_sim=IR_hash_vs_IR_hash(IR1,IR2)
      #if text_sim>ACCEPT_IR_THRESHOD:
       potential_node2s.append(node2)
       #potential_node_similarity.append(text_sim)
   max_sim=0
   max_node2=None   
   print("node1",node1,"potential similar nodes:",len(potential_node2s))
   #for potential_node2,bare_node_sim in zip(potential_node2s,potential_node_similarity):#For each potential node2, we calculate sequence similarity with node1
    #bp()
   for potential_node2 in potential_node2s:
    neighbour_hash_sim=minhash_sim(minhash_set1[node1],minhash_set2[potential_node2])
    if neighbour_hash_sim>max_sim:#If sequences of node1 and node2 are similar, we deem node2 similar to node1.
     max_sim=neighbour_hash_sim
     max_node2=potential_node2
     break
   print("compare4all_nodes_hash max_sim=",max_sim,"node1=",node1,"max sim node2:",max_node2)
   bp()  
   total_sim+= max_sim#For node1, it compares to all potential node2's sequences (neighbour). If neighbour similarity>=0.5, we deem node1 and node2's bare node similarity as their similarity.
   len1+=1
   if max_sim!=0:    
    print("sim:",max_sim,node1,"vs",max_node2,G1.nodes[node1],"            ",G2.nodes[max_node2],"mode=",G1.nodes[node1]["mode"])
   elif max_sim==0:
    print(node1,"has no similar nodes")
 print("compare4all_nodes_sequence_assisted total_sim=",total_sim)
 if len1==0:
  return 0
 else: 
  return total_sim*1.0/len1
  
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
 
#Generate a dictionary. Key is node (address), value is its neighbour instructions' hash value
def generate_minhash_set(node_list,G,sequence_length):
 minhash_dict={}
 IR_dict={}
 for node in node_list:
  node_sequences=generate_sequence_starting_at_node(G,node,sequence_length)
  #print("generate_minhash_set node_sequences=",node_sequences)
  IR_list=translate_sequences2list(node_sequences,G)
  m = MinHash(num_perm=128)
  for d in IR_list:
    m.update(d.encode('utf8'))
  minhash_dict[node]=m
  IR_dict[node]=IR_list
 return minhash_dict,IR_dict
 ''' IR_dict[node]=IR_list
 return {},IR_dict'''
 
#calculate two minhashes similarity
def minhash_sim(minhash1,minhash2):
 return minhash1.jaccard(minhash2)
 
#Input is a list of node sequeces (e.g., [[node1,node2,node3,node4],[nodeX,nodeY,nodeZ]......])
#We need to firstly: translate each sequence into IR sequence: [[IR1,IR2,IR3,IR4],[IRX,IRY,IRZ]......]
#An example IR looks like: ["VAR1","4","VAR5","*","6"]
#Secondly, we need to flatten each sequence e.g., [IR1,IR2,IR3,IR4]--> a list of string (["VAR1","4","VAR5","*","6","VAR2","VAR7","VAR5","5"])
#Thridly, sort the list i.e., [sequence1,seqnece2,sequence3]-->[sequence3,seqnece2,sequence1] so that similar list can get similar sorted value
#Fourthly, flatten the [sequence1,seqnece2,sequence3]-->[neighbours]
def translate_sequences2list(node_sequences,G):
 IR_list=sequences2list(node_sequences,G)
 flattened_IR_list=flatten_IRS(IR_list)
 sorted_IR_list=sorted(flattened_IR_list, key=itemgetter(0))
 translated_list=flatten_sequences(sorted_IR_list)
 return translated_list
 
#Firstly: translate each sequence into IR sequence. Input is [[node1,node2,node3,node4],[nodeX,nodeY,nodeZ]......], translate each node to IR. Output is [[IR1,IR2,IR3,IR4],[IRX,IRY,IRZ]......]. An example IR looks like: ["VAR1","4","VAR5","*","6"]
def sequences2list(node_sequences,G):
 result_list=[]
 for sequence in node_sequences:
  new_sequence=[]
  for node in sequence:
   if node==0:
    new_sequence.append('')
   else:
    IR=G.nodes[node]["IR"][0]
    new_sequence.append(IR)
  result_list.append(new_sequence) 
 return result_list
  
#Secondly, we need to flatten each sequence e.g., [IR1,IR2,IR3,IR4]--> a list of string (["VAR1","4","VAR5","*","6","VAR2","VAR7","VAR5","5"])
def flatten_IRS(IR_list):
 result_list=[]
 for sequence in IR_list:
  new_sequence=[]
  for IR in sequence:
   new_sequence+=IR
  result_list.append(new_sequence) 
 return  result_list
 
#Fourthly, flatten the [sequence1,seqnece2,sequence3]-->[neighbours] 
def flatten_sequences(sorted_IR_list):
 result=[]
 for sequence in sorted_IR_list:
  result+=sequence
 return result 
 
#Given two IRs in form of two splited string list, we compare their hash similarity.
def IR_hash_vs_IR_hash(IR1,IR2):
 m1 = MinHash(num_perm=128)
 for d in IR1:
  m1.update(d.encode('utf8'))
 m2 = MinHash(num_perm=128)
 for d in IR2:
  m2.update(d.encode('utf8'))
 return m1.jaccard(m2)
  