from .text import *
ACCEPT_IR_THRESHOD=0.5

#Each node contains a list of possible IRs. So to compare two nodes,
#they are similar only one of their IRs are similar
def node_vs_node(node1,node2):
 if node1["mode"]==node2["mode"]:
  max_sim=0
  for IR1 in node1["IR"]:
   for IR2 in node2["IR"]:
    sim=IR_vs_IR(IR1,IR2,node1["mode"])
    if sim>max_sim:
     max_sim=sim
  return max_sim 
    #if sim>=ACCEPT_IR_THRESHOD:
 else:
  return 0
 
#5 types of IR to process:
#              1....=...
#              2.if...==...
#              3....
#              4.function(..,..,..)
#              5.return
def IR_vs_IR(IR1,IR2,mode):
 #IR1=G1.nodes[node1]['IR']
 #IR2=G2.nodes[node2]['IR']
 #print(IR1,"vs",IR2,"mode=",mode)
 #IR1,IR2=clean_suffix(IR1,IR2)
 #if IR1.find('[')!=-1:
 # IR1=simplify_address(IR1)
 #if IR2.find('[')!=-1:
 # IR2=simplify_address(IR2)
 if mode==4:
  if type(IR1.func_name)!=type(IR2.func_name): #function name type even not same
   return 0
  else:
   function_name_sim=function_name_similarity(IR1.func_name,IR2.func_name) 
   if function_name_sim==1:#if function name of disp match perfectly
    parameter_content_sim=similar_parameter_content(IR1.parameters,IR2.parameters)
    return parameter_content_sim
   else:
    return 0
  '''name1=get_function_name(IR1)
  name2=get_function_name(IR2)
  parameters1=get_parameters(IR1)
  parameters2=get_parameters(IR2)
 
  function_name=similar_function_name(name1,name2) 
  #parameter_number=similar_parameter_number(parameters1,parameters2)
  if len(parameters1)==len(parameters2) and len(parameters1)>0:
   parameter_number=1
  else:
   parameter_number=0
  parameter_type=similar_parameter_type(parameters1,parameters2)
  #print("function_name=",function_name,"parameter_number=",parameter_number,"parameter_type=",parameter_type)
  if function_name>=0 and parameter_number and parameter_type:
   parameter_content_score=similar_parameter_content(parameters1,parameters2)
   #print("content similarity:",parameter_content_score)
   return (parameter_content_score+function_name+parameter_type)*1.0/3
   # calling instruction similarity should be the parameters content similarity
  scaler=(max(len(parameters1),len(parameters2))*1.0+1)/(max(len(parameters1),len(parameters2))+2)
  return (function_name+parameter_type)*1.0/2*scaler'''
  
 elif mode==2:
  #If mode=2, i.e., comparing instruction like cmp and etc. If one IR is a set while another is one, return 1 if the 'one' matches one of the set. If two IRs are two sets, for examlple, len(IR1)=5,len(IR2)=3, if 3 elements matches, return 3, if two elements matches, return 2.
  IR1_cmp_set=IR1.compare_lists
  #print("IR1_cmp_set:")
  #for item in IR1_cmp_set:
  # print(item.left,item.Mnem,item.right)  
  IR2_cmp_set=IR2.compare_lists
  #print("IR2_cmp_set:")
  #for item in IR2_cmp_set:
  # print(item.left,item.Mnem,item.right)  
  if len(IR1_cmp_set)==1:#If IR1 has only one element.
   for element in IR2_cmp_set:
    if cmp_IR_matches(IR1_cmp_set[0],element):
     return 1#If any one of IR2 get matches, return 1
   return 0 #If none of IR2 get matched, return 0
  elif len(IR2_cmp_set)==1:#if IR2 has only one element
   for element in IR1_cmp_set:
    if cmp_IR_matches(IR2_cmp_set[0],element):
     return 1#If any one of IR2 get matches, return 1
   return 0 #If none of IR2 get matched, return 0
  else:#If IR1 and IR2 all contains multiple elements
   matched_num=0
   for element1 in IR1_cmp_set:
    for element2 in IR2_cmp_set:
     if cmp_IR_matches(element1,element2):
      matched_num+=1
      break   
   return matched_num
  '''IR1_left=get_cmp_left(IR1)
  IR1_right=get_cmp_right(IR1)
  IR2_left=get_cmp_left(IR2)
  IR2_right=get_cmp_right(IR2)
  #IR1 left----IR2 left, IR1 right----IR2 right
  #print("IR_VS_IR",IR1_left,IR2_left)
  left_similarity=text_similarity(IR1_left,IR2_left)
  right_similarity=text_similarity(IR1_right,IR2_right)
  total_similarity=(left_similarity+right_similarity)*1.0/2
  #print("left=",left_similarity,"right=",right_similarity,"total=",total_similarity)
  #IR1 left----IR2 right, IR1 right----IR2 left
  left_similarity=text_similarity(IR1_left,IR2_right)
  right_similarity=text_similarity(IR1_right,IR2_left)
  total_similarity1=(left_similarity+right_similarity)*1.0/2
  #print("left=",left_similarity,"right=",right_similarity,"total=",total_similarity1)
  return max(total_similarity,total_similarity1)'''
  
 elif mode==1:#memory address store
  IR1_left=IR1.left
  IR1_right=IR1.right
  IR2_left=IR2.left
  IR2_right=IR2.right
  #print("IR1=",IR1_left,", ",IR1_right)
  #print("IR2=",IR2_left,", ",IR2_right)
  left_similarity=disp_sim(IR1.left,IR2.left)
  #print("IR_VS_IR MODE 1",IR1_left,IR2_left,"sim:",left_similarity)
  right_similarity=text_similarity_v1(IR1_right,IR2_right)
  #print("IR_VS_IR MODE 1",IR1_right,IR2_right,"sim:",right_similarity)
  total_similarity=min(left_similarity,right_similarity)
  #print("total sim:",total_similarity)
  return total_similarity
 
 elif mode==3:#expression
   #print("IR_VS_IR MODE 3",IR1,IR2)
   similarity=text_similarity_v1(IR1.elements,IR2.elements)
   return similarity
   
def similar_parameter_content(parameters1,parameters2):
 if len(parameters1)>2*len(parameters2) or len(parameters1)*2<len(parameters2):
  #if parameter number significantly unequal, return0.
  return 0
 total_param_sim=0
 len1=0
 #else if parameters amount equal
 for parameter1,parameter2 in zip(parameters1,parameters2):
  param_sim=text_similarity_v1(parameter1,parameter2)
  #print(parameter1,parameter2,"sim:",param_sim)
  total_param_sim+=param_sim
  len1+=1
 if len1>0:
  result= total_param_sim*1.0/len1
  return result
 else:
  return 1
 
 
def function_name_similarity(name1,name2):
 if type(name1)==str and type(name2)==str:
  return 1
 elif type(name1)==out_most_disp and type(name2)==out_most_disp:
  return disp_sim(name1,name2)
 
  
'''def similar_parameter_number(parameters1,parameters2):
 global ACCEPT_PARAM_NUM
 #print("similar_parameter_number",parameters1,parameters2)
 difference_percent=abs(len(parameters1)-len(parameters2))*1.0/min(len(parameters1),len(parameters2))
 return 1.0-difference_percent'''
 
 
def similar_parameter_type(parameters1,parameters2):
 score=0
 #print("parameters1: ",parameters1)
 #print("parameters2: ",parameters2)
 for parameter1,parameter2 in zip(parameters1,parameters2):
  #if two parameters are all string
  if parameter1.find('"'):
   if parameter2.find('"'):
    score+=1
   else:
    score+=-1   
  #if first parameter is all disp
  elif parameter1.strip().startswith('[') and parameter1.strip().endswith(']'):
   #if second parameter is disp 
   if parameter2.strip().startswith('[') and parameter2.strip().endswith(']'):
    if parameter1.count('[')==parameter2.count('['):
     score+=1
    else:
     score+=0
   #if second parameter is not disp
   else:
    score-=1
  #if first parameter is expression 
  else:
   #if second parameter is expression
   if parameter2.find('"')==-1 and  not parameter2.strip().startswith('[') and not parameter2.strip().endswith(']'):
    score+=1
   else:
    score+=-1 
 if max(len(parameters1),len(parameters2))>0:
  return score*1.0/max(len(parameters1),len(parameters2))  
 else:
  return 0 
  
def test_node_vs_node(arm_G,x64_G):
 arm_node=input("Please enter the node in ARM:")
 for node in x64_G.nodes():
  if node!=0:
   if x64_G.nodes[node]["mode"]==arm_G.nodes[arm_node]["mode"]:
    #print ("ARM ",arm_node,"-- x64 ",node)
    print("ARM ",arm_node,"-- x64 ",node, "mode=",x64_G.nodes[node]["mode"],"similarity=", node_vs_node(arm_G.nodes[arm_node]["IR"],x64_G.nodes[node]["IR"],x64_G.nodes[node]["mode"]))
    
#Compare similarity of two cmp_stru structures. The two cmp_stru structures should all be the lowest level of the cmp_stru structure. That is, its left and right should not be a cmp_stru structure. Instead, they should be a list type (for string) or int type.
def cmp_IR_matches(cmp1,cmp2):
 total_sim=0
 if not similar_cmp_stru_Mnem(cmp1.Mnem,cmp2.Mnem):#If Mnem not even similar, return false
  return False
 #If right=right, left=left
 elif cmp_comstru_left_right(cmp1.left,cmp2.left)>=ACCEPT_IR_THRESHOD and cmp_comstru_left_right(cmp1.right,cmp2.right)>=ACCEPT_IR_THRESHOD:
 #total_sim=(cmp_comstru_left_right(cmp1.left,cmp2.left)+cmp_comstru_left_right(cmp1.right,cmp2.right))*1.0/2
 #if total_sim>=ACCEPT_IR_THRESHOD:
  return True
 #If right=left, left=right
 elif cmp_comstru_left_right(cmp1.left,cmp2.right)>=ACCEPT_IR_THRESHOD and cmp_comstru_left_right(cmp1.right,cmp2.left)>=ACCEPT_IR_THRESHOD:
 #total_sim=(cmp_comstru_left_right(cmp1.left,cmp2.right)+cmp_comstru_left_right(cmp1.right,cmp2.left))*1.0/2
 #if total_sim>=ACCEPT_IR_THRESHOD:
  return True
 return False 
 
#Given two sides (either left or right of a cmp_stru structure), calculated their similarity. Each side can be either list type for string and int type for a single integer.
def cmp_comstru_left_right(side1,side2):
 if type(side1)!= type(side2):
  return 0
 elif type(side1)==out_most_disp and type(side2)==out_most_disp:
  return disp_sim(side1,side2)
 elif type(side1)==int and type(side2)==int:
  if side1==side2 or abs(side1-side2)==1:#For example, 1 and 1 are the same. 1 and 0 are also the same. 5 and 6 are same.
   return 1
  else:
   return 0

 
#Check whether two Mnem are simialr. The given two Mnems are complete Mnem (e.g., compne rather than cmp) all lower case.
def similar_cmp_stru_Mnem(Mnem1,Mnem2):
 type_0=['cmp','sub','sbb','xor','test','and']
 type_1=['mov']
 type_2=['add','adc']
 type_3=['set']
 types=[type_0,type_1,type_2,type_3]
 Mnem1_type=-1
 Mnem2_type=-1
 for index in range(0,len(types)):
  for item in types[index]:
   if item in Mnem1:
    Mnem1_type=index
    break
  if Mnem1_type!=-1:
   break
 for index in range(0,len(types)):
  for item in types[index]:
   if item in Mnem2:
    Mnem2_type=index
    break
  if Mnem2_type!=-1:
   break  
 #print("Mnem1=",Mnem1,"Mnem2=",Mnem2,"Mnem1_type:",Mnem1_type,"Mnem2_type:",Mnem2_type)  
 #bp()  
 if Mnem1_type==Mnem2_type:
  return True
 else:
  return False