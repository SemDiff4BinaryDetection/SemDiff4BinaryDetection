from gensim.models import Word2Vec, KeyedVectors
#from .text import split_elements
model=None

def learn_variable_meaning(samples):
 global model
 model=Word2Vec(sentences=samples,vector_size=100,window=40,min_count=1,workers=4,epochs=1000)
 ARM_var_list=[]
 x86_var_list=[]
 for key in model.wv.key_to_index.keys():
  if key.startswith("VAR"):
   if key.find('.')!=-1:
    x86_var_list.append(key)
   else:
    ARM_var_list.append(key)
 for ARM_key in ARM_var_list:
  for x86_key in x86_var_list:
   print(ARM_key,"---",x86_key," = ",model.wv.similarity(w1=ARM_key,w2=x86_key))
  print("")
 print("0x55---0x56 = ",model.wv.similarity(w1="0x55",w2="0x56"))
 
 
def check_vocab_sim(base1,base2):
 global model 
 #print(base1,", ",base2)
 result1=model.wv.similarity(w1=base1,w2=base2)
 result2=model.wv.similarity(w1=base2,w2=base1)
 #print("similarity ",base1,", ",base2,"=",result1, " similarity 2-1=",result2)
 total=(result1+result2)*1.0/2
 return total
 
'''def test_learn():
 file_path1=input("Please enter the ARM file path:")
 file_path2=input("Please enter the x86 file path:")
 sample=[]
 with open(file_path1,'r') as f:
  content1=f.read()
 f.close()
 with open(file_path2,'r') as f:
  content2=f.read()
 f.close()
 content=content1.split('\n')
 content2=content2.split('\n')
 for line in content2:
  content.append(line)
 for line in content:
  line=line[line.find(':')+1:].replace(" ","")
  new_line=split_elements(line)
  sample.append(new_line)
 learn_variable_meaning(sample) '''
 
 

 
#test_learn()