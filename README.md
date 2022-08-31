### Binary Code Similarity Detection Tool -- SemDiff
SemDiff contains two modules, graph generation and graph diffing

### Graph Generation
This module is in the symbolic_engine folder

### Graph Diffing 
This module is in the compare_sim folder

### Installation

First of all, this is a plugin for IDA pro. Make sure you install IDA pro first. We implemented on IDA pro 7.5 SP3. Thus this plugin works for this version.
We haven't tested on other versions of IDA pro.

open up the binary_similarity.cpp file, change the path you want to generate symbolic expression files as path1.

Then open up idasdkandtools_ida7.5hello.sln, build it. Once successful, you will find semdiff64.dll for IDA pro 64 under symbolic_engine\x64\Debug. By default we 
implement for IDA pro 64. If you want to build for IDA pro 32, you can select x64/x86 under Configuration Manager in Visual Studio.

To install the dll plugin into IDA pro, copy paste semdiff64.dll under plugins folder in IDA pro 7.5. 

You also need to install msynth and miasm for python.

### Usage

##### Graph Generation

Once open IDA pro and load the binary, under plugin you can find the "binary similarity detection" or press F8. Click this button, then current binary's symbolic
files will be generated under path1. A folder with the name same as the binary loaded will be generated. Within the folder is a list of folders which are named by each functions in the binary. For each function, we output a 0_output.txt file recording the symbolic expressions and a IR_output.txt file recording the control flow. The 0_output.txt contains the symbolic formula that can be very complex. To simplify it, run compare_sim/write_IR.py. This generates IR_output1.txt and IR_output1_simplified.pickle, which represent the symplified key instructions.



##### Graph Diffing
Run compare_sim/IR_graphcheck_IRs_similarity.py and input two binaries you want to check similarity. This will output a sim.txt file under each function folder. 
Then extract functions with at least 5 blocks (If you have Asm2vec, you can extract the same functions as Asm2vec through  copy_same_files function in compare_sim/check_output/).

Lastly, check precision@1 score by running main function in compare_sim/check_output/ .
 
<!--
**SemDiff4BinaryDetection/SemDiff4BinaryDetection** is a ✨ _special_ ✨ repository because its `README.md` (this file) appears on your GitHub profile.

Here are some ideas to get you started:

- 🔭 I’m currently working on ...
- 🌱 I’m currently learning ...
- 👯 I’m looking to collaborate on ...
- 🤔 I’m looking for help with ...
- 💬 Ask me about ...
- 📫 How to reach me: ...
- 😄 Pronouns: ...
- ⚡ Fun fact: ...
-->
