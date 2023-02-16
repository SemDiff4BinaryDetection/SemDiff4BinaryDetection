### Binary Code Similarity Detection Tool -- SemDiff
SemDiff contains two modules, graph generation and graph diffing

### Graph Generation
This module include all the symbolic_engine folder, compare_sim/write_IR.py, and compare_sim/IR_graph/check_IRs_similarity.py.

### Graph Diffing 
This module is in compare_sim/IR_graph/check_IRs_similarity.py.

### Data
This folder contains the data we used for experiments. This include cross-compiling-optimization-level, cross-compilers, corss-versions, and cross-ollvm-flags.

### Installation

First of all, this is a plugin for IDA pro. Make sure you install IDA pro first. We implemented on IDA pro 7.5 SP3 in Windows. Thus this plugin works for this version.
We haven't tested on other versions of IDA pro.

open up the binary_similarity.cpp file, change "working_path" to the path you want to generate symbolic expression files at.

Then open up idasdkandtools_ida7.5hello.sln, build it. Once successful, you will find semdiff64.dll for IDA pro 64 under symbolic_engine\x64\Debug. By default we 
implement for IDA pro 64. If you want to build for IDA pro 32, you can select x64/x86 under Configuration Manager in Visual Studio.

To install the dll plugin into IDA pro, copy paste semdiff64.dll under plugins folder in IDA pro 7.5. 

You also need to install msynth and miasm for python.

### Usage

##### Graph Generation

1. Once open IDA pro and load the binary, under plugin you can find the "binary similarity detection" or press F8. Click this button, then current binary's symbolic
files will be generated under the path you changed for "working_path". A folder with the name same as the binary loaded will be generated in the "working_path". Within the folder is a list of folders which are named by each functions in the binary. For each function, we output a 0_output.txt file recording the symbolic expressions and a IR_output.txt file recording the control flow. 

2. Since the 0_output.txt contains the symbolic formula that can be very complex, to simplify it, run: ``` python compare_sim/write_IR.py ```
This generates a IR_output1.txt and a IR_output1_simplified.pickle for each function, which represent the symplified key instructions.



##### Graph Diffing
3. Run ```python compare_sim/IR_graph/check_IRs_similarity.py``` and input two binaries you want to check similarity against each other. This will output a sim.txt file under each function folder. 
Then extract functions with at least 5 blocks (If you have Asm2vec, you can extract the same functions as Asm2vec through copy_same_files function in compare_sim/check_output/).

4. Lastly, check precision@1 score by running main function in compare_sim/check_output/ .
 
 
### Experiment Results
Due to the paper page limitation, we show the complete experiment results here. 

#### Experiment 1: Correctness of Key Expressions
![plot](/figs/correctness.jpg)
To justify the correctness of the translated key expressions, we
randomly selected 200 functions from the projects described in
Section 5 and manually analyzed them. For each function, we read
each assembly instruction line and check the correctness of their
symbolic expressions in order to check the correctness of the key
expressions. The result shows that 85% of the key expressions are
correct. The incorrectness were due to two aspects: 1) the lack of
support of some x64 mnemonics’ variants. For example, mov and
movzx both move the value into a register or a memory address
where the former mnemonic directly moves the value while the
latter one further zero extend the value if the value has less bits
than the register or the memory address. Since mnemonics like
movzx are rarely observed in the projects, we did not support them
in the current version of SemDiff. Rather, we address movzx as mov,
which can cause subtle inaccuracy in the symbolic expression. 2)
Sometimes the IDA pro that SemDiff depends on can mistakenly
resolve strings. We designed SemDiff to resolve strings variables
names into the contents of the string. For example, SemDiff resolves
string variable address from instruction mov esi, address into
“Rtmin” that address points to. However, in some cases, IDA pro
may consider constant value as memory address and resolve the
content at that memory address.

#### Experiment 2: Similarity Quantification Cross Compiling Optimization, Compilers, and Obfuscations
##### Experiment 2.1: Similarity Quantification in Cross-GCC-Compiling-Optimization-Level
![plot](/figs/gcc.jpg)
![plot](/figs/gcc_extra.jpg)

##### Experiment 2.2: Similarity Quantification in Cross-Compiler.
![plot](/figs/clang.jpg)
![plot](/figs/clang_extra.jpg)

##### Experiment 2.3: Similarity Quantification in Different Obfuscation Options
![plot](/figs/obfuscate.jpg)

#### Experiment 3: Applications of SemDiff

##### Experiment 3.1: Similarity Quantification in Cross-Program-Version
![plot](/figs/versions.jpg)

##### Experiment 3.2: Vulnerability Search
![plot](/figs/cve.jpg)
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
