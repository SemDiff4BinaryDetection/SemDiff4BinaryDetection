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
implement for IDA pro 64. If you want to build for 32 bit, you can select x64/x86 under Configuration Manager in Visual Studio.

Copy paste semdiff64.dll under plugins folder in IDA pro 7.5. 

Once open IDA pro and load the binary, under plugin you can find the "binary similarity detection" or press F8. Click this button, then current binary's symbolic
files for each function will be generated under path1.


 
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
