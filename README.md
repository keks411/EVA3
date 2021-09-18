# EVA3: using hellsgate in EVA to get the syscalls [tested with cobalt strike 4.3]

# USAGE: 

1- copy your x64 shellcode to encoder.py file

2- change the key if u want but remeber to change it in main.c file too 

3- run encoder.py as following:
python2 encoder.py

4- copy the generated shellcode to your 'shellcode' variable in main.c 

5- compile inside visual studio, as release x64 

6- enjoy

# BASED ON:
- https://github.com/am0nsec/HellsGate the whole repo is just copied from there, i just modified the way of writing to memory, and xored it .

## i actually dont know if it can bypass some avs, but its a nice approach worth some attention  

![image](https://user-images.githubusercontent.com/66519611/133883316-591c5969-ee67-4ee6-b1ca-274701ab8d86.png)


