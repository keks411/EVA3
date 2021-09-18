# EVA3: using hellsgate in EVA to get the syscalls [tested with cobalt strike 4.3]
     note that i dont claim that the idea is mine, this repo is probably just a
     fork but i wanted to show other ways of getting syscalls .

# USAGE: 

1- copy your x64 shellcode to encoder.py file

2- change the key if u want but remeber to change it in main.c file too 

3- run encoder.py as following:
python2 encoder.py

4- copy the generated shellcode to your 'shellcode' variable in main.c 

5- compile using visual studio, as release x64 


# BASED ON:
- https://github.com/am0nsec/HellsGate the whole repo is just copied from there, i just modified the way of writing to memory, and xored it .

## i actually dont know if it can bypass some avs, but its a nice approach worth some attention, if u wanna add some other things like detecting debuggers / virtual envs, it will be a cool way to sharpen ur skills, u can view eva2 for some functions. 

![image](https://user-images.githubusercontent.com/66519611/133883316-591c5969-ee67-4ee6-b1ca-274701ab8d86.png)


