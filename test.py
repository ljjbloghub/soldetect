import re 
import time 
import subprocess
import os
def Solfiledect(filename):
	inputfilename="./solfile/"+filename
	# with open(inputfilename) as f:
	# 	lines=f.readlines()
	# 	for line in lines:
	# 		if 'pragma solidity' in line:
	# 			solidity_version=re.findall("\d+.\d+.\d+", line)
	# 			break
	# 		else:
	# 			continue
	# start=time.time()
	# command='python3 soldection.py a '+inputfilename+' --solv '+solidity_version[0]+' -o text'
	# proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,) 
	# out_value, err_value = proc.communicate()
	# result=out_value.decode('utf-8')

	# end=time.time()
	# analyzetime=round(end-start,2)
	# print(analyzetime)
	
	# print('Running time: %s Seconds'%analyzetime)
	

if __name__=="__main__":
	filename='uncheck-returnvalue.sol'
	name, ext = os.path.splitext(filename)
	print(ext)