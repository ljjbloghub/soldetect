import os 
import re
import subprocess
import json
import os 

def Solfiledect(filename):
	try:
		name, ext = os.path.splitext(filename)
		if ext != '.sol':
			return 'type error'
		inputfilename="./solfile/"+filename
		with open(inputfilename) as f:
			lines=f.readlines()
			checksol=False
			for line in lines:
				if 'pragma solidity' in line:
					solidity_version=re.findall("\d+.\d+.\d+", line)
					checksol=True
					break
				else:
					continue
		if not checksol:
			return 'version error'
		command='python3 soldection.py a '+inputfilename+' --solv '+solidity_version[0]+' -o text'
		proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,) 
		out_value, err_value = proc.communicate()
		result=out_value.decode('utf-8')
		# result=json.loads(out_value.decode('utf-8').strip())
		return result
	except:
		return 'detect error'
def Bytecodedect(bytecode):
	if bytecode[:8] =='60806040':
		command='python3 soldection.py a -c'+bytecode+' -o text'

		proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,) 
		out_value, err_value = proc.communicate()
		result=out_value.decode('utf-8')


	# result=json.loads(out_value.decode('utf-8').strip())
		return result
	else:
		return 'bytecode error'

def Addressdect(address):
	command='python3 soldection.py a -a'+address+' -o text'

	proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,) 
	out_value, err_value = proc.communicate()
	result=out_value.decode('utf-8')

	# result=json.loads(out_value.decode('utf-8').strip())
	return result

# if __name__=="__main__":
# # 	filename='overflow.sol'
# # 	Solfiledect(filename)
# 	bytecode='608060405234801561001057600080fd5b506101fc806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c806370a082311461003b578063e4849b3214610093575b600080fd5b61007d6004803603602081101561005157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100c1565b6040518082815260200191505060405180910390f35b6100bf600480360360208110156100a957600080fd5b81019080803590602001909291905050506100d9565b005b60006020528060005260406000206000915090505481565b6000816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054031161012657600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a764000083029081150290604051600060405180830381858888f193505050501580156101c2573d6000803e3d6000fd5b505056fea264697066735822122054d8ad5f95edaaeb936aeace7a7287129a6640bda7abbb928073a9ce86c4227364736f6c63430007040033'
# 	Bytecodedect(bytecode)
# # 	bytecodedect(bytecode)

    
