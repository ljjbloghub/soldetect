#coding:utf-8

import os
from flask import Flask,request,jsonify,render_template,redirect,url_for
from dection import Solfiledect,Addressdect,Bytecodedect
import json
import time

app = Flask(__name__)

@app.route(rule='/',methods=['POST','GET'])
def start():
	if request.method == 'POST':
		get = False
		return render_template('index.html',get=get)
	get = True
	return render_template('index.html',get=get)


@app.route(rule='/solfile',methods=['POST','GET'])
def solfiledect():
	if request.method == 'POST':
		get = False
		file = request.files.get('file','')
		if file:
			filename=file.filename
			if not file:return '上传失败！'
			file.save(os.path.join('./solfile',filename))
			start=time.time()
			dectresult=Solfiledect(filename)
			if dectresult =='version error':
				text='请添加sol文件版本号'
				return render_template('error.html',data=text,get=get)
			if dectresult =='detect error':
				text= '智能合约检测失败，请检查合约文件是否正确！'
				return render_template('error.html',data=text,get=get)
			if dectresult == 'type error':
				text = '请上传sol类型文件'
				return render_template('error.html',data=text,get=get)
			else:
				end=time.time()
				analyzetime=round(end-start,2)
				resp={'dectresult':dectresult,'analyzetime':analyzetime}
				return render_template('solfile.html',data=resp,get=get)
		else:
			text="请上传文件后点击检测"
			return render_template('error.html',data=text,get=get)
		

	get = True
	return render_template('solfile.html',data=dict(),get=get)


@app.route(rule='/bytecode',methods=['POST','GET'])
def bytecodedect():
	if request.method == 'POST':
		get = False
		bytecode = request.values.get('bytecode')
		start=time.time()
		dectresult=Bytecodedect(bytecode)
		if dectresult=='bytecode error':
			text = '请确保字节码内容正确'
			return render_template('error.html',data=text,get=get)
		end=time.time()
		analyzetime=round(end-start,2)
		resp={'dectresult':dectresult,'analyzetime':analyzetime}
		return render_template('bytecode.html',data=resp,get=get)
		
	get = True
	return render_template('bytecode.html',data=dict(),get=get)
	

@app.route(rule='/address',methods=['POST','GET'])
def address():
	if request.method == 'POST':
		get = False
		address = request.values.get('address')
		if address=='':
			text="请填入的合约地址"
			return render_template('error.html',data=text,get=get)
		start=time.time()
		dectresult=Addressdect(address)
		if dectresult =='detect error':
			text= '智能合约检测失败，请检查合约地址是否正确！'
			return render_template('error.html',data=text,get=get)

		end=time.time()
		analyzetime=round(end-start,2)
		resp={'dectresult':dectresult,'analyzetime':analyzetime}
		return render_template('address.html',data=resp,get=get)

	get = True
	return render_template('address.html',data=dict(),get=get)


	


if __name__ == '__main__':

	app.run(debug=True,host='0.0.0.0',port=4000)

