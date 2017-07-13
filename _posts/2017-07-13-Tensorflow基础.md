---
published: false
---
## Tensorflow 基础
### Tensorflow 在Windows下的安装
	-安装Visual Studio 2015
    -安装CUDA 8.0
    -安装CUDNN 5.x并将bin include lib文件夹都拷贝到CUDA的安装目录中即可
    -安装python 3.5.x 64位
    -运行pip3 install --upgrade tensorflow-gpu
     在调用pip进行安装时如果出现Fatal error in launcher: Unable to create process using '"' 错误，则可以直接用python3 -m pip install --upgrade tensorflow-gpu 进行安装
     -如果在导入tensorflow过程中出现DLL未找到的错误则使用denpends工具打开_pywrap_tensorflow_internal.pyd查看依赖的dll并排错



    
   

Enter text in [Markdown](http://daringfireball.net/projects/markdown/). Use the toolbar above, or click the **?** button for formatting help.
