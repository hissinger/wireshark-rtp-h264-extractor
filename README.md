
# rtp_h264_extractor

## wireshark lua脚本位置

mac下：

	/Applications/Wireshark.app/Contents/Resources/share/wireshark/


下文记做{wireshark-lua-dir}


## 安装rtp_h264_extractor插件


1. 将rtp_h264_extractor，拷贝到{wireshark-lua-dir}

2. 修改{wireshark-lua-dir}/init.lua文件，脚本结尾添加如下


	dofile(DATA_DIR.."rtp_h264_extractor.lua")


3. 添加环境变量WIRESHARK_H264_PATH,作用：录音文件的存储位置。


## 使用

在wireshark->tools菜单下会新加一功能项“Export H264 to file”