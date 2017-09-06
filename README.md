
# rtp_h264_extractor

Dump RTP h.264 payload to raw h.264 file (*.264)  
According to RFC3984 to dissector H264 payload of RTP to NALU, and write it to from<sourceIp_sourcePort>to<dstIp_dstPort>.264 file. By now, we support single NALU, STAP-A and FU-A format RTP payload for H.264.  
You can access this feature by menu "Tools->Export H264 to file [HQX's plugins]"  

Author: Huang Qiangxiong (qiangxiong.huang@gmail.com)
