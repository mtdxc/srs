/*
The MIT License (MIT)

Copyright (c) 2013-2015 SRS(ossrs)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SRS_PROTOCOL_RAW_AVC_HPP
#define SRS_PROTOCOL_RAW_AVC_HPP

/*
#include <srs_raw_avc.hpp>
*/

#include <srs_core.hpp>

#include <string>

#include <srs_kernel_codec.hpp>

class SrsStream;

/**
* the raw h.264 stream, in annexb.
useage:
@code
SrsStream steam;
steam.initialize(raw264,n264);
SrsRawH264Stream raw264;
std::string sps, pps;
u_int32_t dts;
u_int32_t pts;
while (!steam.empty()){
  char* pNal = NULL;
  int nNal = 0;
  raw264.annexb_demux(&steam, &pNal, &nNal);
  if (raw264.is_sps(pNal, nNal)){
    raw264.sps_demux(pNal, nNal, sps);
  }
  if (raw264.is_pps(pNal, nNal)){
    raw264.pps_demux(pNal, nNal, pps);
  }
  int nFlv = 0;
  char* pFlv = NULL;
  std::string sh;
  if (is_sps_pps_change()){
    raw264.mux_sequence_header(sps, pps, dts, pts, sh);
    raw264.mux_avc2flv(sh, SrsCodecVideoAVCFrameKeyFrame, SrsCodecVideoAVCTypeSequenceHeader,
dts, pts, pFlv, nFlv);
    // save pFlv
    delete [] pFlv;
  }
  SrsAvcNaluType nal_unit_type = (SrsAvcNaluType)(pNal[0] & 0x1f);

  // for IDR frame, the frame is keyframe.
  SrsCodecVideoAVCFrame frame_type = SrsCodecVideoAVCFrameInterFrame;
  if (nal_unit_type == SrsAvcNaluTypeIDR) {
    frame_type = SrsCodecVideoAVCFrameKeyFrame;
  }
  raw264.mux_ipb_frame(pNal,nNal, sh);
  raw264.mux_avc2flv(sh, frame_type, SrsCodecVideoAVCTypeNALU, dts, pts, pFlv, nFlv);
  // save pFlv
  delete [] pFlv;
}
@endcode
*/
class SrsRawH264Stream
{
public:
    SrsRawH264Stream();
    virtual ~SrsRawH264Stream();
public:
    /**
    * demux the stream in annexb format. 
    * @param stream the input stream bytes.
    * @param pframe the output h.264 frame(nal) in stream. user should never free it.
    * @param pnb_frame the output h.264 frame(nal) size.
    */
    virtual int annexb_demux(SrsStream* stream, char** pframe, int* pnb_frame);
    /**
    * whether the frame is sps or pps.
    */
    virtual bool is_sps(char* frame, int nb_frame);
    virtual bool is_pps(char* frame, int nb_frame);
    /**
    * demux the sps or pps to string.
    * @param sps/pps output the sps/pps.
    */
    virtual int sps_demux(char* frame, int nb_frame, std::string& sps);
    virtual int pps_demux(char* frame, int nb_frame, std::string& pps);
public:
    /**
    * h264 raw data to h264 packet, without flv payload header.
    * mux the sps/pps to flv sequence header packet.
    * @param sh output the sequence header.
    */
    virtual int mux_sequence_header(const std::string& sps, const std::string& pps, 
      u_int32_t dts, u_int32_t pts, std::string& sh);
    /**
    * h264 raw data to h264 packet, without flv payload header.
    * mux the ibp to flv ibp packet. add nal length header, not flv header
    * @param ibp output the packet.
    * @param frame_type output the frame type.
    */
    virtual int mux_ipb_frame(char* frame, int nb_frame, std::string& ibp);
    /**
    * mux the avc video packet to flv video packet.
    * @param frame_type, SrsCodecVideoAVCFrameKeyFrame or SrsCodecVideoAVCFrameInterFrame.
    * @param avc_packet_type, SrsCodecVideoAVCTypeSequenceHeader or SrsCodecVideoAVCTypeNALU.
    * @param video the h.264 raw data.
    * @param flv output the muxed flv packet.
    * @param nb_flv output the muxed flv size.
    */
    virtual int mux_avc2flv(const std::string& video, int8_t frame_type, int8_t avc_packet_type, u_int32_t dts, u_int32_t pts, 
      char** flv, int* nb_flv);
    virtual int mux_avc2flv(const char* video, int len, int8_t frame_type, int8_t avc_packet_type, u_int32_t dts, u_int32_t pts,
      char** flv, int* nb_flv);
};

/**
* the header of adts sample.
*/
struct SrsRawAacStreamCodec
{
    int8_t protection_absent;
    SrsAacObjectType aac_object;
    int8_t sampling_frequency_index;
    int8_t channel_configuration;
    int16_t frame_length;

    char sound_format;
    char sound_rate;
    char sound_size;
    char sound_type;
    // 0 for sh; 1 for raw data.
    int8_t aac_packet_type;
};

/**
* the raw aac stream, in adts.
*/
class SrsRawAacStream
{
public:
    SrsRawAacStream();
    virtual ~SrsRawAacStream();
public:
    /**
    * demux the stream in adts format.
    * @param stream the input stream bytes.
    * @param pframe the output aac frame in stream. user should never free it.
    * @param pnb_frame the output aac frame size.
    * @param codec the output codec info.
    */
    virtual int adts_demux(SrsStream* stream, char** pframe, int* pnb_frame, SrsRawAacStreamCodec& codec);
    /**
    * aac raw data to aac packet, without flv payload header.
    * mux the aac specific config to flv sequence header packet.
    * @param sh output the sequence header.
    */
    virtual int mux_sequence_header(SrsRawAacStreamCodec* codec, std::string& sh);
    /**
    * mux the aac audio packet to flv audio packet.
    * @param frame the aac raw data.
    * @param nb_frame the count of aac frame.
    * @param codec the codec info of aac.
    * @param flv output the muxed flv packet.
    * @param nb_flv output the muxed flv size.
    */
    virtual int mux_aac2flv(char* frame, int nb_frame, SrsRawAacStreamCodec* codec, u_int32_t dts, 
      char** flv, int* nb_flv);
};

#endif
