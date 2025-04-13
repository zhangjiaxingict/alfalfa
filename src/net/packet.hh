/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* Copyright 2013-2018 the Alfalfa authors
                       and the Massachusetts Institute of Technology

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:

      1. Redistributions of source code must retain the above copyright
         notice, this list of conditions and the following disclaimer.

      2. Redistributions in binary form must reproduce the above copyright
         notice, this list of conditions and the following disclaimer in the
         documentation and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#ifndef PACKET_HH
#define PACKET_HH

#include <vector>
#include <deque>
#include <cassert>

#include "chunk.hh"
#include "socket.hh"
#include "exception.hh"
#include "pacer.hh"

class Packet
{
private:
  bool valid_;
  
  uint16_t is_fec_pkt_;
  uint16_t connection_id_;
  uint32_t source_state_;
  uint32_t target_state_;
  uint32_t frame_no_;
  uint32_t block_no_;
  uint32_t first_frame_no_in_block_;
  uint16_t protected_pkt_num_in_this_block_;
  uint16_t protected_frame_num_in_this_block_;
  uint16_t fec_pkts_in_this_block_;
  uint16_t fragment_no_; //代表media pkt /fec pkt 在各自的frame/fec组内的序号
  uint16_t block_index_; //代表media pkt /fec pkt 在fec block组内的序号
  uint16_t fragments_in_this_frame_;
  uint32_t time_since_last_; /* microseconds */

  std::string payload_;

public:
  static constexpr size_t MAXIMUM_PAYLOAD = 1000;

  static std::string put_header_field( const uint16_t n );
  static std::string put_header_field( const uint32_t n );
  static std::string put_header_field( const uint64_t n );

  /* getters */
  bool valid() const { return valid_; }
  uint16_t connection_id() const { return connection_id_; }
  uint32_t source_state() const { return source_state_; }
  uint32_t target_state() const { return target_state_; }
  uint32_t frame_no() const { return frame_no_; }
  uint16_t fragment_no() const { return fragment_no_; }
  uint16_t block_index() const { return block_index_; }
  uint16_t is_fec_pkt() const { return is_fec_pkt_; }
  uint32_t block_no() const { return block_no_; }
  uint32_t first_frame_num_in_block() const { return first_frame_no_in_block_; }
  uint16_t fragments_in_this_frame() const { return fragments_in_this_frame_; }
  uint16_t protected_pkt_num_in_this_block() const { return protected_pkt_num_in_this_block_; }
  uint16_t protected_frame_num_in_this_block() const { return protected_frame_num_in_this_block_; }
  uint16_t fec_pkts_in_this_block() const { return fec_pkts_in_this_block_; }
  uint32_t time_since_last() const { return time_since_last_; }
  const std::string & payload() const { return payload_; }

  /* construct outgoing Packet */
  Packet( const std::vector<uint8_t> & whole_frame,
          const uint16_t is_fec_pkt,
          const uint16_t connection_id,
          const uint32_t source_state,
          const uint32_t target_state,
          const uint32_t frame_no,
          const uint32_t block_no,
          const uint32_t first_frame_num_in_block,
          const uint32_t protected_pkt_num_in_this_block,
          const uint32_t protected_frame_num_in_this_block,
          const uint32_t fec_pkts_in_this_block,
          const uint16_t fragment_no,
          const uint16_t block_index,
          const uint16_t time_to_next,
          size_t & next_fragment_start );

  /* construct incoming Packet */
  Packet( const Chunk & str );

  /* construct an empty, invalid packet */
  Packet();

  /* serialize a Packet */
  //在这里构造数据包
  std::string to_string() const;

  void set_fragments_in_this_frame( const uint16_t x );
  void set_time_to_next( const uint32_t val ) { time_since_last_ = val; }
};

class FecBlock
{
private:
  uint16_t connection_id_;
  uint32_t source_state_;
  uint32_t target_state_;

  uint32_t block_no_;//
  uint32_t first_frame_no_;
  uint16_t protected_pkts_in_this_block_;//目标应收 protected_pkts_in_this_block || least_pkts_to_fix_in_this_block_
  uint16_t frame_num_in_this_block_;
  uint16_t fec_pkts_in_this_block_;//本block内所添加的fec个数

  std::vector<Packet> fec_pkts_;
  std::vector<Packet> block_pkts_;

  // uint32_t remaining_pkts_to_fix_;
  uint32_t recved_pkts_num_;

public:
  // /* construct outgoing FragmentedFrame */
  //构造fec block并产生fec pkts
  FecBlock( const uint16_t connection_id,
                   const uint32_t source_state,
                   const uint32_t target_state,
                   const uint32_t block_no,
                   const uint32_t first_frame_no,
                   const uint32_t time_to_next_frame,
                   const uint16_t protected_pkt_num,
                   const uint16_t protected_frame_num,
                   const uint16_t fec_pkts_in_this_block,
                   uint16_t pkt_count_in_current_block,
                   const std::vector<uint8_t> & whole_frame );

  /* construct incoming FragmentedFrame from a Packet */
  FecBlock( const uint16_t connection_id,
                   const Packet & packet );

  void sanity_check( const Packet & packet ) const;

  /* read a new packet */
  void add_packet( const Packet & packet );

  // /* send */
  // void send( UDPSocket & socket );

  bool complete() const;

  /* getters */
  uint16_t connection_id() const { return connection_id_; }
  uint32_t source_state() const { return source_state_; }
  uint32_t target_state() const { return target_state_; }
  
  uint32_t block_no() const { return block_no_; }
  uint32_t first_frame_no() const { return first_frame_no_; }
  uint32_t frame_num_in_this_block() const { return frame_num_in_this_block_; }
  uint16_t fragments_in_this_frame() const { return protected_pkts_in_this_block_; }
  std::string frame() const;
  std::string partial_frame() const;
  const std::vector<Packet> & packets() const;

  /* delete copy-constructor and copy-assign operator */
  FecBlock( const FecBlock & other ) = delete;
  FecBlock & operator=( const FecBlock & other ) = delete;

  /* allow moving */
  FecBlock( FecBlock && other ) noexcept
    : connection_id_( other.connection_id_ ),
      source_state_( other.source_state_ ),
      target_state_( other.target_state_ ),
      block_no_( other.block_no_ ),
      first_frame_no_( other.first_frame_no_ ),
      protected_pkts_in_this_block_( other.protected_pkts_in_this_block_ ),
      frame_num_in_this_block_( other.frame_num_in_this_block_ ),
      fec_pkts_in_this_block_( other.fec_pkts_in_this_block_ ),
      fec_pkts_( move( other.fec_pkts_ ) ),
      block_pkts_( move( other.block_pkts_ ) ),
      recved_pkts_num_( other.recved_pkts_num_ )
      // remaining_pkts_to_fix_( other.remaining_pkts_to_fix_ )
  {}
};
class FragmentedFrame
{
private:
  uint16_t connection_id_;
  uint32_t source_state_;
  uint32_t target_state_;
  uint32_t frame_no_;
  uint16_t fragments_in_this_frame_;

  std::vector<Packet> fragments_;

  uint32_t remaining_fragments_;

public:
  /* construct outgoing FragmentedFrame */
  FragmentedFrame( const uint16_t connection_id,
                   const uint32_t source_state,
                   const uint32_t target_state,
                   const uint32_t frame_no,
                   const uint32_t block_no,//new added
                   const uint32_t first_frame_no,//new added
                   const uint16_t protected_pkt_num_in_this_block,//new added,0 for media pkt
                   uint16_t pkt_count_in_current_block,//stand for how many pkts have in this block inserted by former frames
                   const uint32_t time_to_next_frame,
                   const std::vector<uint8_t> & whole_frame );

  /* old construct outgoing FragmentedFrame */
  FragmentedFrame( const uint16_t connection_id,
    const uint32_t source_state,
    const uint32_t target_state,
    const uint32_t frame_no,
    const uint32_t time_to_next_frame,
    const std::vector<uint8_t> & whole_frame );

  /* construct incoming FragmentedFrame from a Packet */
  FragmentedFrame( const uint16_t connection_id,
                   const Packet & packet );

  void sanity_check( const Packet & packet ) const;

  /* read a new packet */
  void add_packet( const Packet & packet );

  /* send */
  void send( UDPSocket & socket );

  bool complete() const;

  /* getters */
  uint16_t connection_id() const { return connection_id_; }
  uint32_t source_state() const { return source_state_; }
  uint32_t target_state() const { return target_state_; }
  uint32_t frame_no() const { return frame_no_; }
  uint16_t fragments_in_this_frame() const { return fragments_in_this_frame_; }
  std::string frame() const;
  std::string partial_frame() const;
  const std::vector<Packet> & packets() const;

  /* delete copy-constructor and copy-assign operator */
  FragmentedFrame( const FragmentedFrame & other ) = delete;
  FragmentedFrame & operator=( const FragmentedFrame & other ) = delete;

  /* allow moving */
  FragmentedFrame( FragmentedFrame && other ) noexcept
    : connection_id_( other.connection_id_ ),
      source_state_( other.source_state_ ),
      target_state_( other.target_state_ ),
      frame_no_( other.frame_no_ ),
      fragments_in_this_frame_( other.fragments_in_this_frame_ ),
      fragments_( move( other.fragments_ ) ),
      remaining_fragments_( other.remaining_fragments_ )
  {}
};

class AckPacket
{
private:
  uint16_t connection_id_;
  uint32_t frame_no_;
  uint16_t fragment_no_;
  uint32_t avg_delay_;

  uint32_t current_state_;
  std::deque<uint32_t> complete_states_;

public:
  AckPacket( const uint16_t connection_id, const uint32_t frame_no,
             const uint16_t fragment_no, const uint32_t avg_delay,
             const uint32_t current_state, std::deque<uint32_t> complete_states );

  AckPacket( const Chunk & str );

  std::string to_string();

  void sendto( UDPSocket & socket, const Address & addr );

  /* getters */
  uint16_t connection_id() const { return connection_id_; }
  uint32_t frame_no() const { return frame_no_; }
  uint16_t fragment_no() const { return fragment_no_; }
  uint32_t avg_delay() const { return avg_delay_; }

  uint32_t current_state() const { return current_state_; }
  std::deque<uint32_t> complete_states() const { return complete_states_; }
};

#endif /* PACKET_HH */
