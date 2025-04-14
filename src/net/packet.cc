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

#include <string>
#include <algorithm>
#include <vector>

#include "packet.hh"

using namespace std;

string Packet::put_header_field( const uint16_t n )
{
  const uint16_t network_order = htole16( n );
  return string( reinterpret_cast<const char *>( &network_order ),
                 sizeof( network_order ) );
}

string Packet::put_header_field( const uint32_t n )
{
  const uint32_t network_order = htole32( n );
  return string( reinterpret_cast<const char *>( &network_order ),
                 sizeof( network_order ) );
}

string Packet::put_header_field( const uint64_t n )
{
  const uint32_t network_order = htole64( n );
  return string( reinterpret_cast<const char *>( &network_order ),
                 sizeof( network_order ) );
}

Packet::Packet( const vector<uint8_t> & whole_frame,
                const uint16_t is_fec_pkt,//add 1 extra element
                const uint16_t connection_id,
                const uint32_t source_state,
                const uint32_t target_state,
                const uint32_t frame_no,
                const uint32_t block_no,//add 2 extra element
                const uint32_t first_frame_no_in_block,//add 6 extra element
                const uint32_t protected_pkt_num_in_this_block,//add 3 extra element
                const uint32_t protected_frame_num_in_this_block,//add 4 extra element
                const uint32_t fec_pkts_in_this_block,//add 5 extra element
                const uint16_t fragment_no,
                const uint16_t block_index,
                const uint16_t time_since_last,
                size_t & next_fragment_start )
  : valid_( true ),
    is_fec_pkt_(is_fec_pkt),//
    connection_id_( connection_id ),
    source_state_( source_state ),
    target_state_( target_state ),
    frame_no_( frame_no ),
    block_no_(block_no),//
    first_frame_no_in_block_(first_frame_no_in_block),
    protected_pkt_num_in_this_block_(protected_pkt_num_in_this_block),//
    protected_frame_num_in_this_block_(protected_frame_num_in_this_block),//
    fec_pkts_in_this_block_(fec_pkts_in_this_block),//
    fragment_no_( fragment_no ),
    block_index_( block_index ),
    fragments_in_this_frame_( 0 ), /* temp value */
    time_since_last_( time_since_last ),
    payload_()
{
  assert( not whole_frame.empty() );

  size_t first_byte = MAXIMUM_PAYLOAD * fragment_no;
  assert( first_byte < whole_frame.size() );

  size_t length = min( whole_frame.size() - first_byte, MAXIMUM_PAYLOAD );//static constexpr size_t Packet::MAXIMUM_PAYLOAD = 1000UL
  assert( first_byte + length <= whole_frame.size() );

  payload_ = string( reinterpret_cast<const char*>( &whole_frame.at( first_byte ) ), length );

  next_fragment_start = first_byte + length;
}

/* construct incoming Packet */
Packet::Packet( const Chunk & str )
  : valid_( true ),
    is_fec_pkt_(str(0, 2).le16()) ,//
    connection_id_( str( 2, 2 ).le16() ),
    source_state_( str( 4, 4 ).le32() ),
    target_state_( str( 8, 4 ).le32() ),
    frame_no_( str( 12, 4 ).le32() ),
    block_no_(str( 16, 4 ).le32()),//
    first_frame_no_in_block_(str( 20, 4 ).le32()),//
    protected_pkt_num_in_this_block_(str( 24, 2 ).le16()),
    protected_frame_num_in_this_block_(str( 26, 2 ).le16()),
    fec_pkts_in_this_block_(str( 28, 2 ).le16()),//
    fragment_no_( str( 30, 2 ).le16() ),
    block_index_( str( 32, 2 ).le16() ),
    fragments_in_this_frame_( str( 34, 2 ).le16() ),
    time_since_last_( str( 36, 4 ).le32() ),
    payload_( str( 40 ).to_string() )
{ 
  // printf("fragment_no_:%u,fragments_in_this_frame=%u\n",fragment_no_,fragments_in_this_frame_);
  // printf("is_fec_pkt_: %u\n", is_fec_pkt_);
  // printf("connection_id_: %u\n", connection_id_);
  // printf("source_state_: %u\n", source_state_);
  // printf("target_state_: %u\n", target_state_);
  // printf("frame_no_: %u\n", frame_no_);
  // printf("block_no_: %u\n", block_no_);
  // printf("protected_pkt_num_in_this_block_: %u\n", protected_pkt_num_in_this_block_);
  // printf("protected_frame_num_in_this_block_: %u\n", protected_frame_num_in_this_block_);
  // printf("fec_pkts_in_this_block_: %u\n", fec_pkts_in_this_block_);
  // printf("fragment_no_: %u\n", fragment_no_);
  // printf("block_index_: %u\n", block_index_);
  // printf("fragments_in_this_frame_: %u\n", fragments_in_this_frame_);
  // printf("time_since_last_: %u\n", time_since_last_);
  if ( fragment_no_ >= fragments_in_this_frame_ ) {
    throw runtime_error( "invalid packet: fragment_no_ >= fragments_in_this_frame" );
  }

  if ( payload_.empty() ) {
    throw runtime_error( "invalid packet: empty payload" );
  }
}

/* construct an empty, invalid packet */
Packet::Packet()
  : valid_( false ),
    is_fec_pkt_(),
    connection_id_(),
    source_state_(),
    target_state_(),
    frame_no_(),
    block_no_(),//
    first_frame_no_in_block_(),//
    protected_pkt_num_in_this_block_(),
    protected_frame_num_in_this_block_(),
    fec_pkts_in_this_block_(),//
    fragment_no_(),
    block_index_(),
    fragments_in_this_frame_(),
    time_since_last_(),
    payload_()
{}

/* serialize a Packet */
string Packet::to_string() const
{
  assert( fragments_in_this_frame_ > 0 );

  return put_header_field( is_fec_pkt_ )
       + put_header_field( connection_id_ )
       + put_header_field( source_state_ )
       + put_header_field( target_state_ )
       + put_header_field( frame_no_ )
       + put_header_field( block_no_ )//
       + put_header_field( first_frame_no_in_block_ )//
       + put_header_field( protected_pkt_num_in_this_block_ )
       + put_header_field( protected_frame_num_in_this_block_ )
       + put_header_field( fec_pkts_in_this_block_ )//
       + put_header_field( fragment_no_ )
       + put_header_field( block_index_ )
       + put_header_field( fragments_in_this_frame_ )//when fec pkt , it stands for num of fec pkts in this fec-block
       + put_header_field( time_since_last_ )
       + payload_;
}

void Packet::set_fragments_in_this_frame( const uint16_t x )
{
  fragments_in_this_frame_ = x;
  assert( fragment_no_ < fragments_in_this_frame_ );
}
/*fec block logic*/
/* construct outgoing FecBlock */
FecBlock::FecBlock( const uint16_t connection_id,
                    const uint32_t source_state,
                    const uint32_t target_state,
                    const uint32_t block_no,//
                    const uint32_t first_frame_no,//
                    const uint32_t time_to_next_frame,
                    const uint16_t protected_pkt_num,// in this block
                    const uint16_t protected_frame_num,
                    const uint16_t fec_pkts_in_this_block,
                    uint16_t pkt_count_in_current_block,//
                    const vector<uint8_t> & fec_block )
  : connection_id_( connection_id ),
    source_state_( source_state ),
    target_state_( target_state ),
    block_no_( block_no ),//
    first_frame_no_( first_frame_no ),//
    protected_pkts_in_this_block_( protected_pkt_num ),//target pkt num ,protected_pkts_in_this_block_ to fix
    frame_num_in_this_block_(protected_frame_num),
    fec_pkts_in_this_block_(fec_pkts_in_this_block),//
    fec_pkts_(),
    block_pkts_(),
    // remaining_pkts_to_fix_( 0 ),
    recved_pkts_num_(0)
{
  size_t next_fragment_start = 0;

  for ( uint16_t fragment_no = 0; next_fragment_start < fec_block.size();
        fragment_no++ ) {
    fec_pkts_.emplace_back( fec_block, 1, connection_id, source_state_, target_state_,
                            0, block_no, first_frame_no_, protected_pkts_in_this_block_ ,frame_num_in_this_block_,
                            fec_pkts_in_this_block_, fragment_no, pkt_count_in_current_block, 0, next_fragment_start );//通过FragmentedFrame构造pkt：可能构造media_pkt或fec_pkt
    pkt_count_in_current_block++;
  }//1 in first line stands for fec pkt
  //the 0 in second line because fec pkts dont have frame_no

  fec_pkts_.front().set_time_to_next( time_to_next_frame );

  fec_pkts_in_this_block_ = fec_pkts_.size();
  // remaining_pkts_to_fix_ = 0;
  recved_pkts_num_ = 0 ;

  for ( Packet & packet : fec_pkts_ ) {
    packet.set_fragments_in_this_frame( fec_pkts_in_this_block_ );
  }
}

  /* construct incoming FecBlock from a Packet */
  FecBlock::FecBlock( const uint16_t connection_id,
                                  const Packet & packet )
  : connection_id_( connection_id ),
    source_state_( packet.source_state() ),
    target_state_( packet.target_state() ),
    // fec setting
    block_no_( packet.block_no() ),
    first_frame_no_( packet.first_frame_num_in_block() ),
    protected_pkts_in_this_block_( packet.protected_pkt_num_in_this_block() ), //for media pkt ,it's 0
    frame_num_in_this_block_(packet.protected_frame_num_in_this_block()), //for media pkt ,it's 0
    //fec_pkts_in_this_block_( packet.fragments_in_this_frame() ),//都是可以的
    fec_pkts_in_this_block_( packet.fec_pkts_in_this_block() ), //for media pkt ,it's 0
    //protected_frame_num_in_this_block( packet.protected_frame_num_in_this_block() ), //currently we dont care
    fec_pkts_( packet.fec_pkts_in_this_block() ),//开这么大的len for media pkt ,it's 0
    block_pkts_( packet.fec_pkts_in_this_block() + packet.protected_pkt_num_in_this_block() ),//block size = media pkts + fec pkts
    // remaining_pkts_to_fix_( packet.fragments_in_this_frame() ) --media version
    //both media and fec pkt can trigger new FecBlock
    // remaining_pkts_to_fix_( packet.protected_pkt_num_in_this_block() ), //we set target size here and add pkt later
    recved_pkts_num_(0)
    //on frame not the last in the block ,we dont know exactly protected_pkt_num_in_this_block,just set a large num/infinity,and update each time a new pkt arrive
{
  sanity_check( packet );

  add_packet( packet );
}

void FecBlock::sanity_check( const Packet & packet ) const {
  // TODO : FEC 的 sanity_check
  if ( packet.connection_id() != connection_id_ ) {
    cerr << packet.connection_id() << " vs. " << connection_id_ << "\n";
    throw runtime_error( "invalid packet, connection_id mismatch" );
  }

  // if ( packet.source_state() != source_state_ ) {
  //   throw runtime_error( "invalid packet, source_state mismatch" );
  // }

  // if ( packet.target_state() != target_state_ ) {
  //   throw runtime_error( "invalid packet, source_state mismatch" );
  // }

  // if ( packet.fragments_in_this_frame() != fec_pkts_in_this_block_ ) {
  //   throw runtime_error( "invalid packet, fragments_in_this_frame mismatch" );
  // }

  // if ( packet.block_no() != block_no_ ) {
  //   throw runtime_error( "invalid packet, block_no mismatch" );
  // }

  // if ( packet.fragment_no() >= fec_pkts_in_this_block_ ) {
  //   throw runtime_error( "invalid packet, fragment_no >= fec_pkts_in_this_block_" );
  // }
}

/* read a new packet */
void FecBlock::add_packet( const Packet & packet )
{
  sanity_check( packet );

  // if(packet.is_fec_pkt()){}
  if(packet.block_index() >= block_pkts_.size()){//block_pkts_[ packet.block_index() ] == nullptr
    block_pkts_.resize(packet.block_index() + 1);
  }

  if ( not block_pkts_[ packet.block_index() ].valid() ) {//check if recv the same pkt in block again
    // remaining_pkts_to_fix_--;
    recved_pkts_num_++;
    //新进入的包更新fecblock内的参数设定，只在接收到fec包时更新
    if(packet.is_fec_pkt()){
      // fec_pkts_( packet.fec_pkts_in_this_block() );
      if(protected_pkts_in_this_block_==0 && frame_num_in_this_block_==0 && fec_pkts_in_this_block_==0){
        protected_pkts_in_this_block_ = packet.protected_pkt_num_in_this_block();
        frame_num_in_this_block_ = packet.protected_frame_num_in_this_block();
        fec_pkts_in_this_block_ = packet.fec_pkts_in_this_block();
        printf("protected_pkts_in_this_block_=%u",protected_pkts_in_this_block_);
        printf("frame_num_in_this_block_=%u",frame_num_in_this_block_);
        printf("fec_pkts_in_this_block_=%u",fec_pkts_in_this_block_);
        fec_pkts_.resize(packet.fec_pkts_in_this_block());//fec status update，直接更新到完整的block size
        block_pkts_.resize(packet.fec_pkts_in_this_block() + packet.protected_pkt_num_in_this_block());
      }
      else{
        //media pkt , update fdec status temply
        block_pkts_.resize(packet.block_index());//收一个开一个 2025.4.9，todo ：do it in a more graceful way
      }
    }
    //更新fecblock的
    block_pkts_[ packet.block_index() ] = packet;
  }
}
/* send */
// void FragmentedFrame::send( UDPSocket & socket )
// {
//   if ( fragments_.size() != fragments_in_this_frame_ ) {
//     throw runtime_error( "attempt to send unfinished FragmentedFrame" );
//   }

//   assert( complete() );

//   for ( const Packet & packet : fragments_ ) {
//     socket.send( packet.to_string() );
//   }
// }

/* check if fec block can be decoded */
bool FecBlock::complete() const
{
  printf("protected_pkts_in_this_block_=%u",protected_pkts_in_this_block_);
  printf("frame_num_in_this_block_=%u",frame_num_in_this_block_);
  printf("fec_pkts_in_this_block_=%u",fec_pkts_in_this_block_);
  //first check fecblock valid? : p/f num !=0
  if(protected_pkts_in_this_block_==0 || frame_num_in_this_block_==0 || fec_pkts_in_this_block_==0)
  {
    throw runtime_error( "fec setting not upodated before fix check" );//only fec pkt can trigger fix-check
    // return false; 
  }//fec-block not valid(no fec pkt recved yet)
  else
  {
    //try to decode
    printf("fec try to fix check:recved_pkts_num_%u,protected_pkts_in_this_block_%u\n",recved_pkts_num_,protected_pkts_in_this_block_);
    return recved_pkts_num_ >= protected_pkts_in_this_block_;
  }
}

const vector<Packet> & FecBlock::packets() const
{
  // if ( (not complete()) or (fec_pkts_.size() != fec_pkts_in_this_block_) ) {
  //   throw runtime_error( "attempt to access unfinished FragmentedFrame" );
  // }

  return fec_pkts_;
}


/* construct outgoing FragmentedFrame */
FragmentedFrame::FragmentedFrame( const uint16_t connection_id,
                                  const uint32_t source_state,
                                  const uint32_t target_state,
                                  const uint32_t frame_no,
                                  const uint32_t block_no,//new added
                                  const uint32_t first_frame_no,//new added,0
                                  const uint16_t protected_pkt_num_in_this_block,//new added,0 for media pkt
                                  uint16_t pkt_count_in_current_block,//stand for how many pkts have in this block inserted by former frames
                                  const uint32_t time_since_last,
                                  const vector<uint8_t> & whole_frame )
  : connection_id_( connection_id ),
    source_state_( source_state ),
    target_state_( target_state ),
    frame_no_( frame_no ),
    fragments_in_this_frame_(),
    fragments_(),
    remaining_fragments_( 0 )
{
  size_t next_fragment_start = 0;
  uint16_t is_fec_pkt = 0;//media pkts
  // uint16_t protected_pkt_num_in_this_block = 0;//not know yet
  uint16_t protected_frame_num_in_this_block = 0;
  uint16_t fec_pkts_in_this_block = 0;

  for ( uint16_t fragment_no = 0; next_fragment_start < whole_frame.size();
        fragment_no++ ) {
    fragments_.emplace_back( whole_frame, is_fec_pkt, connection_id, source_state_,
                             target_state_, frame_no, block_no, first_frame_no, protected_pkt_num_in_this_block,//packet类多了4个新的成员
                             protected_frame_num_in_this_block, fec_pkts_in_this_block,
                             fragment_no, pkt_count_in_current_block, 0, next_fragment_start );//通过FragmentedFrame构造pkt：可能构造media_pkt或fec_pkt
    pkt_count_in_current_block++;
  }

  fragments_.front().set_time_to_next( time_since_last );

  fragments_in_this_frame_ = fragments_.size();
  remaining_fragments_ = 0;

  for ( Packet & packet : fragments_ ) {
    packet.set_fragments_in_this_frame( fragments_in_this_frame_ );
  }
}

/* old construct outgoing FragmentedFrame  just for compile salsify*/
FragmentedFrame::FragmentedFrame( const uint16_t connection_id,
  const uint32_t source_state,
  const uint32_t target_state,
  const uint32_t frame_no,
  const uint32_t time_since_last,
  const vector<uint8_t> & whole_frame )
: connection_id_( connection_id ),
source_state_( source_state ),
target_state_( target_state ),
frame_no_( frame_no ),
fragments_in_this_frame_(),
fragments_(),
remaining_fragments_( 0 )
{
  uint32_t next_fragment_start = time_since_last;
  next_fragment_start++;
  int a = whole_frame.size();
  a++;
// size_t next_fragment_start = 0;
// uint16_t is_fec_pkt = 0;//media pkts
// // uint16_t protected_pkt_num_in_this_block = 0;//not know yet
// uint16_t protected_frame_num_in_this_block = 0;
// uint16_t fec_pkts_in_this_block = 0;
// for ( uint16_t fragment_no = 0; next_fragment_start < whole_frame.size();
// fragment_no++ ) {
// fragments_.emplace_back( whole_frame, is_fec_pkt, connection_id, source_state_,
// target_state_, frame_no, block_no, protected_pkt_num_in_this_block,//packet类多了4个新的成员
// protected_frame_num_in_this_block, fec_pkts_in_this_block,
// fragment_no, 0, next_fragment_start );//通过FragmentedFrame构造pkt：可能构造media_pkt或fec_pkt
// }

// fragments_.front().set_time_to_next( time_since_last );

// fragments_in_this_frame_ = fragments_.size();
// remaining_fragments_ = 0;

// for ( Packet & packet : fragments_ ) {
// packet.set_fragments_in_this_frame( fragments_in_this_frame_ );
// }
}

  /* construct incoming FragmentedFrame from a Packet */
FragmentedFrame::FragmentedFrame( const uint16_t connection_id,
                                  const Packet & packet )
  : connection_id_( connection_id ),
    source_state_( packet.source_state() ),
    target_state_( packet.target_state() ),
    frame_no_( packet.frame_no() ),
    fragments_in_this_frame_( packet.fragments_in_this_frame() ),
    fragments_( packet.fragments_in_this_frame() ),
    remaining_fragments_( packet.fragments_in_this_frame() )
{
  sanity_check( packet );

  add_packet( packet );
}

void FragmentedFrame::sanity_check( const Packet & packet ) const {
  if ( packet.connection_id() != connection_id_ ) {
    cerr << packet.connection_id() << " vs. " << connection_id_ << "\n";
    throw runtime_error( "invalid packet, connection_id mismatch" );
  }

  if ( packet.source_state() != source_state_ ) {
    throw runtime_error( "invalid packet, source_state mismatch" );
  }

  if ( packet.target_state() != target_state_ ) {
    throw runtime_error( "invalid packet, source_state mismatch" );
  }

  if ( packet.fragments_in_this_frame() != fragments_in_this_frame_ ) {
    throw runtime_error( "invalid packet, fragments_in_this_frame mismatch" );
  }

  if ( packet.frame_no() != frame_no_ ) {
    throw runtime_error( "invalid packet, frame_no mismatch" );
  }

  if ( packet.fragment_no() >= fragments_in_this_frame_ ) {
    throw runtime_error( "invalid packet, fragment_no >= fragments_in_this_frame" );
  }
}

/* read a new packet */
void FragmentedFrame::add_packet( const Packet & packet )
{
  sanity_check( packet );

  if ( not fragments_[ packet.fragment_no() ].valid() ) {
    remaining_fragments_--;
    fragments_[ packet.fragment_no() ] = packet;
  }
}

/*fec fix a frame*/
void FragmentedFrame::fix_fragments() {
  remaining_fragments_ = 0;
  for (auto& fragment : fragments_) {
    fragment.setvalid(); //将元素置为有效状态,simulated fec decoding
    // fragment = reconstructed_packet; //fec decoding
  }
}  
/* send */
void FragmentedFrame::send( UDPSocket & socket )
{
  if ( fragments_.size() != fragments_in_this_frame_ ) {
    throw runtime_error( "attempt to send unfinished FragmentedFrame" );
  }

  assert( complete() );

  for ( const Packet & packet : fragments_ ) {
    socket.send( packet.to_string() );
  }
}

bool FragmentedFrame::complete() const
{
  return remaining_fragments_ == 0;
}

const vector<Packet> & FragmentedFrame::packets() const
{
  if ( (not complete()) or (fragments_.size() != fragments_in_this_frame_) ) {
    throw runtime_error( "attempt to access unfinished FragmentedFrame" );
  }

  return fragments_;
}

string FragmentedFrame::frame() const
{
  string ret;

  if ( not complete() ) {
    throw runtime_error( "attempt to build frame from unfinished FragmentedFrame" );
  }

  for ( const auto & fragment : fragments_ ) {
    ret.append( fragment.payload() );
  }

  return ret;
}

string FragmentedFrame::partial_frame() const
{
  string ret;

  for ( const auto & fragment : fragments_ ) {
    if ( not fragment.valid() ) {
      break;
    }

    ret.append( fragment.payload() );
  }

  return ret;
}

/* AckPacket */

AckPacket::AckPacket( const uint16_t connection_id, const uint32_t frame_no,
                      const uint16_t fragment_no, const uint32_t avg_delay,
                      const uint32_t current_state, deque<uint32_t> complete_states )
  : connection_id_( connection_id ), frame_no_( frame_no ),
    fragment_no_( fragment_no ), avg_delay_( avg_delay ),
    current_state_( current_state ), complete_states_( complete_states )
{}

AckPacket::AckPacket( const Chunk & str )
  : connection_id_( str( 0, 2 ).le16() ),
    frame_no_( str( 2, 4 ).le32() ),
    fragment_no_( str( 6, 2 ).le16() ),
    avg_delay_( str( 8, 4 ).le32() ),
    current_state_( str( 12, 4 ).le32() ),
    complete_states_( str( 16, 4 ).le32() )
{
  for ( size_t i = 0; i < complete_states_.size(); i++ ) {
    complete_states_[ i ] = str( 20 + i * 4, 4 ).le32();
  }
}

std::string AckPacket::to_string()
{
  string packet = Packet::put_header_field( connection_id_ )
                + Packet::put_header_field( frame_no_ )
                + Packet::put_header_field( fragment_no_ )
                + Packet::put_header_field( avg_delay_ )
                + Packet::put_header_field( current_state_ );

  packet += Packet::put_header_field( static_cast<uint32_t>( complete_states_.size() ) );

  for ( const auto state : complete_states_ ) {
    packet += Packet::put_header_field( state );
  }

  return packet;
}

void AckPacket::sendto( UDPSocket & socket, const Address & addr )
{
  socket.sendto( addr, to_string() );
}
