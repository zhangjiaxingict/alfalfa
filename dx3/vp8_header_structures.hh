#ifndef VP8_HEADER_STRUCTURES_HH
#define VP8_HEADER_STRUCTURES_HH

#include <vector>
#include <type_traits>

#include "optional.hh"
#include "bool_decoder.hh"

template <int width>
class Unsigned
{
private:
  uint8_t i_;

public:
  Unsigned( BoolDecoder & data ) : i_( data.uint( width ) )
  {
    static_assert( width <= 8, "Unsigned width must be <= 8" );
  }
  Unsigned( const uint8_t & val ) : i_( val ) {}

  operator const uint8_t & () const { return i_; }
};

template <int width>
class Signed
{
private:
  int8_t i_;

public:
  Signed( BoolDecoder & data ) : i_( data.sint( width ) )
  {
    static_assert( width <= 7, "Signed width must be <= 7" );
  }
  Signed( const int8_t & val ) : i_( val ) {}

  operator const int8_t & () const { return i_; }
};

class Bool
{
private:
  bool i_;

public:
  Bool( BoolDecoder & data, const uint8_t probability ) : i_( data.get( probability ) ) {}
  Bool( const bool & val ) : i_( val ) {}
  operator const bool & () const { return i_; }
  virtual ~Bool() {}
};

class Flag : public Bool
{
public:
  Flag( BoolDecoder & data ) : Bool( data, 128 ) {}
};

template <class T>
class Flagged : public Optional<T>
{
public:
  Flagged( BoolDecoder & data )
    : Optional<T>( Flag( data ), data )
  {}
};

/* An Array of VP8 header elements.
   A header element may optionally take its position in the array as an argument. */

template <class T, unsigned int size>
class Array
{
private:
  std::vector< T > storage_;

  template < int > struct switch_helper {};

  template < typename... Targs,
	     typename Y = switch_helper<1>,
	     typename = typename std::enable_if< std::is_constructible< T, BoolDecoder &, Targs... >::value, Y >::type >
  Array( switch_helper<1>, BoolDecoder & data, Targs&&... Fargs )
    : storage_()
  {
    storage_.reserve( size );
    for ( unsigned int i = 0; i < size; i++ ) {
      storage_.emplace_back( data, std::forward<Targs>( Fargs )... );
    }
  }

  template < typename... Targs,
	     typename Y = switch_helper<2>,
	     typename = typename std::enable_if< std::is_constructible< T, unsigned int, const Array &, BoolDecoder &, Targs... >::value, Y >::type >
  Array( switch_helper<2>, BoolDecoder & data, Targs&&... Fargs )
    : storage_()
  {
    storage_.reserve( size );
    for ( unsigned int i = 0; i < size; i++ ) {
      storage_.emplace_back( i, *this, data, std::forward<Targs>( Fargs )... );
    }
  }

public:
  template < typename... Targs >
  Array( BoolDecoder & data, Targs&&... Fargs ) : Array( {}, data, std::forward<Targs>(Fargs)... ) {}

  Array( const std::vector< T > & x ) : storage_( x ) {}

  const T & at( const typename decltype( storage_ )::size_type & offset ) const
  {
    return storage_.at( offset );
  }

  operator const std::vector< T > & () const { return storage_; }
};

template <class enumeration, uint8_t alphabet_size, const std::array< int8_t, 2 * (alphabet_size - 1) > & nodes>
class Tree
{
private:
  enumeration value_;

public:
  Tree( BoolDecoder & data, const std::array< uint8_t, alphabet_size - 1 > & probabilities )
    : value_( data.tree< alphabet_size, enumeration >( nodes, probabilities ) )
  {}

  Tree( const enumeration & x ) : value_( x ) {}

  operator const enumeration & () const { return value_; }

  virtual ~Tree() {}
};

#endif /* VP8_HEADER_STRUCTURES_HH */
