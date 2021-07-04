#pragma once
#include <tuple>
#include <random>
#include <cstdint>
#include <memory>
#include "windows_exports.hpp"
#include "fnv.hpp"
#include "pattern.hpp"
#include "xorstr.hpp"

using process_reference = std::unique_ptr<std::remove_pointer_t<PEPROCESS>, decltype( &ObfDereferenceObject )>;
using driver_reference = std::unique_ptr<std::remove_pointer_t<PDRIVER_OBJECT>, decltype( &ObfDereferenceObject )>;

namespace utils
{
	PLDR_DATA_TABLE_ENTRY system_module( const wchar_t* module_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		UNICODE_STRING unicode_string{ };
		RtlInitUnicodeString( &unicode_string, module_name );

		PLDR_DATA_TABLE_ENTRY system_module_entry = nullptr;

		for ( auto entry = PsLoadedModuleList; entry != PsLoadedModuleList->Blink; entry = entry->Flink )
		{
			PLDR_DATA_TABLE_ENTRY data_table = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

			if ( RtlEqualUnicodeString( &data_table->BaseDllName, &unicode_string, TRUE ) )
			{
				system_module_entry = data_table;
				break;
			}
		}

		return system_module_entry;
	}

	void* system_routine( const wchar_t* routine_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		UNICODE_STRING unicode_string{ };
		RtlInitUnicodeString( &unicode_string, routine_name );

		return MmGetSystemRoutineAddress( &unicode_string );
	}

	void* system_export( const wchar_t* module_name, const char* export_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		const auto module = system_module( module_name );

		if ( !module )
			return nullptr;

		return RtlFindExportedRoutineByName( module->DllBase, export_name );
	}

	void* trampoline_at( void* base_address )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		const auto nt_header = RtlImageNtHeader( base_address );

		if ( !nt_header )
			return nullptr;

		const auto section_array = reinterpret_cast< PIMAGE_SECTION_HEADER >( nt_header + 1 );

		for ( auto section = 0; section < nt_header->FileHeader.NumberOfSections; section++ )
		{
			const auto current = section_array[ section ];

			if ( current.VirtualAddress == 0 || current.Misc.VirtualSize == 0 )
				continue;

			if ( !( current.Characteristics & 0x20000000 ) || !( current.Characteristics & 0x08000000 ) )
				continue;

			const auto section_address = reinterpret_cast< char* >( base_address ) + current.VirtualAddress;

			for ( auto i = section_address; i < ( section_address + current.SizeOfRawData ) - 1; ++i )
			{
				if ( !i )
					continue;
				
				if ( *reinterpret_cast< std::uint16_t* >( i ) == 0xe1ff )
					return i;
			}
		}

		return nullptr;
	}

	process_reference reference_process_by_pid( std::uintptr_t pid)
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		PEPROCESS process{ };

		if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( pid ), &process ) ) )
			return process_reference(nullptr, nullptr);

		return process_reference( process, &ObfDereferenceObject );
	}

	driver_reference reference_driver_by_name( const wchar_t* driver_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		UNICODE_STRING driver_unicode{ };
		RtlInitUnicodeString( &driver_unicode, driver_name );

		PDRIVER_OBJECT driver_local = nullptr;
		ObReferenceObjectByName( &driver_unicode, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast< void** >( &driver_local ) );

		return driver_reference( driver_local, &ObfDereferenceObject );
	}

	std::uint32_t get_windows_version( )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );
		
		RTL_OSVERSIONINFOW version_info = { 0 };
		version_info.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOW );

		if ( !NT_SUCCESS( RtlGetVersion( &version_info ) ) )
			return 0;

		if ( version_info.dwBuildNumber > 16352 && version_info.dwBuildNumber < 17135 )
			return 1803;

		if ( version_info.dwBuildNumber > 17603 && version_info.dwBuildNumber < 17765 )
			return 1809;

		if ( version_info.dwBuildNumber >= 18360 )
			return 1903;

		return 0;
	}

	bool clean_piddb_table()
	{
		const auto PiDDBCacheTable_address = memory::from_pattern( system_module( _( L"ntoskrnl.exe" ) ), _( "\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83" ), _( "xxx????x????x????xx" ) );

		if ( !PiDDBCacheTable_address )
			return false;

		const auto PiDDBCacheTable = reinterpret_cast< PRTL_AVL_TABLE >( PiDDBCacheTable_address + *reinterpret_cast< std::int32_t* >( PiDDBCacheTable_address + 3 ) + 7 );

		const auto first_entry = reinterpret_cast< PiDDBCacheEntry* >( std::uintptr_t( PiDDBCacheTable->BalancedRoot.RightChild ) + sizeof( RTL_BALANCED_LINKS ) );

		UNICODE_STRING falsified_string{ };
		RtlInitUnicodeString( &falsified_string, _( L"monitor.sys" ) );
		
		if ( first_entry->TimeDateStamp == 0x5284eac3 )
		{
			first_entry->TimeDateStamp = 0x54eac3;
			first_entry->DriverName = falsified_string;

			return true;
		}

		for ( auto current = first_entry->List.Flink; current != first_entry->List.Blink; current = current->Flink )
		{
			const auto casted_entry = reinterpret_cast< PiDDBCacheEntry* >( current );

			if ( !casted_entry )
				continue;

			if ( casted_entry->TimeDateStamp != 0x5284eac3 )
				continue;

			first_entry->TimeDateStamp = 0x54eac3;
			first_entry->DriverName = falsified_string;
		}

		return true;
	}
}

namespace serializer
{
	// thanks to namazso
	static inline bool is_good_char( char c )
	{
		const auto u = uint8_t( c );
		return ( u >= uint8_t( '0' ) && u <= uint8_t( '9' ) )
			|| ( u >= uint8_t( 'A' ) && u <= uint8_t( 'Z' ) )
			|| ( u >= uint8_t( 'a' ) && u <= uint8_t( 'z' ) );
	}
	static inline bool is_hex( char c )
	{
		const auto u = uint8_t( c );
		return ( u >= uint8_t( '0' ) && u <= uint8_t( '9' ) )
			|| ( u >= uint8_t( 'A' ) && u <= uint8_t( 'F' ) )
			|| ( u >= uint8_t( 'a' ) && u <= uint8_t( 'f' ) );
	}
	static inline uint8_t unhex_char( char c )
	{
		const auto u = uint8_t( c );
		if ( u >= uint8_t( '0' ) && u <= uint8_t( '9' ) )
			return u - uint8_t( '0' );
		if ( u >= uint8_t( 'A' ) && u <= uint8_t( 'F' ) )
			return u - uint8_t( 'A' ) + 0xA;
		if ( u >= uint8_t( 'a' ) && u <= uint8_t( 'f' ) )
			return u - uint8_t( 'a' ) + 0xa;
		return 0xFF;
	}
	static inline uint8_t unhex_byte( char a, char b ) { return ( unhex_char( a ) << 4 ) + unhex_char( b ); }
	static inline char hex_char( uint8_t v )
	{
		if ( v < 0xA )
			return char( uint8_t( '0' ) + v );
		return char( uint8_t( 'A' ) + v - 0xA );
	}
	static inline std::pair<char, char> hex_byte( uint8_t v ) { return { hex_char( v >> 4 ), hex_char( v & 0xF ) }; }

	static fnv::hash hash_subserial( const char* serial, size_t len )
	{
		auto h = fnv::hash_init( );
		for ( auto i = 0u; i < len; ++i )
			if ( is_good_char( serial[ i ] ) )
				h = fnv::hash_byte( h, serial[ i ] );
		return h;
	}

	void randomize_subserial( std::uintptr_t start, char* serial, size_t len )
	{
		if ( !serial )
			return;
		
		const auto seed = hash_subserial( serial, len ) ^ start;
		auto engine = std::mt19937_64{ seed };
		const auto distribution = std::uniform_int_distribution<unsigned>( 'A', 'Z' );

		for ( auto i = 0u; i < len; ++i )
			if ( is_good_char( serial[ i ] ) )
				serial[ i ] = char( distribution( engine ) );
	}

	void randomize( std::uintptr_t start, char* serial )
	{
		if ( !serial )
			return;
		
		// must be 20 or less
		size_t len;
		char buf[ 21 ];

		bool is_serial_hex = true;

		for ( len = 0; serial[ len ]; ++len )
			if ( !is_hex( serial[ len ] ) )
				is_serial_hex = false;

		if ( is_serial_hex )
		{
			len /= 2;
			len = std::min<size_t>( len, 20 );
			for ( auto i = 0u; i < len; ++i )
				buf[ i ] = unhex_byte( serial[ i * 2 ], serial[ i * 2 + 1 ] );
		}
		else
		{
			memcpy( buf, serial, len );
		}


		buf[ len ] = 0;
		char split[ 2 ][ 11 ];
		memset( split, 0, sizeof( split ) );

		for ( auto i = 0u; i < len; ++i )
			split[ i % 2 ][ i / 2 ] = buf[ i ];

		randomize_subserial( start, split[ 0 ], ( len + 1 ) / 2 );
		randomize_subserial( start, split[ 1 ], len / 2 );

		for ( auto i = 0u; i < len; ++i )
			buf[ i ] = split[ i % 2 ][ i / 2 ];
		buf[ len ] = 0;

		if ( is_serial_hex )
		{
			for ( auto i = 0u; i < len; ++i )
				std::tie( serial[ i * 2 ], serial[ i * 2 + 1 ] ) = hex_byte( buf[ i ] );
			serial[ len * 2 ] = 0;
		}
		else
		{
			memcpy( serial, buf, len + 1 );
		}
	}
}