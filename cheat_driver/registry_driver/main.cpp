#include "windows_exports.hpp"
#include "utils.hpp"
#include "shared_structs.hpp"
#include "pattern.hpp"
#include "raid_extension.hpp"
#include "xorstr.hpp"

#include <string>
#include <memory>


void write_to_local_memory( PEPROCESS local_process, void* data, void* data_local, std::uint64_t size )
{
	if ( !data )
		return;

	if ( !local_process )
		return;

	static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uint64_t( PsLoadedModuleList ) + 0x30 );

	const auto is_process = local_process == IoGetCurrentProcess( );

	KAPC_STATE apc{ };

	if ( !is_process )
		KeStackAttachProcess( local_process, &apc );

	memcpy( data_local, data, size );

	if ( !is_process )
		KeUnstackDetachProcess( &apc );
}

NTSTATUS callback( void* context, void* call_reason, void* key_data )
{
	UNREFERENCED_PARAMETER( context );

	auto return_value = STATUS_SUCCESS;

	if ( reinterpret_cast< std::uint64_t >( call_reason ) == RegNtPreSetValueKey )
	{
		const auto key_value = static_cast< PREG_SET_VALUE_KEY_INFORMATION >( key_data );

		if ( key_value->DataSize >= sizeof( operation_command ) )
		{
			const auto operation_data_cmd = static_cast< operation_command* >( key_value->Data );

			if ( operation_data_cmd->serial_key == 0x3c10bd66)
			{
				return_value = STATUS_ACCESS_DENIED;

				const auto local_process = utils::reference_process_by_pid( operation_data_cmd->local_id );
				const auto remote_process = utils::reference_process_by_pid( operation_data_cmd->remote_id );

				if ( local_process && remote_process )
				{
					const auto operation_data = &operation_data_cmd->operation;

					static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );
					static const auto ValidateHwnd = reinterpret_cast< std::uintptr_t( __stdcall* )( std::uintptr_t ) >( utils::system_export( _( L"win32kbase.sys" ), _( "ValidateHwnd" ) ) );

					switch ( operation_data->type )
					{
						case operation_read:
							{
								if ( !operation_data->virtual_address || !operation_data->buffer )
									break;

								SIZE_T return_size = 0;
								MmCopyVirtualMemory( remote_process.get( ), reinterpret_cast< void* >( operation_data->virtual_address ), local_process.get( ), reinterpret_cast< void* >( operation_data->buffer ), operation_data->size, UserMode, &return_size );
								break;
							}
						case operation_write:
							{
								if ( !operation_data->virtual_address || !operation_data->buffer )
									break;

								SIZE_T return_size = 0;
								MmCopyVirtualMemory( local_process.get( ), reinterpret_cast< void* >( operation_data->buffer ), remote_process.get( ), reinterpret_cast< void* >( operation_data->virtual_address ), operation_data->size, UserMode, &return_size );
								break;
							}
						case operation_protect:
							{
								if ( !operation_data->virtual_address )
									break;

								const auto new_protection = operation_data->new_protection;
								auto address = reinterpret_cast< void* >( operation_data->virtual_address );
								auto old_protection = 0ul;
								auto size = operation_data->size;

								KAPC_STATE apc_state{ };

								KeStackAttachProcess( remote_process.get( ), &apc_state );

								ZwProtectVirtualMemory( ZwCurrentProcess( ), &address, &size, new_protection, &old_protection );

								KeUnstackDetachProcess( &apc_state );

								operation request{ };
								request.old_protection = old_protection;

								write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
								break;
							}
						case operation_allocation:
							{
								if ( !operation_data->virtual_address )
									break;

								auto address = reinterpret_cast< void* >( operation_data->virtual_address );
								auto size = operation_data->size;
								auto protection = operation_data->new_protection;

								KAPC_STATE apc_state{ };

								KeStackAttachProcess( remote_process.get( ), &apc_state );

								ZwAllocateVirtualMemory( ZwCurrentProcess( ), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, protection );

								KeUnstackDetachProcess( &apc_state );

								operation request{ };
								request.virtual_address = reinterpret_cast< std::uintptr_t >( address );
								request.size = size;

								write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
								break;
							}
						case operation_base:
							{
								operation request{ };
								request.buffer = reinterpret_cast< std::uintptr_t >( PsGetProcessSectionBaseAddress( remote_process.get( ) ) );

								write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
								break;
							}
						case operation_module:
							{
								//const auto name = operation_data->module_name;
								const auto peb = reinterpret_cast< PPEB64 >( PsGetProcessPeb( remote_process.get( ) ) );

								if ( !peb )
									break;

								KAPC_STATE apc_state{ };

								KeStackAttachProcess( remote_process.get( ), &apc_state );

								PVOID base_address = nullptr;

								UNICODE_STRING unicode_string{ };
								RtlInitUnicodeString( &unicode_string, _( L"UnityPlayer.dll" ) );

								for ( auto list_entry = peb->Ldr->InLoadOrderLinks.Flink; list_entry != &peb->Ldr->InLoadOrderLinks; list_entry = list_entry->Flink )
								{
									if ( !list_entry )
										continue;

									PLDR_DATA_TABLE_ENTRY data_table = CONTAINING_RECORD( list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

									if ( RtlEqualUnicodeString( &data_table->BaseDllName, &unicode_string, TRUE ) )
									{
										base_address = data_table->DllBase;
										break;
									}
								}

								KeUnstackDetachProcess( &apc_state );

								operation request{ };
								request.buffer = reinterpret_cast< std::uintptr_t >( base_address );

								write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
								break;
							}
						case operation_module2:
						{
							//const auto name = operation_data->module_name;
							const auto peb = reinterpret_cast< PPEB64 >( PsGetProcessPeb( remote_process.get( ) ) );

							if ( !peb )
								break;

							KAPC_STATE apc_state{ };

							KeStackAttachProcess( remote_process.get( ), &apc_state );

							PVOID base_address = nullptr;

							UNICODE_STRING unicode_string{ };
							RtlInitUnicodeString( &unicode_string, _( L"GameAssembly.dll" ) );

							for ( auto list_entry = peb->Ldr->InLoadOrderLinks.Flink; list_entry != &peb->Ldr->InLoadOrderLinks; list_entry = list_entry->Flink )
							{
								if ( !list_entry )
									continue;

								PLDR_DATA_TABLE_ENTRY data_table = CONTAINING_RECORD( list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

								if ( RtlEqualUnicodeString( &data_table->BaseDllName, &unicode_string, TRUE ) )
								{
									base_address = data_table->DllBase;
									break;
								}
							}

							KeUnstackDetachProcess( &apc_state );

							operation request{ };
							request.buffer = reinterpret_cast< std::uintptr_t >( base_address );

							write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
							break;
						}
						case operation_window_get:
							{
								if ( !ValidateHwnd )
									break;

								const auto validated_window = ValidateHwnd( operation_data->virtual_address );

								if ( !validated_window )
									break;

								operation request{};
								request.buffer = *reinterpret_cast< std::uintptr_t* >( validated_window + 0x10 );

								write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
								break;
							}
						case operation_window_set:
							{
								if ( !ValidateHwnd )
									break;

								const auto validated_window = ValidateHwnd( operation_data->virtual_address );

								if ( !validated_window )
									break;

								SIZE_T return_size = 0;
								MmCopyVirtualMemory( PsGetCurrentProcess( ), reinterpret_cast< void* >( &operation_data->buffer ), PsGetCurrentProcess( ), reinterpret_cast< void* >( validated_window + 0x10 ), sizeof( PVOID ), KernelMode, &return_size );
								break;
							}
						case operation_verification:
							{
								operation request{};
								request.buffer = 1;

								write_to_local_memory( local_process.get( ), &request, reinterpret_cast< void* >( operation_data_cmd->operation_address ), sizeof( operation ) );
								break;
							}
						case operation_hardware_spoof:
							{
								const auto windows_version = utils::get_windows_version( );

								if ( windows_version != 0 )
								{
									static const auto DiskEnableDisableFailurePrediction = reinterpret_cast< NTSTATUS( __fastcall* )( PFUNCTIONAL_DEVICE_EXTENSION, BOOLEAN ) >( memory::from_pattern( utils::system_module( _( L"disk.sys" ) ), _( "\x48\x89\x5c\x24\x00\x48\x89\x74\x24\x00\x57\x48\x81\xec\x00\x00\x00\x00\x48\x8b\x05\x00\x00\x00\x00\x48\x33\xc4\x48\x89\x84\x24\x00\x00\x00\x00\x48\x8b\x59\x60\x48\x8b\xf1\x40\x8a\xfa\x8b\x4b\x10" ), _( "xxxx?xxxx?xxxx????xxx????xxxxxxx????xxxxxxxxxxxxx" ) ) );

									if ( DiskEnableDisableFailurePrediction == nullptr )
										break;

									static const auto RaidUnitRegisterInterfaces_address = memory::from_pattern( utils::system_module( _( L"storport.sys" ) ), _( "\xe8\x00\x00\x00\x00\x48\x8b\xcb\xe8\x00\x00\x00\x00\x85\xc0\x74\x0a" ), _( "x????xxxx????xxxx" ) );

									if ( RaidUnitRegisterInterfaces_address == 0 )
										break;

									const auto RaidUnitRegisterInterfaces = reinterpret_cast< NTSTATUS( __fastcall* )( RAID_UNIT_EXTENSION* ) >( RaidUnitRegisterInterfaces_address + 5 + *reinterpret_cast< std::int32_t* >( RaidUnitRegisterInterfaces_address + 1 ) );

									if ( !RaidUnitRegisterInterfaces )
										break;

									const auto disk_object = utils::reference_driver_by_name( _( L"\\Driver\\Disk" ) );

									if ( disk_object == nullptr )
										break;

									/* you can also use __rdtsc */
									LARGE_INTEGER seed_large{};
									KeQuerySystemTimePrecise( &seed_large );

									const auto seed = seed_large.LowPart ^ seed_large.HighPart;

									const auto first_object = disk_object.get( )->DeviceObject;

									if ( !first_object )
										break;

									for ( auto current_object = first_object; current_object != nullptr; current_object = current_object->NextDevice )
									{
										if ( !current_object )
											continue;

										const auto fd_extension = reinterpret_cast< PFUNCTIONAL_DEVICE_EXTENSION >( current_object->DeviceExtension );

										if ( !fd_extension )
											continue;

										const auto fs_device = IoGetDeviceAttachmentBaseRef( current_object );

										if ( !fs_device || !fs_device->DeviceExtension || fs_device->DeviceType != FILE_DEVICE_DISK )
											continue;

										const auto raid_extension = reinterpret_cast< PRAID_UNIT_EXTENSION >( fs_device->DeviceExtension );

										PSTOR_SCSI_IDENTITY identity = nullptr;

										switch ( windows_version )
										{
											case 1803:
												identity = reinterpret_cast< PSTOR_SCSI_IDENTITY >( std::uintptr_t( raid_extension ) + 0x60 );
												break;
											case 1809:
											case 1903:
												identity = reinterpret_cast< PSTOR_SCSI_IDENTITY >( std::uintptr_t( raid_extension ) + 0x68 );
												break;
											default:;
										}

										if ( !identity )
										{
											ObfDereferenceObject( fs_device );
											continue;
										}

										const auto fdo_descriptor = fd_extension->DeviceDescriptor;

										if ( !fdo_descriptor )
											continue;

										const auto fdo_serial = reinterpret_cast< char* >( fdo_descriptor ) + fdo_descriptor->SerialNumberOffset;

										serializer::randomize( seed, fdo_serial );

										identity->SerialNumber.Length = static_cast<std::uint16_t>( std::strlen( fdo_serial ) );
										memset( identity->SerialNumber.Buffer, 0, identity->SerialNumber.Length );
										memcpy( identity->SerialNumber.Buffer, fdo_serial, identity->SerialNumber.Length );

										/* this will only spoof the main serial, and not the smart serials. */
										DiskEnableDisableFailurePrediction( fd_extension, FALSE );
										RaidUnitRegisterInterfaces( raid_extension );

										ObfDereferenceObject( fs_device );
									}

									break;
								}
							}
						default:;
					}
				}
			}
		}
	}

	return return_value;
}

NTSTATUS driver_start( )
{
	//utils::clean_piddb_table( );
	
	LARGE_INTEGER cookie{ };

	const auto ntoskrnl_base = *reinterpret_cast< void** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );
	
	if ( !ntoskrnl_base )
		return STATUS_UNSUCCESSFUL;

	const auto trampoline = utils::trampoline_at( ntoskrnl_base );

	if ( !trampoline )
		return STATUS_UNSUCCESSFUL;

	return CmRegisterCallback( static_cast< PEX_CALLBACK_FUNCTION >( trampoline ), reinterpret_cast< void* >( &callback ), &cookie );
}