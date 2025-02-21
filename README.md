# Registry Security Descriptor Utility

This utility allows you to print and copy security descriptors of Windows registry keys. It provides detailed error handling and displays security descriptor components in a human-readable format.

## Features

- Print the security descriptor of a specified registry key, including:
  - Owner SID
  - Primary Group SID
  - Discretionary Access Control List (DACL)
  - System Access Control List (SACL)
  - Security Descriptor Control Bits
- Copy the security descriptor from one registry key to another
- Detailed error handling with human-readable error messages

## Requirements

- Windows operating system
- Visual Studio 2022 or later
- C++14 compiler

## Usage

### Print Security Descriptor

To print the security descriptor of a registry key, run the utility with the registry key path as the argument:

regaccess.exe <source_registry_key_path>

Example:

regaccess.exe HKEY_LOCAL_MACHINE\SOFTWARE\MyKey

### Copy Security Descriptor

To copy the security descriptor from one registry key to another, run the utility with the source and destination registry key paths as arguments:

regaccess.exe <source_registry_key_path> <dest_registry_key_path>

Example:

regaccess.exe HKEY_LOCAL_MACHINE\SOFTWARE\SourceKey HKEY_LOCAL_MACHINE\SOFTWARE\DestKey

## Building the Project

1. Open the solution in Visual Studio 2022.
2. Build the solution using the `Release` configuration.
