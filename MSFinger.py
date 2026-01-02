#!/usr/bin/env python3
# This file was created and is currently maintained by Laurent Gaffie.
# email: lgaffie@secorizon.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sys
import struct
import socket
import argparse
import datetime
import ipaddress
import warnings
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL deprecation warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

__version__ = "1.0"

# Default timeout for connections (optimized for internal networks)
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 100
DEFAULT_DB = "MSFinger.db"

class Colors:
    """ANSI color codes"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def color_text(text, color):
    """Colorize text output"""
    return f"{color}{text}{Colors.END}"

# ============================================================================
# Database Functions
# ============================================================================

def init_database(db_path):
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create hosts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            hostname TEXT,
            os_version TEXT,
            os_build INTEGER,
            domain TEXT,
            boot_time TEXT,
            smb_dialect TEXT,
            smb_signing TEXT,
            smb1_supported INTEGER DEFAULT 0,
            smb1_signing TEXT,
            rdp_open INTEGER DEFAULT 0,
            mssql_open INTEGER DEFAULT 0,
            ldap_signing TEXT,
            ldaps_signing TEXT,
            ldaps_channel_binding TEXT,
            ldaps_error TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def save_to_database(db_path, result):
    """Save scan result to database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    ip = result["host"]
    smb2 = result.get("smb2")
    smb1 = result.get("smb1")
    ldap = result.get("ldap")
    ldaps = result.get("ldaps")
    
    # Extract values
    os_version = smb2.get("os_version") if smb2 else None
    os_build = smb2.get("build") if smb2 else None
    domain = smb2.get("domain") if smb2 else None
    boot_time = smb2.get("boot_time") if smb2 else None
    smb_dialect = smb2.get("dialect") if smb2 else None
    smb_signing = smb2.get("signing") if smb2 else None
    
    smb1_supported = 1 if smb1 else 0
    smb1_signing = smb1.get("signing") if smb1 else None
    
    rdp_open = 1 if result.get("rdp") else 0
    mssql_open = 1 if result.get("mssql") else 0
    
    ldap_signing = ldap.get("signing") if ldap else None
    
    ldaps_signing = None
    ldaps_channel_binding = None
    ldaps_error = None
    if ldaps:
        if ldaps.get("supported"):
            ldaps_signing = ldaps.get("signing")
            ldaps_channel_binding = ldaps.get("channel_binding")
        else:
            ldaps_error = ldaps.get("error")
    
    # Insert or update record
    cursor.execute('''
        INSERT INTO hosts (
            ip, os_version, os_build, domain, boot_time,
            smb_dialect, smb_signing, smb1_supported, smb1_signing,
            rdp_open, mssql_open, ldap_signing, ldaps_signing,
            ldaps_channel_binding, ldaps_error, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(ip) DO UPDATE SET
            os_version=excluded.os_version,
            os_build=excluded.os_build,
            domain=excluded.domain,
            boot_time=excluded.boot_time,
            smb_dialect=excluded.smb_dialect,
            smb_signing=excluded.smb_signing,
            smb1_supported=excluded.smb1_supported,
            smb1_signing=excluded.smb1_signing,
            rdp_open=excluded.rdp_open,
            mssql_open=excluded.mssql_open,
            ldap_signing=excluded.ldap_signing,
            ldaps_signing=excluded.ldaps_signing,
            ldaps_channel_binding=excluded.ldaps_channel_binding,
            ldaps_error=excluded.ldaps_error,
            last_seen=CURRENT_TIMESTAMP
    ''', (ip, os_version, os_build, domain, boot_time,
          smb_dialect, smb_signing, smb1_supported, smb1_signing,
          rdp_open, mssql_open, ldap_signing, ldaps_signing,
          ldaps_channel_binding, ldaps_error))
    
    conn.commit()
    conn.close()

# ============================================================================
# OS Version Detection
# ============================================================================

OS_VERSION_MAP = {
    b"\x04\x00": "Windows 95",
    b"\x04\x0A": "Windows 98",
    b"\x04\x5A": "Windows ME",
    b"\x05\x00": "Windows 2000",
    b"\x05\x01": "Windows XP",
    b"\x05\x02": "Windows XP (64-bit)/2003",
    b"\x06\x00": "Windows Vista/2008",
    b"\x06\x01": "Windows 7/2008 R2",
    b"\x06\x02": "Windows 8/2012",
    b"\x06\x03": "Windows 8.1/2012 R2",
    b"\x0A\x00": "Windows 10/11/2016+",
}

# Build number to OS mapping for Windows 10/11 and Server 2016+
BUILD_VERSION_MAP = {
    # Windows 10
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    14393: "Windows 10 1607 / Server 2016",
    15063: "Windows 10 1703",
    16299: "Windows 10 1709",
    17134: "Windows 10 1803",
    17763: "Windows 10 1809 / Server 2019",
    18362: "Windows 10 1903",
    18363: "Windows 10 1909",
    19041: "Windows 10 2004",
    19042: "Windows 10 20H2",
    19043: "Windows 10 21H1",
    19044: "Windows 10 21H2",
    19045: "Windows 10 22H2",
    # Windows 11
    22000: "Windows 11 21H2",
    22621: "Windows 11 22H2",
    22631: "Windows 11 23H2",
    # Windows Server
    20348: "Windows Server 2022 21H2",
    25398: "Windows Server 2025",
}

def get_os_version(version_bytes, build=None):
    """Map version bytes to OS name with build-specific details"""
    base_os = OS_VERSION_MAP.get(version_bytes, "Unknown OS")
    
    # For Windows 10/11/2016+, use build number for more specific detection
    if base_os == "Windows 10/11/2016+" and build:
        specific_os = BUILD_VERSION_MAP.get(build)
        if specific_os:
            return specific_os
        # If build not in map, check ranges
        elif build >= 22000:
            return f"Windows 11 (Build {build})"
        elif build >= 10240:
            return f"Windows 10/Server (Build {build})"
    
    return base_os

def get_build_number(data):
    """Extract Windows build number"""
    try:
        return struct.unpack("<H", data)[0]
    except:
        return 0

# ============================================================================
# Time/Date Functions
# ============================================================================

def parse_filetime(filetime_bytes):
    """Convert Windows FILETIME to datetime"""
    try:
        if len(filetime_bytes) != 8:
            return None, "Unknown"
        
        filetime = struct.unpack('<Q', filetime_bytes)[0]
        
        # Check for zero or invalid values
        if filetime == 0 or filetime == 0xFFFFFFFFFFFFFFFF:
            return None, "Disabled"
        
        # Convert FILETIME to Unix timestamp
        # FILETIME epoch is January 1, 1601
        unix_time = (filetime - 116444736000000000) // 10000000
        
        # Sanity check - make sure it's a reasonable date
        # (after year 1900 and before year 2100)
        if unix_time < -2208988800 or unix_time > 4102444800:
            return None, "Unknown"
        
        dt = datetime.datetime.fromtimestamp(unix_time)
        return dt, dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return None, "Unknown"

# ============================================================================
# Network Helper Functions
# ============================================================================

def pack_smb_length(data):
    """Pack SMB message with NetBIOS session length"""
    if isinstance(data, str):
        data = data.encode('latin-1')
    length = struct.pack(">I", len(data))
    return length + data

def create_socket(host, port, timeout):
    """Create and connect a socket"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return s
    except:
        s.close()
        return None

# ============================================================================
# SMB1 Detection
# ============================================================================

def build_smb1_negotiate():
    """Build SMB1 negotiate packet"""
    # SMB Header
    header = (
        b"\xff\x53\x4d\x42"  # Protocol
        b"\x72"              # Negotiate
        b"\x00\x00\x00\x00"  # Status
        b"\x18"              # Flags
        b"\x53\xc8"          # Flags2
        b"\x00\x00"          # PID High
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        b"\x00\x00"          # Reserved
        b"\x00\x00"          # TID
        b"\xff\xfe"          # PID
        b"\x00\x00"          # UID
        b"\x00\x00"          # MID
    )
    
    # Negotiate data
    dialects = b"\x02NT LM 0.12\x00"
    
    # Word count + byte count
    negotiate = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    
    packet = header + negotiate
    return pack_smb_length(packet)

def build_smb1_session_setup():
    """Build SMB1 session setup with NTLMSSP"""
    header = (
        b"\xff\x53\x4d\x42"
        b"\x73"              # Session Setup
        b"\x00\x00\x00\x00"
        b"\x18"
        b"\x07\xc8"
        b"\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\xff\xfe"
        b"\x00\x00"
        b"\x00\x00"
    )
    
    # NTLMSSP Negotiate
    ntlmssp = (
        b"NTLMSSP\x00"
        b"\x01\x00\x00\x00"  # Type 1
        b"\x07\x82\x08\xa2"  # Flags
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Domain
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Workstation
        b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"  # Version
    )
    
    # SPNEGO wrapper
    spnego = (
        b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02"
        b"\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a"
        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
        b"\xa2\x2a\x04\x28" + ntlmssp
    )
    
    # Session setup parameters
    params = (
        b"\x0c"              # Word count
        b"\xff\x00"          # AndX
        b"\x00\x00"          # Reserved
        b"\xec\x00"          # AndX offset
        b"\x04\x11"          # Max buffer
        b"\x32\x00"          # Max mpx
        b"\x00\x00"          # VC number
        b"\x00\x00\x00\x00"  # Session key
        + struct.pack("<H", len(spnego))  # Security blob length
        + b"\x00\x00\x00\x00"  # Reserved
        + b"\xd4\x00\x00\xa0"  # Capabilities
    )
    
    # Native OS/LAN Manager
    native = b"Windows 2000 2195\x00Windows 2000 5.0\x00\x00"
    
    bcc = struct.pack("<H", len(spnego) + len(native))
    
    packet = header + params + bcc + spnego + native
    return pack_smb_length(packet)

def detect_smb1(host, timeout):
    """Detect SMB1 support and signing"""
    s = create_socket(host, 445, timeout)
    if not s:
        return None
    
    try:
        # Send negotiate
        s.send(build_smb1_negotiate())
        data = s.recv(4096)
        
        if len(data) < 40:
            return None
        
        # Check if SMB1 response
        if data[4:8] != b"\xff\x53\x4d\x42":
            return None
        
        # Check signing (byte 39 in SMB header)
        signing_required = (data[39] & 0x0f) == 0x0f
        signing_enabled = (data[39] & 0x08) == 0x08
        
        if signing_required:
            signing = "required"
        elif signing_enabled:
            signing = "enabled"
        else:
            signing = "disabled"
        
        s.close()
        return {"supported": True, "signing": signing}
    except:
        s.close()
        return None

# ============================================================================
# SMB2/SMB3 Detection
# ============================================================================

def build_smb2_negotiate():
    """Build SMB2 negotiate packet"""
    # SMB2 Header
    header = (
        b"\xfe\x53\x4d\x42"  # Protocol
        b"\x40\x00"          # Header length
        b"\x00\x00"          # Credit charge
        b"\x00\x00\x00\x00"  # Status
        b"\x00\x00"          # Command (Negotiate)
        b"\x00\x00"          # Credits
        b"\x00\x00\x00\x00"  # Flags
        b"\x00\x00\x00\x00"  # Chain offset
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Message ID
        b"\xff\xfe\x00\x00"  # Process ID
        b"\x00\x00\x00\x00"  # Tree ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    )
    
    # Negotiate request
    negotiate = (
        b"\x24\x00"          # Structure size
        b"\x02\x00"          # Dialect count (2)
        b"\x01\x00"          # Security mode
        b"\x00\x00"          # Reserved
        b"\x00\x00\x00\x00"  # Capabilities
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Client GUID (random)
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Client start time
        b"\x02\x02"          # Dialect 2.0.2
        b"\x10\x02"          # Dialect 2.1
    )
    
    packet = header + negotiate
    return pack_smb_length(packet)

def build_smb2_session_setup():
    """Build SMB2 session setup with NTLMSSP"""
    # SMB2 Header
    header = (
        b"\xfe\x53\x4d\x42"  # Protocol
        b"\x40\x00"          # Header length
        b"\x01\x00"          # Credit charge (1, not 0)
        b"\x00\x00\x00\x00"  # Status
        b"\x01\x00"          # Command (Session Setup)
        b"\x1f\x00"          # Credits requested (31, not 1)
        b"\x00\x00\x00\x00"  # Flags
        b"\x00\x00\x00\x00"  # Chain offset
        b"\x01\x00\x00\x00\x00\x00\x00\x00"  # Message ID
        b"\xff\xfe\x00\x00"  # Process ID
        b"\x00\x00\x00\x00"  # Tree ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    )
    
    # NTLMSSP Negotiate (Type 1)
    ntlmssp = (
        b"NTLMSSP\x00"       # Signature
        b"\x01\x00\x00\x00"  # Message Type (1 = Negotiate)
        b"\x97\x82\x08\xe2"  # Flags
        b"\x00\x00"          # Domain name length (0)
        b"\x00\x00"          # Domain name max length (0)
        b"\x00\x00\x00\x00"  # Domain name offset (0)
        b"\x00\x00"          # Workstation length (0)
        b"\x00\x00"          # Workstation max length (0)
        b"\x00\x00\x00\x00"  # Workstation offset (0)
        b"\x06\x01\xb0\x1d"  # Version: Major 6, Minor 1, Build 7600
        b"\x00\x00\x00\x0f"  # Reserved (3 bytes) + NTLM revision 15
    )
    # Total: 40 bytes (0x28)
    
    # SPNEGO negTokenInit wrapper
    spnego_inner = (
        b"\xa0\x0e"          # [0] MechTypes
        b"\x30\x0c"          # SEQUENCE
        b"\x06\x0a"          # OID length
        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"  # NTLMSSP OID
        b"\xa2\x2a"          # [2] MechToken
        b"\x04\x28"          # OCTET STRING (40 bytes = 0x28)
        + ntlmssp
    )
    
    spnego_outer = (
        b"\x60\x48"          # APPLICATION 0 (length 0x48 = 72)
        b"\x06\x06"          # OID length
        b"\x2b\x06\x01\x05\x05\x02"  # SPNEGO OID
        b"\xa0\x3e"          # [0] negTokenInit (length 0x3e = 62)
        b"\x30\x3c"          # SEQUENCE (length 0x3c = 60)
        + spnego_inner
    )
    
    # Session setup structure
    session_setup = (
        b"\x19\x00"          # Structure size
        b"\x00"              # Flags
        b"\x01"              # Security mode (signing enabled)
        b"\x01\x00\x00\x00"  # Capabilities (DFS = 0x00000001)
        b"\x00\x00\x00\x00"  # Channel
        b"\x58\x00"          # Security buffer offset
        + struct.pack("<H", len(spnego_outer))  # Security buffer length
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Previous session ID
    )
    
    packet = header + session_setup + spnego_outer
    return pack_smb_length(packet)

def detect_smb2(host, timeout):
    """Detect SMB2/3 support, version, signing, and OS info"""
    s = create_socket(host, 445, timeout)
    if not s:
        return None
    
    try:
        # Send negotiate
        s.send(build_smb2_negotiate())
        data = s.recv(4096)
        
        if len(data) < 68:
            s.close()
            return None
        
        # Check if SMB2 response
        if data[4:8] != b"\xfe\x53\x4d\x42":
            s.close()
            return None
        
        result = {"supported": True}
        
        # Get dialect (offset 72-74 in the response, after the 4-byte NetBIOS header)
        if len(data) >= 74:
            dialect = struct.unpack("<H", data[72:74])[0]
            dialect_map = {
                0x0202: "2.0.2",
                0x0210: "2.1",
                0x0300: "3.0",
                0x0302: "3.0.2",
                0x0311: "3.1.1"
            }
            result["dialect"] = dialect_map.get(dialect, f"Unknown")
        
        # Get signing (offset 70-72) - this is Security Mode field
        # Structure: [0-1] Structure Size, [2-3] Security Mode
        if len(data) >= 72:
            security_mode = struct.unpack("<H", data[70:72])[0]
            # Security mode bits:
            # 0x01 = Signing enabled
            # 0x02 = Signing required
            # 0x03 = Both (signing required takes precedence)
            if security_mode & 0x02:  # Bit 1 set = required (even if bit 0 also set)
                result["signing"] = "required"
            elif security_mode & 0x01:  # Only bit 0 set = enabled but not required
                result["signing"] = "enabled"
            else:  # Neither bit set
                result["signing"] = "disabled"
        
        # Get boot time (offset 112-120, after NetBIOS header + SMB2 header)
        if len(data) >= 120:
            boot_dt, boot_str = parse_filetime(data[112:120])
            result["boot_time"] = boot_str
        
        # Now send session setup to get NTLMSSP challenge with OS info
        s.send(build_smb2_session_setup())
        data = s.recv(4096)
        
        if len(data) > 100:
            # Look for NTLMSSP challenge
            ntlmssp_offset = data.find(b'NTLMSSP\x00\x02\x00\x00\x00')
            if ntlmssp_offset > 0 and ntlmssp_offset + 60 < len(data):
                # Version info at offset +48 from NTLMSSP signature
                os_major = data[ntlmssp_offset+48]
                os_minor = data[ntlmssp_offset+49]
                build_bytes = data[ntlmssp_offset+50:ntlmssp_offset+52]
                
                os_version_bytes = bytes([os_major, os_minor])
                build_num = get_build_number(build_bytes)
                result["os_version"] = get_os_version(os_version_bytes, build_num)
                result["build"] = build_num
                
                # Domain/hostname extraction from TargetName
                try:
                    target_name_len = struct.unpack('<H', data[ntlmssp_offset+12:ntlmssp_offset+14])[0]
                    target_name_offset = struct.unpack('<I', data[ntlmssp_offset+16:ntlmssp_offset+20])[0]
                    
                    target_start = ntlmssp_offset + target_name_offset
                    target_end = target_start + target_name_len
                    
                    if target_end < len(data):
                        domain = data[target_start:target_end].decode('utf-16le', errors='ignore')
                        result["domain"] = domain
                except:
                    pass
        
        s.close()
        return result
    except Exception as e:
        s.close()
        return None

# ============================================================================
# LDAP/LDAPS Detection
# ============================================================================

def build_ldap_bind_request():
    """Build LDAP bind request to test for signing"""
    # Simple LDAP Bind Request (anonymous)
    # BER encoding of LDAP BindRequest
    bind_request = (
        b"\x30"  # SEQUENCE
        b"\x0c"  # Length
        b"\x02\x01\x01"  # messageID: 1
        b"\x60"  # BindRequest
        b"\x07"  # Length
        b"\x02\x01\x03"  # version: 3
        b"\x04\x00"      # name: empty (anonymous)
        b"\x80\x00"      # authentication: simple, empty
    )
    return bind_request

def detect_ldap_signing(host, port, timeout, use_ssl=False):
    """Detect if LDAP/LDAPS signing is required and channel binding status"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        
        # For LDAPS, wrap in SSL
        if use_ssl:
            import ssl
            
            # Create SSL context - use PROTOCOL_TLS for maximum compatibility
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            except AttributeError:
                # Fallback for very old Python versions
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Disable SSLv2 and SSLv3 but allow TLS 1.0+
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            
            # Set permissive cipher list
            try:
                context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except:
                context.set_ciphers('DEFAULT')
            
            # Wrap the socket - this will send Client Hello
            try:
                s = context.wrap_socket(s, do_handshake_on_connect=True)
            except ssl.SSLError as e:
                # SSL handshake failed - server closed connection or doesn't support SSL
                if s:
                    try:
                        s.close()
                    except:
                        pass
                return {"supported": False, "ssl": True, "error": "SSL handshake failed"}
            except OSError as e:
                # Connection reset or other network error
                if s:
                    try:
                        s.close()
                    except:
                        pass
                return {"supported": False, "ssl": True, "error": f"Connection error: {e.errno}"}
            except Exception as e:
                if s:
                    try:
                        s.close()
                    except:
                        pass
                return {"supported": False, "ssl": True, "error": str(e)}
        
        # Send LDAP bind without signing
        s.send(build_ldap_bind_request())
        data = s.recv(4096)
        
        if len(data) < 10:
            if s:
                s.close()
            return None
        
        # Parse LDAP response
        result_code_offset = data.find(b'\x0a\x01')
        
        result_info = {"supported": True, "ssl": use_ssl}
        
        if result_code_offset > 0 and result_code_offset + 2 < len(data):
            result_code = data[result_code_offset + 2]
            
            if result_code == 0:
                result_info["signing"] = "not_required"
                if use_ssl:
                    result_info["channel_binding"] = "not_required"
            elif result_code == 8:
                result_info["signing"] = "required"
                if use_ssl:
                    result_info["channel_binding"] = "unknown"
            elif result_code == 13:
                result_info["signing"] = "unknown"
                if use_ssl:
                    result_info["channel_binding"] = "required"
            else:
                result_info["signing"] = "unknown"
                if use_ssl:
                    result_info["channel_binding"] = "unknown"
        else:
            result_info["signing"] = "unknown"
            if use_ssl:
                result_info["channel_binding"] = "unknown"
        
        if s:
            s.close()
        return result_info
    except Exception as e:
        if s:
            try:
                s.close()
            except:
                pass
        return None

# ============================================================================
# Service Detection
# ============================================================================

def check_port_open(host, port, timeout):
    """Check if a TCP port is open"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except:
        return False

# ============================================================================
# Main Fingerprinting Function
# ============================================================================

def fingerprint_host(host, timeout=DEFAULT_TIMEOUT):
    """Perform comprehensive host fingerprinting"""
    result = {
        "host": host,
        "smb1": None,
        "smb2": None,
        "rdp": False,
        "mssql": False,
        "ldap": None,
        "ldaps": None,
    }
    
    # SMB2/3 Detection (try first as it's more common)
    smb2_info = detect_smb2(host, timeout)
    if smb2_info:
        result["smb2"] = smb2_info
    
    # SMB1 Detection
    smb1_info = detect_smb1(host, timeout)
    if smb1_info:
        result["smb1"] = smb1_info
    
    # RDP Detection (port 3389)
    result["rdp"] = check_port_open(host, 3389, timeout)
    
    # MSSQL Detection (port 1433)
    result["mssql"] = check_port_open(host, 1433, timeout)
    
    # LDAP Detection (port 389)
    ldap_info = detect_ldap_signing(host, 389, timeout, use_ssl=False)
    if ldap_info:
        result["ldap"] = ldap_info
    
    # LDAPS Detection (port 636) - use much longer timeout for SSL
    # Only try if port is open
    if check_port_open(host, 636, timeout):
        ldaps_timeout = max(timeout * 3, 2.0)  # At least 2 seconds for SSL
        ldaps_info = detect_ldap_signing(host, 636, ldaps_timeout, use_ssl=True)
        if ldaps_info:
            result["ldaps"] = ldaps_info
    
    return result

# ============================================================================
# Output Formatting
# ============================================================================

def format_result(result):
    """Format fingerprint result for display"""
    host = result["host"]
    parts = []
    
    # SMB2/3 info
    if result["smb2"]:
        smb2 = result["smb2"]
        os_info = smb2.get("os_version", "Unknown")
        
        # Don't append build if it's already in the OS version string
        build = smb2.get("build", "")
        if build and str(build) not in os_info:
            os_info += f" (Build {build})"
        
        dialect = smb2.get("dialect", "Unknown")
        signing = smb2.get("signing", "unknown")
        boot_time = smb2.get("boot_time", "Unknown")
        domain = smb2.get("domain", "Unknown")
        
        # Color code signing status
        if signing == "required":
            signing_colored = color_text(f"Signing: {signing}", Colors.GREEN)
        elif signing == "enabled":
            signing_colored = color_text(f"Signing: {signing}", Colors.YELLOW)
        else:  # disabled
            signing_colored = color_text(f"Signing: {signing}", Colors.RED)
        
        smb_str = f"SMB: {dialect}, {signing_colored}, OS: {os_info}, Domain: {domain}, Boot: {boot_time}"
        parts.append(smb_str)
    
    # SMB1 info
    if result["smb1"]:
        smb1_signing = result["smb1"]["signing"]
        
        # Color code SMB1 signing
        if smb1_signing == "required":
            smb1_signing_colored = color_text(f"Signing: {smb1_signing}", Colors.GREEN)
        elif smb1_signing == "enabled":
            smb1_signing_colored = color_text(f"Signing: {smb1_signing}", Colors.YELLOW)
        else:
            smb1_signing_colored = color_text(f"Signing: {smb1_signing}", Colors.RED)
        
        parts.append(color_text(f"SMB1: supported, {smb1_signing_colored}", Colors.YELLOW))
    elif result["smb2"]:  # If SMB2 works but not SMB1
        parts.append(color_text("SMB1: disabled", Colors.BLUE))
    
    # Services
    services = []
    if result["rdp"]:
        services.append("RDP")
    if result["mssql"]:
        services.append("MSSQL")
    
    # LDAP with color-coded signing
    if result["ldap"]:
        ldap_signing = result["ldap"]["signing"]
        if ldap_signing == "required":
            ldap_str = color_text(f"LDAP (signing: {ldap_signing})", Colors.GREEN)
        elif ldap_signing == "not_required":
            ldap_str = color_text(f"LDAP (signing: {ldap_signing})", Colors.RED)
        else:
            ldap_str = f"LDAP (signing: {ldap_signing})"
        services.append(ldap_str)
    
    if result["ldaps"]:
        ldaps_info = result["ldaps"]
        
        # Check if LDAPS is supported or just port open
        if not ldaps_info.get("supported", False):
            # Port open but SSL handshake failed
            error = ldaps_info.get("error", "unknown error")
            ldaps_str = color_text(f"LDAPS (port open, {error})", Colors.YELLOW)
            services.append(ldaps_str)
        else:
            ldaps_signing = ldaps_info.get("signing", "unknown")
            ldaps_channel_binding = ldaps_info.get("channel_binding", "unknown")
            
            # Build LDAPS string with both signing and channel binding
            ldaps_parts = []
            
            # Signing status
            if ldaps_signing == "required":
                ldaps_parts.append(color_text(f"signing: {ldaps_signing}", Colors.GREEN))
            elif ldaps_signing == "not_required":
                ldaps_parts.append(color_text(f"signing: {ldaps_signing}", Colors.RED))
            else:
                ldaps_parts.append(f"signing: {ldaps_signing}")
            
            # Channel binding status
            if ldaps_channel_binding == "required":
                ldaps_parts.append(color_text(f"channel binding: {ldaps_channel_binding}", Colors.GREEN))
            elif ldaps_channel_binding == "not_required":
                ldaps_parts.append(color_text(f"channel binding: {ldaps_channel_binding}", Colors.RED))
            elif ldaps_channel_binding != "unknown":
                ldaps_parts.append(f"channel binding: {ldaps_channel_binding}")
            
            ldaps_str = f"LDAPS ({', '.join(ldaps_parts)})"
            services.append(ldaps_str)
    
    if services:
        parts.append(f"Services: {', '.join(services)}")
    
    # Only print if we have actual results
    if parts:
        print(f"[{host}] {' | '.join(parts)}")

# ============================================================================
# IP Range Processing
# ============================================================================

def parse_targets(target_input):
    """Parse target input (IP, CIDR, or file)"""
    targets = []
    
    # Check if it's a file
    try:
        with open(target_input, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.extend(parse_targets(line))
        return targets
    except (FileNotFoundError, IOError):
        pass
    
    # Check if it's a CIDR range
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass
    
    # Check if it's a single IP
    try:
        ipaddress.ip_address(target_input)
        return [target_input]
    except ValueError:
        pass
    
    # Check if it's a range like 192.168.1.1-10
    match = re.match(r'(\d+\.\d+\.\d+\.)(\d+)-(\d+)', target_input)
    if match:
        base = match.group(1)
        start = int(match.group(2))
        end = int(match.group(3))
        return [f"{base}{i}" for i in range(start, end + 1)]
    
    print(f"Error: Invalid target format: {target_input}")
    return []

# ============================================================================
# Main Function
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MSFinger - Microsoft Network Service Fingerprinting Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 %(prog)s -i 192.168.1.10
  python3 %(prog)s -i 192.168.1.0/24
  python3 %(prog)s -i 192.168.1.1-50
  python3 %(prog)s -f targets.txt
  python3 %(prog)s -i 192.168.1.0/24 -t 0.5 -w 200 -d scan_results.db
  
For detailed documentation, see the README or run with --help
        '''
    )
    
    parser.add_argument('-i', '--ip', dest='target', 
                        help='Target IP address, CIDR range, or IP range')
    parser.add_argument('-f', '--file', dest='filename',
                        help='File containing target IPs (one per line)')
    parser.add_argument('-t', '--timeout', dest='timeout', type=float, 
                        default=DEFAULT_TIMEOUT,
                        help=f'Connection timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('-w', '--workers', dest='workers', type=int,
                        default=MAX_WORKERS,
                        help=f'Number of concurrent workers (default: {MAX_WORKERS})')
    parser.add_argument('-d', '--database', dest='database',
                        default=DEFAULT_DB,
                        help=f'SQLite database file for results (default: {DEFAULT_DB})')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        Colors.BLUE = Colors.GREEN = Colors.YELLOW = Colors.RED = Colors.END = Colors.BOLD = ''
    
    # Get targets
    targets = []
    if args.target:
        targets = parse_targets(args.target)
    elif args.filename:
        targets = parse_targets(args.filename)
    else:
        parser.print_help()
        sys.exit(1)
    
    if not targets:
        print("Error: No valid targets found")
        sys.exit(1)
    
    # Initialize database
    init_database(args.database)
    
    print(f"{color_text('[*]', Colors.BOLD)} Starting MSFinger v{__version__}")
    print(f"{color_text('[*]', Colors.BOLD)} Targets: {len(targets)} | Timeout: {args.timeout}s | Workers: {args.workers}")
    print(f"{color_text('[*]', Colors.BOLD)} Database: {args.database}")
    print()
    
    # Process targets with thread pool
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(fingerprint_host, target, args.timeout): target 
                   for target in targets}
        
        for future in as_completed(futures):
            try:
                result = future.result()
                format_result(result)
                # Save to database
                save_to_database(args.database, result)
            except Exception as e:
                target = futures[future]
                print(f"[{target}] {color_text(f'Error: {str(e)}', Colors.RED)}")
    
    print()
    print(f"{color_text('[*]', Colors.BOLD)} Scan complete")
    print(f"{color_text('[*]', Colors.BOLD)} Results saved to: {args.database}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
