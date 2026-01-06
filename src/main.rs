//! Adreno GPU Info - Universal Version
//! Erkennt automatisch Strukturgröße (16, 20, 32, 40 Bytes)

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::mem::size_of;

// ============================================================================
// IOCTL Definitionen
// ============================================================================

#[repr(C)]
struct KgslDeviceGetProperty {
    type_: u32,
    value: *mut std::ffi::c_void,
    sizebytes: u32,
    _pad: [u32; 2],
}

const KGSL_PROP_DEVICE_INFO: u32 = 0x00000001;
const KGSL_PROP_VERSION: u32 = 0x00000008;

// ============================================================================
// Verschiedene mögliche Strukturen
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KgslDeviceInfo16 {
    pub device_id: u32,
    pub chip_id: u32,
    pub mmu_enabled: u32,
    pub gmem_gpubaseaddr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KgslDeviceInfo20 {
    pub device_id: u32,
    pub chip_id: u32,
    pub mmu_enabled: u32,
    pub gmem_gpubaseaddr: u32,
    pub gmem_sizebytes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KgslDeviceInfo32 {
    pub device_id: u32,
    pub chip_id: u32,
    pub mmu_enabled: u32,
    pub gmem_gpubaseaddr: u64,
    pub gmem_sizebytes: u32,
    pub bus_width: u32,
    pub gpu_model: u32,
    pub gpu_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KgslDeviceInfo40 {
    pub device_id: u32,
    pub chip_id: u32,
    pub mmu_enabled: u32,
    pub gmem_gpubaseaddr: u64,
    pub gmem_sizebytes: u32,
    pub bus_width: u32,
    pub gpu_model: u32,
    pub gpu_id: u64,
    pub unknown1: u32,
    pub unknown2: u32,
}

// ============================================================================
// Universelle Erkennung
// ============================================================================

fn try_read_gpu_info(fd: i32) -> Result<(Vec<u8>, usize), String> {
    // Teste verschiedene Strukturgrößen
    let sizes_to_try = [16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64];

    for &size in &sizes_to_try {
        let mut buffer = vec![0u8; size];

        let mut prop = KgslDeviceGetProperty {
            type_: KGSL_PROP_DEVICE_INFO,
            value: buffer.as_mut_ptr() as *mut std::ffi::c_void,
            sizebytes: size as u32,
            _pad: [0; 2],
        };

        // IOCTL-Nummer berechnen: IOWR(3, 0x09, 0x02, size)
        let ioctl_num: u32 = 0xc0000000 | ((size as u32) << 16) | (0x09 << 8) | 0x02;

        unsafe {
            let result = libc::ioctl(fd, ioctl_num as i32, &mut prop);
            if result == 0 {
                // Prüfe ob gültige Daten enthalten sind (nicht alles 0)
                if buffer.iter().any(|&x| x != 0) {
                    return Ok((buffer, size));
                }
            }
        }
    }

    Err("Keine passende Strukturgröße gefunden".to_string())
}

// ============================================================================
// Chip ID Decoding
// ============================================================================

#[derive(Debug, Clone)]
struct ChipInfo {
    pub raw_id: u32,
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub revision: u8,
    pub model_name: String,
    pub adreno_generation: String,
    pub snapdragon_model: Option<String>,
}

fn decode_chip_id(chip_id: u32) -> ChipInfo {
    let major = ((chip_id >> 24) & 0xFF) as u8;
    let minor = ((chip_id >> 16) & 0xFF) as u8;
    let patch = ((chip_id >> 8) & 0xFF) as u8;
    let revision = (chip_id & 0xFF) as u8;

    let adreno_gen = match major {
        1 => "100",
        2 => "200",
        3 => "300",
        4 => "400",
        5 => "500",
        6 => "600",
        7 => "700",
        8 => "800",
        9 => "900",
        _ => "Unknown",
    };

    let model_name = match (major, minor) {
        (6, 0) => "Adreno 600",
        (6, 1) => "Adreno 610",
        (6, 2) => "Adreno 620",
        (6, 3) => "Adreno 630",
        (6, 4) => "Adreno 640",
        (6, 5) => "Adreno 650",
        (6, 6) => "Adreno 660",
        (6, 8) => "Adreno 680",
        (6, 9) => "Adreno 690",
        (7, 0) => "Adreno 700",
        (7, 1) => "Adreno 710",
        (7, 2) => "Adreno 720",
        (7, 3) => "Adreno 730",
        (7, 4) => "Adreno 740",
        (7, 5) => "Adreno 750",
        _ => "Adreno GPU",
    };

    let snapdragon_model = match (major, minor) {
        (6, 1) => Some("Snapdragon 665/680/685/690/6 Gen 1"),
        (6, 0) => Some("Snapdragon 600 series"),
        _ => None,
    };

    ChipInfo {
        raw_id: chip_id,
        major,
        minor,
        patch,
        revision,
        model_name: model_name.to_string(),
        adreno_generation: adreno_gen.to_string(),
        snapdragon_model: snapdragon_model.map(|s| s.to_string()),
    }
}

// ============================================================================
// Daten-Parsing
// ============================================================================

fn parse_gpu_data(data: &[u8]) -> Result<ChipInfo, String> {
    if data.len() < 8 {
        return Err("Daten zu kurz".to_string());
    }

    // Chip ID ist immer an Offset 4 (Bytes 4-7)
    let chip_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    if chip_id == 0 {
        return Err("Ungültige Chip ID".to_string());
    }

    Ok(decode_chip_id(chip_id))
}

fn get_device_id(data: &[u8]) -> u32 {
    if data.len() >= 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        0
    }
}

fn get_mmu_enabled(data: &[u8]) -> bool {
    if data.len() >= 12 {
        let mmu = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        mmu != 0
    } else {
        false
    }
}

// ============================================================================
// Hauptprogramm
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Adreno GPU Info - Universal Version");
    println!("   Automatische Strukturerkennung\n");

    // Gerät finden
    let device_path = "/dev/kgsl-3d0";
    let file = match File::open(device_path) {
        Ok(f) => {
            println!("✅ Device {} geöffnet", device_path);
            f
        },
        Err(e) => {
            eprintln!("❌ Kann {} nicht öffnen: {}", device_path, e);
            eprintln!("   Versuche mit Root: sudo ./programm");
            return Ok(());
        }
    };

    let fd = file.as_raw_fd();

    // GPU Info lesen mit automatischer Größenerkennung
    match try_read_gpu_info(fd) {
        Ok((data, size)) => {
            println!("\n🎯 Erfolgreich gelesen!");
            println!("   Strukturgröße: {} Bytes", size);
            println!("   Erste 16 Bytes: {:02x?}", &data[..16.min(data.len())]);

            // Daten parsen
            match parse_gpu_data(&data) {
                Ok(chip_info) => {
                    println!("\n╔══════════════════════════════════════════╗");
                    println!("║           GPU INFORMATION                ║");
                    println!("╠══════════════════════════════════════════╣");
                    println!("║  📱 Device:  {}", chip_info.model_name);

                    if let Some(snapdragon) = &chip_info.snapdragon_model {
                        println!("║  📱 Chipset: {}", snapdragon);
                    }

                    println!("║  🏷️  Chip ID:  0x{:08x}", chip_info.raw_id);
                    println!("║  🏷️  Version:  v{}.{}.{}.{}",
                        chip_info.major, chip_info.minor,
                        chip_info.patch, chip_info.revision);
                    println!("║  🔢 Device ID: 0x{:08x}", get_device_id(&data));
                    println!("║  🛡️  MMU:       {}",
                        if get_mmu_enabled(&data) { "✅ Enabled" } else { "❌ Disabled" });
                    println!("║  🎯 Generation: Adreno {}", chip_info.adreno_generation);

                    // Weitere Felder basierend auf Größe
                    if size >= 20 && data.len() >= 20 {
                        let gmem_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                        if gmem_size > 0 {
                            println!("║  💾 GMEM Size: {} MB", gmem_size / (1024 * 1024));
                        }
                    }

                    if size >= 24 && data.len() >= 24 {
                        let bus_width = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                        if bus_width > 0 {
                            println!("║  🔌 Bus Width: {} bit", bus_width);
                        }
                    }

                    println!("╚══════════════════════════════════════════╝");

                    // Gerätespezifische Info
                    println!("\n📱 Device Detection:");
                    match (chip_info.major, chip_info.minor, chip_info.patch, chip_info.revision) {
                        (6, 1, 0, 1) => println!("   • Xiaomi Topaz (Rodin?) - Adreno 610 v6.1.0.1"),
                        (6, 1, 0, 0) => println!("   • Xiaomi Laurel Sprout - Adreno 610 v6.1.0.0"),
                        _ => println!("   • Unbekanntes Xiaomi Gerät mit Adreno 610"),
                    }
                }
                Err(e) => {
                    eprintln!("❌ Fehler beim Parsen: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Fehler: {}", e);
            eprintln!("\n🔧 Fehlerbehebung:");
            eprintln!("   1. Mit Root ausführen: sudo ./adreno_ioctl");
            eprintln!("   2. Gerätedatei prüfen: ls -la /dev/kgsl*");
            eprintln!("   3. Kernel-Treiber: dmesg | grep kgsl");
        }
    }

    Ok(())
}
